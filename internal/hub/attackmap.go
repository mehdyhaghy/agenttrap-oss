package hub

import (
	"context"
	"sort"
	"time"

	"agenttrap/internal/classify"
	"agenttrap/internal/geo"
)

// SetGeo attaches the IP-geolocation database used by the attack map. A nil db
// (no database mounted) leaves the map disabled but everything else running.
func (h *Hub) SetGeo(db *geo.DB) { h.geo = db }

// locate fills an actor's country from the geolocation database, if any.
func (h *Hub) locate(a *classify.Actor) {
	if loc, _ := h.geo.Lookup(a.Source); loc.CountryCode != "" {
		a.CountryCode, a.Country = loc.CountryCode, loc.Country
	}
}

// MapPoint is one location (a city, or a country in the rollup) with attacker
// activity.
type MapPoint struct {
	Lat         float64  `json:"lat"`
	Lon         float64  `json:"lon"`
	City        string   `json:"city,omitempty"`
	Country     string   `json:"country,omitempty"`
	CountryCode string   `json:"country_code,omitempty"`
	Count       int      `json:"count"`     // distinct actors here
	Score       int      `json:"score"`     // highest agent-likeness score here
	TopClass    string   `json:"top_class"` // class of that highest-scoring actor
	Sources     []string `json:"sources,omitempty"`
}

// AttackMap aggregates actors active in [since, until] into city points and a
// country rollup for the admin world map. classes, when non-empty, keeps only
// those actor classes. It returns disabled=true (no points) when no
// geolocation database is mounted.
func (h *Hub) AttackMap(ctx context.Context, since, until time.Time, classes map[string]bool) (map[string]any, error) {
	if h.geo == nil {
		return map[string]any{"enabled": false, "points": []MapPoint{}, "countries": []MapPoint{}, "attribution": geo.AttributionText}, nil
	}
	actors, _, err := h.Analyze(ctx, since)
	if err != nil {
		return nil, err
	}
	cities, countries, mapped := aggregatePoints(actors, until, classes, h.geo.Lookup)
	return map[string]any{
		"enabled":     true,
		"attribution": geo.AttributionText,
		"generated":   time.Now().UTC(),
		"since":       since.UTC(),
		"until":       until.UTC(),
		"actors":      len(actors),
		"mapped":      mapped,
		"points":      cities,
		"countries":   countries,
	}, nil
}

// aggregatePoints buckets actors into city and country points. It skips
// operators, actors that first appeared after until, classes not in the filter
// (when one is given), and addresses geolocation can't place. City points come
// back loudest-last (drawn on top); countries come back busiest-first (a list).
func aggregatePoints(actors []classify.Actor, until time.Time, classes map[string]bool,
	lookup func(string) (geo.Location, bool)) (cities, countries []MapPoint, mapped int) {
	byCity := map[string]*MapPoint{}
	byCountry := map[string]*MapPoint{}
	for _, a := range actors {
		if a.Class == classify.Operator {
			continue
		}
		if len(classes) > 0 && !classes[a.Class] {
			continue
		}
		if !until.IsZero() && a.FirstSeen.After(until) {
			continue
		}
		loc, ok := lookup(a.Source)
		if !ok {
			continue
		}
		addTo(byCity, loc.CountryCode+"|"+loc.City, loc, a, true)
		addTo(byCountry, loc.CountryCode, loc, a, false)
		mapped++
	}
	cities = points(byCity)
	sort.Slice(cities, func(i, j int) bool {
		if cities[i].Score != cities[j].Score {
			return cities[i].Score < cities[j].Score
		}
		return cities[i].Count < cities[j].Count
	})
	countries = points(byCountry)
	sort.Slice(countries, func(i, j int) bool {
		if countries[i].Count != countries[j].Count {
			return countries[i].Count > countries[j].Count
		}
		return countries[i].Score > countries[j].Score
	})
	return cities, countries, mapped
}

func addTo(m map[string]*MapPoint, key string, loc geo.Location, a classify.Actor, city bool) {
	p := m[key]
	if p == nil {
		p = &MapPoint{Lat: loc.Lat, Lon: loc.Lon, Country: loc.Country, CountryCode: loc.CountryCode}
		if city {
			p.City = loc.City
		}
		m[key] = p
	}
	p.Count++
	if a.Score >= p.Score { // the worst actor here defines the point's class
		p.Score, p.TopClass = a.Score, a.Class
	}
	if city && len(p.Sources) < 8 {
		p.Sources = append(p.Sources, a.Source)
	}
}

func points(m map[string]*MapPoint) []MapPoint {
	out := make([]MapPoint, 0, len(m))
	for _, p := range m {
		out = append(out, *p)
	}
	return out
}
