package hub

import (
	"testing"
	"time"

	"agenttrap/internal/classify"
	"agenttrap/internal/geo"
)

func TestAggregatePoints(t *testing.T) {
	// A fake geolocator: two actors in London, one in Frankfurt, one private.
	locs := map[string]geo.Location{
		"1.2.3.4": {CountryCode: "GB", Country: "United Kingdom", City: "London", Lat: 51.5, Lon: -0.1},
		"1.2.3.5": {CountryCode: "GB", Country: "United Kingdom", City: "London", Lat: 51.5, Lon: -0.1},
		"5.6.7.8": {CountryCode: "DE", Country: "Germany", City: "Frankfurt", Lat: 50.1, Lon: 8.7},
	}
	lookup := func(ip string) (geo.Location, bool) { l, ok := locs[ip]; return l, ok }

	actors := []classify.Actor{
		{Source: "1.2.3.4", Class: classify.Scanner, Score: 20},
		{Source: "1.2.3.5", Class: classify.RogueAgent, Score: 80},
		{Source: "5.6.7.8", Class: classify.AIAgent, Score: 55},
		{Source: "9.9.9.9", Class: classify.RogueAgent, Score: 90}, // no geo -> dropped
		{Source: "10.0.0.5", Class: classify.Operator, Score: 100}, // operator -> dropped
	}
	cities, countries, mapped := aggregatePoints(actors, time.Time{}, nil, lookup)

	if mapped != 3 {
		t.Fatalf("mapped %d, want 3 (no-geo and operator excluded)", mapped)
	}
	if len(cities) != 2 {
		t.Fatalf("cities %d, want 2", len(cities))
	}
	// London is the two-actor city; its class comes from the highest-scoring actor.
	var london *MapPoint
	for i := range cities {
		if cities[i].City == "London" {
			london = &cities[i]
		}
	}
	if london == nil || london.Count != 2 || london.Score != 80 || london.TopClass != classify.RogueAgent {
		t.Fatalf("london point: %+v", london)
	}
	// Cities sorted loudest-last: the highest-scoring point is at the end.
	if cities[len(cities)-1].City != "London" {
		t.Fatalf("expected London (score 80) last, got %s", cities[len(cities)-1].City)
	}
	// Country rollup: GB has 2 actors, DE has 1; busiest first.
	if len(countries) != 2 || countries[0].CountryCode != "GB" || countries[0].Count != 2 {
		t.Fatalf("countries: %+v", countries)
	}

	// Class filter keeps only rogue agents (London's rogue).
	cf, _, m := aggregatePoints(actors, time.Time{}, map[string]bool{classify.RogueAgent: true}, lookup)
	if m != 1 || len(cf) != 1 || cf[0].City != "London" || cf[0].Count != 1 {
		t.Fatalf("class-filtered: mapped=%d %+v", m, cf)
	}

	// until excludes actors that first appeared after the window end.
	cutoff := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	late := []classify.Actor{{Source: "1.2.3.4", Class: classify.Scanner, Score: 20, FirstSeen: cutoff.Add(time.Hour)}}
	_, _, lm := aggregatePoints(late, cutoff, nil, lookup)
	if lm != 0 {
		t.Fatalf("actor after until should be excluded, mapped=%d", lm)
	}
}

func TestGeoDisabled(t *testing.T) {
	if db, err := geo.Open(""); err != nil || db != nil {
		t.Fatalf("empty path should disable geo: db=%v err=%v", db, err)
	}
	var db *geo.DB
	if _, ok := db.Lookup("1.2.3.4"); ok {
		t.Fatal("nil DB should never resolve")
	}
}
