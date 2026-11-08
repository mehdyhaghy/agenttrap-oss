// Package geo resolves a client IP to an approximate city location using a
// bundled DB-IP Lite City database (MMDB format). The database is provided as a
// host file mounted into the hub; when it is absent, geolocation is simply
// disabled. The hub has no internet egress, so every lookup is local.
//
// DB-IP Lite is licensed CC-BY-4.0: any surface that shows this data must carry
// a visible "IP geolocation by DB-IP" attribution (see AttributionText).
package geo

import (
	"net/netip"

	"github.com/oschwald/maxminddb-golang/v2"
)

// AttributionText is the attribution CC-BY-4.0 requires wherever the data shows.
const AttributionText = "IP geolocation by DB-IP"

// Location is an approximate position for an IP.
type Location struct {
	CountryCode string  `json:"country_code"`
	Country     string  `json:"country"`
	City        string  `json:"city"`
	Lat         float64 `json:"lat"`
	Lon         float64 `json:"lon"`
}

// DB is an opened city database.
type DB struct{ r *maxminddb.Reader }

// Open opens the MMDB at path. An empty path returns (nil, nil): geolocation is
// disabled and every Lookup misses, which callers handle gracefully.
func Open(path string) (*DB, error) {
	if path == "" {
		return nil, nil
	}
	r, err := maxminddb.Open(path)
	if err != nil {
		return nil, err
	}
	return &DB{r: r}, nil
}

// Lookup resolves an IP string to a Location. It reports false for a nil DB, an
// unparseable or private address, or a record with no coordinates.
func (db *DB) Lookup(ipStr string) (Location, bool) {
	if db == nil {
		return Location{}, false
	}
	ip, err := netip.ParseAddr(ipStr)
	if err != nil || !ip.IsGlobalUnicast() || ip.IsPrivate() {
		return Location{}, false
	}
	var rec struct {
		Country struct {
			ISOCode string            `maxminddb:"iso_code"`
			Names   map[string]string `maxminddb:"names"`
		} `maxminddb:"country"`
		City struct {
			Names map[string]string `maxminddb:"names"`
		} `maxminddb:"city"`
		Location struct {
			Lat float64 `maxminddb:"latitude"`
			Lon float64 `maxminddb:"longitude"`
		} `maxminddb:"location"`
	}
	if err := db.r.Lookup(ip.Unmap()).Decode(&rec); err != nil {
		return Location{}, false
	}
	loc := Location{
		CountryCode: rec.Country.ISOCode,
		Country:     rec.Country.Names["en"],
		City:        rec.City.Names["en"],
		Lat:         rec.Location.Lat,
		Lon:         rec.Location.Lon,
	}
	if loc.Lat == 0 && loc.Lon == 0 {
		return loc, false // no usable coordinates
	}
	return loc, true
}

// Close releases the database.
func (db *DB) Close() error {
	if db == nil {
		return nil
	}
	return db.r.Close()
}
