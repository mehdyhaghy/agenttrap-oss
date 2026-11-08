package geo

import (
	"os"
	"testing"
)

func TestOpenEmptyDisables(t *testing.T) {
	db, err := Open("")
	if err != nil || db != nil {
		t.Fatalf("empty path should disable geo: db=%v err=%v", db, err)
	}
	if _, ok := db.Lookup("8.8.8.8"); ok {
		t.Fatal("nil DB should never resolve")
	}
}

// TestLookupAgainstDatabase runs only when GEO_TEST_DB points at a real DB-IP
// City MMDB, so CI without the file still passes. It checks that a few known
// public IPs resolve to plausible coordinates and that private ones miss.
func TestLookupAgainstDatabase(t *testing.T) {
	path := os.Getenv("GEO_TEST_DB")
	if path == "" {
		t.Skip("set GEO_TEST_DB to a DB-IP City MMDB to run this")
	}
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	loc, ok := db.Lookup("8.8.8.8")
	if !ok || loc.CountryCode != "US" || loc.Lat == 0 {
		t.Fatalf("8.8.8.8 resolved to %+v (ok=%v)", loc, ok)
	}
	if _, ok := db.Lookup("192.168.1.1"); ok {
		t.Fatal("private address must not resolve")
	}
	if _, ok := db.Lookup("not-an-ip"); ok {
		t.Fatal("garbage must not resolve")
	}
}
