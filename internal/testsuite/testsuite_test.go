package testsuite_test

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"agenttrap/adapters/demogpu"
	"agenttrap/internal/canary"
	"agenttrap/internal/events"
	"agenttrap/internal/testsuite"
	"agenttrap/internal/worldpack"
	"agenttrap/personas"
)

type discard struct{}

func (discard) Record(events.Event) {}

// The shipped persona must pass its own test suite: this is the
// deployment gate, run on every test pass.
func TestPersonaPassesTestSuite(t *testing.T) {
	if testing.Short() {
		t.Skip("probes chat latency")
	}
	pack, err := worldpack.Parse(personas.DemoGPU)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(demogpu.New(pack, canary.NewSet([]byte("seed"), pack), discard{}, demogpu.Options{}))
	defer srv.Close()
	rep := testsuite.Run(context.Background(), testsuite.Target{Domain: pack.Company.Domain, Scheme: "http",
		Addr: strings.TrimPrefix(srv.URL, "http://")})
	for _, c := range rep.Checks {
		if !c.Pass && !c.Skipped {
			t.Errorf("%s/%s failed: %s (%s)", c.Dimension, c.ID, c.Title, c.Detail)
		}
	}
	if !rep.Pass || rep.Score < testsuite.Gate {
		t.Fatalf("score %.1f below gate %d", rep.Score, testsuite.Gate)
	}
}
