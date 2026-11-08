package demogpu

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"

	"agenttrap/internal/events"
)

// beaconPath receives the page beacon on every HTML host.
const beaconPath = "/_rum"

// newViewID identifies one HTML page view so its beacon can be matched to it.
func newViewID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// beaconPayload is what the page script sends. Only counts, flags and sizes:
// no text typed, no page content, no identifiers beyond the view ID.
type beaconPayload struct {
	ViewID      string `json:"v"`
	Phase       string `json:"ph"` // load or hide
	Webdriver   bool   `json:"wd"`
	Languages   int    `json:"l"`
	Plugins     int    `json:"p"`
	Cores       int    `json:"hc"`
	Memory      int    `json:"dm"`
	TimeZone    string `json:"tz"`
	ScreenW     int    `json:"sw"`
	ScreenH     int    `json:"sh"`
	OuterW      int    `json:"ow"`
	OuterH      int    `json:"oh"`
	Chrome      bool   `json:"ch"`
	TouchPoints int    `json:"tp"`
	MouseMoves  int    `json:"m"`
	Keys        int    `json:"k"`
	Scrolls     int    `json:"s"`
	Clicks      int    `json:"c"`
	DwellMS     int64  `json:"dt"`
	Visibility  string `json:"vs"`
	// Interaction behavior (see site/rum/app.ts).
	Untrusted   int `json:"ut"` // events with isTrusted=false
	FirstInput  int `json:"fi"` // ms from load to first input, -1 if none
	PathLen     int `json:"pl"` // pointer travel, px
	PathDisp    int `json:"pd"` // straight-line distance first to last point, px
	Jumps       int `json:"pj"` // pointer moves > 300 px between samples
	ClickOffset int `json:"co"` // mean distance of clicks from element center, -1 if no clicks
	ClickNoHov  int `json:"cn"` // clicks without prior pointer movement over the target
	KeyGaps     int `json:"kn"` // keystroke intervals measured
	KeyMean     int `json:"km"` // mean interval, ms
	KeySD       int `json:"ks"` // interval standard deviation, ms
	Pastes      int `json:"pa"`
	ScrollJumps int `json:"sj"` // scroll steps > 1000 px
}

// serveBeacon records a page beacon. It always answers 204 so the script
// never retries or reveals anything.
func (s *Server) serveBeacon(w http.ResponseWriter, r *http.Request) {
	defer w.WriteHeader(http.StatusNoContent)
	if r.Method != http.MethodPost {
		return
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, 4<<10))
	if err != nil {
		return
	}
	var p beaconPayload
	if json.Unmarshal(data, &p) != nil || len(p.ViewID) != 16 {
		return
	}
	s.emit(r, events.Event{Kind: events.KindBeacon, Protocol: "http", Detail: map[string]any{
		"view_id": p.ViewID, "phase": truncate(p.Phase, 8), "webdriver": p.Webdriver,
		"languages": p.Languages, "plugins": p.Plugins, "cores": p.Cores, "memory": p.Memory,
		"timezone": truncate(p.TimeZone, 64), "screen": []int{p.ScreenW, p.ScreenH},
		"outer": []int{p.OuterW, p.OuterH}, "chrome_object": p.Chrome, "touch_points": p.TouchPoints,
		"mouse_moves": p.MouseMoves, "keys": p.Keys, "scrolls": p.Scrolls, "clicks": p.Clicks,
		"dwell_ms": p.DwellMS, "visibility": truncate(p.Visibility, 16),
		"untrusted": p.Untrusted, "first_input_ms": p.FirstInput, "path_len": p.PathLen, "path_disp": p.PathDisp,
		"pointer_jumps": p.Jumps, "click_offset": p.ClickOffset, "click_no_hover": p.ClickNoHov,
		"key_gaps": p.KeyGaps, "key_mean_ms": p.KeyMean, "key_sd_ms": p.KeySD, "pastes": p.Pastes,
		"scroll_jumps": p.ScrollJumps,
	}})
}

// replayPath receives rrweb recording chunks on every HTML host.
const replayPath = "/_rum/r"

// serveReplay forwards one recording chunk. Chunks are small (the page keeps
// them under 64 KB) and capped per page view by the script.
func (s *Server) serveReplay(w http.ResponseWriter, r *http.Request) {
	defer w.WriteHeader(http.StatusNoContent)
	if r.Method != http.MethodPost {
		return
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	if err != nil {
		return
	}
	var chunk struct {
		ViewID string          `json:"v"`
		Seq    int             `json:"s"`
		Events json.RawMessage `json:"e"`
	}
	if json.Unmarshal(data, &chunk) != nil || len(chunk.ViewID) != 16 || chunk.Seq < 0 || chunk.Seq > 200 || len(chunk.Events) < 2 {
		return
	}
	s.emit(r, events.Event{Kind: events.KindReplay, Protocol: "http", Detail: map[string]any{
		"view_id": chunk.ViewID, "seq": chunk.Seq, "rrweb": string(chunk.Events),
	}})
}
