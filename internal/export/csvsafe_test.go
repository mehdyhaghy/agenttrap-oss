package export

import "testing"

func TestCSVSafe(t *testing.T) {
	for in, want := range map[string]string{
		`=HYPERLINK("http://x")`: `'=HYPERLINK("http://x")`,
		"@SUM(A1)":               "'@SUM(A1)",
		"+1":                     "'+1",
		"-1":                     "'-1",
		"curl/8.7.1":             "curl/8.7.1",
		"":                       "",
	} {
		if got := csvSafe(in); got != want {
			t.Errorf("csvSafe(%q) = %q, want %q", in, got, want)
		}
	}
}
