package tea

import (
	"errors"
	"testing"
)

// ParseAPIBase refuses a version that is not SemVer or not supported, with
// build metadata ignored for the comparison and kept verbatim in the path
// (D10; implementation note departure 4).
func TestParseAPIBaseVersion(t *testing.T) {
	const root = "https://example.com/tea"
	for _, v := range []string{"2.0.0", "1.0", "v1.0.0", "", "1.0.0-rc.1", "1.0.1", "01.0.0", "1.0.0+"} {
		b, err := ParseAPIBase(root, v)
		if !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("version %q: %v, want ErrInvalidArgument", v, err)
		}
		if b.String() != "" {
			t.Errorf("version %q: a refused base is not zero: %q", v, b.String())
		}
	}
	for _, v := range []string{"1.0.0", "1.0.0+b", "1.0.0+build.5"} {
		b, err := ParseAPIBase(root, v)
		if err != nil {
			t.Errorf("version %q: %v", v, err)
			continue
		}
		if b.Version() != v || b.String() != root+"/v"+v || b.RootURL() != root {
			t.Errorf("version %q: base %q version %q root %q", v, b.String(), b.Version(), b.RootURL())
		}
	}
}
