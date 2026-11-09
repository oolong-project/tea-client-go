package tea

import (
	"net/url"
	"testing"
)

// fuzzClient allows one http origin, so learned http bases are exercised
// both ways, and caps results at 4.
func fuzzClient(f *testing.F) *Client {
	f.Helper()
	c, err := New(WithInsecureHTTPBase("http://127.0.0.1:8080"), WithLimits(Limits{DiscoveryResults: 4}))
	if err != nil {
		f.Fatal(err)
	}
	return c
}

// Case 17: the well-known decoder never panics, and what it accepts is
// usable: every candidate is a supported, policy-approved API base.
func FuzzDecodeWellKnown(f *testing.F) {
	for _, s := range []string{
		`{"schemaVersion":1,"endpoints":[{"url":"https://a.example.com/tea","versions":["1.0.0"],"priority":0.5}]}`,
		`{"schemaVersion":1,"endpoints":[{"url":"http://127.0.0.1:8080/tea","versions":["0.2.0-beta.2","1.0.0+b"]},{"url":"https://b.example.com","versions":["1.0.0"]}]}`,
		`{"schemaVersion":1,"endpoints":[{"url":"https://h/a/../b","versions":["1.0.0"]}]}`,
		`{"schemaVersion":1.0,"endpoints":[{"url":"https://h","versions":["1.0.0"],"priority":1e0,"x":null}]}`,
		`{"schemaVersion":1,"endpoints":[]}`, `{"schemaVersion":"1"}`, `[]`, `null`, `{`, ``, `{"endpoints":{}}`,
	} {
		f.Add([]byte(s))
	}
	c := fuzzClient(f)
	f.Fuzz(func(t *testing.T, body []byte) {
		cands, err := c.decodeWellKnown(body)
		if err != nil {
			if cands != nil {
				t.Fatalf("candidates with an error")
			}
			return
		}
		for _, cd := range cands {
			u := cd.base.url()
			if u == nil || !rootURLPattern.MatchString(cd.base.RootURL()) || !supportedVersion(cd.base.Version()) || c.checkURL(u) != nil {
				t.Fatalf("accepted an unusable candidate %q", cd.base.String())
			}
		}
	})
}

// Case 17: the discovery decoder never panics, and what it accepts holds
// the rules of architecture 3.6 step 5.
func FuzzDecodeDiscovery(f *testing.F) {
	for _, s := range []string{
		`[{"productReleaseUuid":"22222222-2222-4222-8222-222222222222","servers":[{"rootUrl":"https://a.example.com","versions":["1.0.0"],"priority":1}]}]`,
		`[{"productReleaseUuid":"ABCDEF00-2222-4222-8222-222222222222","servers":[{"rootUrl":"http://127.0.0.1:8080/tea","versions":["1.0.0"]}]},{"productReleaseUuid":"{22222222-2222-4222-8222-222222222222}","servers":[{"rootUrl":"https://b","versions":["2.0.0"]}]}]`,
		`[{"productReleaseUuid":"not-a-uuid","servers":[]}]`,
		`[{"productReleaseUuid":"22222222-2222-4222-8222-222222222222","servers":[{"rootUrl":"http://localhost:8080","versions":["1.0.0"]}]}]`,
		`[1,2,3,4,5]`, `[]`, `null`, `{}`, `[`, ``,
	} {
		f.Add([]byte(s))
	}
	c := fuzzClient(f)
	f.Fuzz(func(t *testing.T, body []byte) {
		res, err := c.decodeDiscovery(body)
		if err != nil {
			if res != nil {
				t.Fatalf("results with an error")
			}
			return
		}
		if len(res) == 0 || len(res) > 4 {
			t.Fatalf("accepted %d results", len(res))
		}
		for _, r := range res {
			if len(r.Servers) == 0 {
				t.Fatalf("accepted a result without servers")
			}
			for _, s := range r.Servers {
				u, perr := url.Parse(s.RootUrl)
				if perr != nil || !rootURLPattern.MatchString(s.RootUrl) || c.checkURL(u) != nil || len(s.Versions) == 0 {
					t.Fatalf("accepted server %+v", s)
				}
				for _, v := range s.Versions {
					if !validVersion(v) {
						t.Fatalf("accepted version %q", v)
					}
				}
				if s.Priority != nil && (*s.Priority < 0 || *s.Priority > 1) {
					t.Fatalf("accepted priority %v", *s.Priority)
				}
			}
		}
	})
}
