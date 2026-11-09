package tea

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// Case 39a: trace events for API calls carry no query or credential.
func TestTraceEvents(t *testing.T) {
	const (
		pageToken = "page-token-SECRET-1"
		bearer    = "bearer-SECRET-2"
		keyID     = "key-id-SECRET-3"
		secret    = "key-secret-SECRET-4"
	)
	ctx := context.Background()
	srv := startHTTP(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/token"):
			jsonHandler(`{"access_token":"issued-SECRET-5","token_type":"Bearer"}`)(w, r)
		case strings.HasSuffix(r.URL.Path, "/r"):
			http.Redirect(w, r, r.URL.Query().Get("to"), http.StatusFound)
		default:
			jsonHandler(`{"hasNext":false,"results":[]}`)(w, r)
		}
	}))
	var events []TraceEvent
	a := newTestAPI(t, srv.URL, "/tea", WithBearerToken(srv.URL+"/tea", bearer), WithTrace(func(ev TraceEvent) {
		events = append(events, ev)
	}))
	apiURL := srv.URL + "/tea/v1.0.0"

	if _, err := a.QueryProducts(ctx, ProductQuery{Page: Page{PageToken: pageToken, PageSize: 5}}); err != nil {
		t.Fatal(err)
	}
	want := []TraceEvent{
		{Kind: TraceRequest, Stage: StageAPI, Method: "GET", URL: apiURL + "/products"},
		{Kind: TraceResponse, Stage: StageAPI, Method: "GET", URL: apiURL + "/products", Status: 200},
	}
	if fmt.Sprint(events) != fmt.Sprint(want) {
		t.Errorf("QueryProducts events:\n%v\nwant\n%v", events, want)
	}

	events = nil
	to := url.QueryEscape(apiURL + "/products?pageToken=" + pageToken)
	if _, err := a.Generated().QueryProductsWithResponse(ctx, nil, rewriteTo(t, apiURL+"/r?to="+to)); err != nil {
		t.Fatal(err)
	}
	if len(events) != 4 || events[0].URL != apiURL+"/r" || events[1].Status != 302 ||
		events[2].Kind != TraceRequest || events[2].URL != apiURL+"/products" || events[3].Status != 200 {
		t.Errorf("redirect events: %v", events)
	}
	all := append([]TraceEvent{}, events...)

	events = nil
	if _, err := a.RequestToken(ctx, keyID, secret); err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[0].Stage != StageToken || events[0].Method != "POST" || events[0].URL != apiURL+"/token" ||
		events[1].Stage != StageToken || events[1].Status != 200 {
		t.Errorf("token events: %v", events)
	}
	all = append(all, events...)
	all = append(all, want...)

	for _, ev := range all {
		s := fmt.Sprintf("%+v", ev)
		for _, bad := range []string{"?", pageToken, bearer, keyID, secret, "SECRET", "%3F"} {
			if strings.Contains(s, bad) {
				t.Errorf("event %s contains %q", s, bad)
			}
		}
	}
}
