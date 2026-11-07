package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealthReportsFullBuildRevision(t *testing.T) {
	const revision = "0123456789abcdef0123456789abcdef01234567"
	previous := BuildVersion
	BuildVersion = revision
	t.Cleanup(func() { BuildVersion = previous })

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	(&Server{}).health(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d, want %d", recorder.Code, http.StatusOK)
	}
	var body struct {
		OK      bool   `json:"ok"`
		Service string `json:"service"`
		Version string `json:"version"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode health response: %v", err)
	}
	if !body.OK || body.Service != "artex" || body.Version != revision {
		t.Fatalf("unexpected health response: %+v", body)
	}
}
