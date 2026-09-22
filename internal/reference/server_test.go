package reference

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestReferenceRejectsForeignHostOnRead(t *testing.T) {
	ts := httptest.NewServer(New("t").Handler())
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/", nil)
	req.Host = "panel.attacker.example"
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("foreign Host accepted: %d", resp.StatusCode)
	}
}

func TestReferenceRejectsMutationWithoutToken(t *testing.T) {
	ts := httptest.NewServer(New("t").Handler())
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/execute", nil)
	req.Header.Set("Origin", "http://127.0.0.1")
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("mutation without token accepted: %d", resp.StatusCode)
	}
}

func TestReferenceStateChangingGetIsMethodNotAllowed(t *testing.T) {
	ts := httptest.NewServer(New("t").Handler())
	defer ts.Close()

	resp, err := ts.Client().Get(ts.URL + "/api/execute")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("state-changing GET not rejected: %d", resp.StatusCode)
	}
}

func TestNewTokenIsFreshAndSized(t *testing.T) {
	a, b := NewToken(), NewToken()
	if a == b {
		t.Error("two tokens identical")
	}
	if len(a) != 64 {
		t.Errorf("token length %d, want 64", len(a))
	}
}
