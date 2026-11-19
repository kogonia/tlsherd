package notify

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSendWebhookMethodAndHeaders(t *testing.T) {
	var gotMethod, gotAuth, gotSig, gotCT string
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotAuth = r.Header.Get("Authorization")
		gotSig = r.Header.Get("X-Tlsherd-Signature")
		gotCT = r.Header.Get("Content-Type")
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	payload := []byte(`{"ok":true}`)
	err := SendWebhook(context.Background(), WebhookConfig{
		URL:     srv.URL,
		Method:  "PUT",
		Headers: map[string]string{"Authorization": "Bearer t"},
		Secret:  "s3cret",
	}, payload)
	if err != nil {
		t.Fatalf("SendWebhook: %v", err)
	}
	if gotMethod != http.MethodPut {
		t.Fatalf("method=%q want PUT", gotMethod)
	}
	if gotAuth != "Bearer t" {
		t.Fatalf("Authorization=%q", gotAuth)
	}
	if gotCT != "application/json" {
		t.Fatalf("Content-Type=%q", gotCT)
	}
	mac := hmac.New(sha256.New, []byte("s3cret"))
	mac.Write(payload)
	want := hex.EncodeToString(mac.Sum(nil))
	if gotSig != want {
		t.Fatalf("signature=%q want %q", gotSig, want)
	}
	if string(gotBody) != string(payload) {
		t.Fatalf("body=%q", gotBody)
	}
}

func TestSendWebhookGETNoBody(t *testing.T) {
	var gotMethod string
	var n int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		n, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	err := SendWebhook(context.Background(), WebhookConfig{
		URL:    srv.URL,
		Method: "GET",
		Secret: "ignored-for-get",
	}, []byte(`{"x":1}`))
	if err != nil {
		t.Fatalf("SendWebhook: %v", err)
	}
	if gotMethod != http.MethodGet {
		t.Fatalf("method=%q", gotMethod)
	}
	if n != 0 {
		t.Fatalf("body bytes=%d want 0", n)
	}
}

func TestValidWebhookMethod(t *testing.T) {
	for _, m := range []string{"", "post", "GET", "Put", "PATCH"} {
		if !ValidWebhookMethod(m) && m != "" {
			t.Fatalf("%q should be valid", m)
		}
	}
	if !ValidWebhookMethod("") { // empty normalizes to POST
		t.Fatal("empty should be valid")
	}
	if ValidWebhookMethod("DELETE") {
		t.Fatal("DELETE should be rejected")
	}
}
