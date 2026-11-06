package integration

import (
	"crypto/tls"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
)

// REALITY contacts its camouflage target even for authenticated connections.
// Use a real TLS 1.3 server on loopback so protocol tests work in a network
// namespace without public DNS/Internet access. Authentication stays enabled.
func localRealityTarget(t *testing.T) string {
	t.Helper()
	target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	target.EnableHTTP2 = true
	target.TLS = &tls.Config{MinVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519}}
	target.Config.ErrorLog = log.New(io.Discard, "", 0)
	target.StartTLS()
	t.Cleanup(target.Close)
	return target.Listener.Addr().String()
}
