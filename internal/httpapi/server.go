package httpapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"nodekit/internal/model"
	"nodekit/internal/render"
	"nodekit/internal/store"
	"strings"
)

type Backend interface {
	View(context.Context) (store.Record, error)
	Reset(context.Context) error
	Change(context.Context, model.Config) error
}

func Subscription(b Backend) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" && r.Method != "HEAD" {
			http.NotFound(w, r)
			return
		}
		record, e := b.View(r.Context())
		if e != nil {
			http.Error(w, "subscription unavailable", 503)
			return
		}
		base := "/s/" + record.Config.Token + "/"
		provider := r.URL.Path == base+"proxies.yaml"
		if !provider && r.URL.Path != base+"config.yaml" {
			http.NotFound(w, r)
			return
		}
		body, e := render.Subscription(record.Config, provider)
		if e != nil {
			http.Error(w, "invalid subscription configuration", 503)
			return
		}
		info := fmt.Sprintf("upload=%d; download=%d", record.Meter.Upload, record.Meter.Download)
		if record.Config.Quota > 0 {
			info += fmt.Sprintf("; total=%d", record.Config.Quota)
		}
		if record.Config.Expiry != nil {
			info += fmt.Sprintf("; expire=%d", record.Config.Expiry.Unix())
		}
		w.Header().Set("Subscription-Userinfo", info)
		w.Header().Set("Profile-Title", "base64:"+base64.StdEncoding.EncodeToString([]byte(record.Config.Name)))
		w.Header().Set("Profile-Update-Interval", "6")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
		w.Header().Set("Content-Length", fmt.Sprint(len(body)))
		if r.Method == "GET" {
			_, _ = w.Write(body)
		}
	})
}
func Admin(b Backend) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		switch r.Method + " " + r.URL.Path {
		case "GET /status":
			record, e := b.View(r.Context())
			if e != nil {
				http.Error(w, e.Error(), 503)
				return
			}
			record.Config.Token = ""
			record.Config.Reality.PrivateKey = ""
			for i := range record.Config.Protocols {
				record.Config.Protocols[i].Password = ""
				record.Config.Protocols[i].UUID = ""
			}
			if record.Operation != nil {
				record.OperationPhase = record.Operation.Phase
			}
			record.Operation = nil
			_ = json.NewEncoder(w).Encode(record)
		case "GET /config":
			record, e := b.View(r.Context())
			if e != nil {
				http.Error(w, e.Error(), 503)
				return
			}
			_ = json.NewEncoder(w).Encode(record.Config)
		case "POST /usage/reset":
			if e := b.Reset(r.Context()); e != nil {
				http.Error(w, e.Error(), 503)
				return
			}
			w.WriteHeader(204)
		case "POST /usage/flush":
			f, ok := b.(interface{ Flush(context.Context) error })
			if !ok {
				http.Error(w, "flush unavailable", 503)
				return
			}
			if e := f.Flush(r.Context()); e != nil {
				http.Error(w, e.Error(), 503)
				return
			}
			w.WriteHeader(204)
		case "POST /cert/renew":
			issuer, ok := b.(interface {
				Renew(context.Context, string) error
			})
			if !ok {
				http.Error(w, "renewal unavailable", 503)
				return
			}
			var request struct {
				Domain string `json:"domain"`
			}
			if e := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&request); e != nil {
				http.Error(w, "invalid renewal request", 400)
				return
			}
			if e := issuer.Renew(r.Context(), request.Domain); e != nil {
				http.Error(w, e.Error(), 409)
				return
			}
			w.WriteHeader(204)
		case "PUT /config", "PUT /config/managed":
			coordinated := r.URL.Path == "/config/managed"
			if coordinated && !RootPeer(r.Context()) {
				http.Error(w, "root Unix peer required", 403)
				return
			}
			var c model.Config
			dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
			dec.DisallowUnknownFields()
			if e := dec.Decode(&c); e != nil {
				http.Error(w, "invalid config", 400)
				return
			}
			if e := c.Validate(); e != nil {
				http.Error(w, e.Error(), 400)
				return
			}
			change := b.Change
			if coordinated {
				manager, ok := b.(interface {
					ChangeManaged(context.Context, model.Config) error
				})
				if !ok {
					http.Error(w, "DNS coordination unavailable", 503)
					return
				}
				change = manager.ChangeManaged
			}
			if e := change(r.Context(), c); e != nil {
				http.Error(w, e.Error(), 409)
				return
			}
			w.WriteHeader(204)
		default:
			if strings.Contains(r.URL.Path, "..") {
				http.NotFound(w, r)
				return
			}
			http.NotFound(w, r)
		}
	})
}
