package main

import (
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

func newDdbProxy(cfg *config) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if !validateRequest(cfg, r) {
			http.Error(w, "KO", http.StatusBadRequest)
			return
		}

		proxyReq, err := http.NewRequest(r.Method, cfg.DdbEndpoint, debugRequest(cfg, r))
		if err != nil {
			http.Error(w, "KO", http.StatusBadRequest)
			return
		}

		for key, values := range r.Header {
			for _, value := range values {
				proxyReq.Header.Add(key, value)
			}
		}

		client := &http.Client{Timeout: time.Duration(cfg.ClientTimeoutSec) * time.Second}
		resp, err := client.Do(proxyReq)
		if err != nil {
			http.Error(w, "KO", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		for key, values := range resp.Header {
			for _, value := range values {
				w.Header().Add(key, value)
			}
		}
		w.WriteHeader(resp.StatusCode)
		_, err = io.Copy(w, resp.Body)
		if err != nil {
			http.Error(w, "KO", http.StatusInternalServerError)
		}
	}
}

const authKey = "Authorization"
const authPrefix = "AWS4-HMAC-SHA256 Credential="

func validateRequest(cfg *config, r *http.Request) bool {
	params := strings.Split(r.URL.Path, "/")
	if len(params) < 3 {
		log.Printf("Invalid request: remote: %v, path: %s\n", r.RemoteAddr, r.URL.Path)
		return false
	}

	auth := r.Header.Get(authKey)
	for _, user := range cfg.Users {
		if user.Name != params[1] || user.Secret != params[2] {
			continue
		}
		if strings.HasPrefix(auth, authPrefix+user.Name+"/") {
			return true
		}
	}

	log.Printf("Invalid request: remote: %v, path: %s\n", r.RemoteAddr, r.URL.Path)
	return false
}
