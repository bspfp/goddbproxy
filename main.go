package main

import (
	"bspfp/gosimplelog"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"
)

const refreshConfigTime = 10 * time.Second

func main() {
	configFile := createConfigFile(parseFlag())

	logCloser, err := gosimplelog.InitLogFile("./log", "goddbproxy.log", 20)
	if err != nil {
		log.Fatalf("failed to init log file: %+v\n", err)
		os.Exit(1)
	}
	defer logCloser.Close()

	if err := loadConfig(configFile); err != nil {
		log.Fatalf("failed to load config file: %+v\n", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	server, runFn := newServer(ctx)

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	log.Printf("start server on %s\n", gConfig.Load().Addr)
	go func() {
		if err := runFn(); err != nil {
			if errors.Is(err, http.ErrServerClosed) {
				log.Printf("server closed\n")
			} else {
				log.Fatalf("failed to run server: %+v\n", err)
			}
		}
	}()

	go refreshConfig(ctx, configFile)

	<-quit

	log.Println("shutting down server...")
	cancel()

	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		log.Printf("failed to shutdown server: %+v\n", err)
		log.Fatalln("server force shutdown")
	}

	log.Println("server shutdown")
}

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
	if len(params) != 3 {
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

	return false
}

var gConfig atomic.Pointer[config]

type user struct {
	Name   string `json:"name"`
	Secret string `json:"secret"`
}

type config struct {
	Addr             string  `yaml:"addr"`
	CertFile         string  `yaml:"certFile"`
	KeyFile          string  `yaml:"keyFile"`
	DdbEndpoint      string  `yaml:"ddbEndpoint"`
	ReadTimeoutSec   int     `yaml:"readTimeoutSec"`
	WriteTimeoutSec  int     `yaml:"writeTimeoutSec"`
	IdleTimeoutSec   int     `yaml:"idleTimeoutSec"`
	ClientTimeoutSec int     `yaml:"clientTimeoutSec"`
	DebugRequest     bool    `yaml:"debugRequest"`
	Users            []*user `yaml:"users"`
}

func defaultConfig() *config {
	return &config{
		Addr:             "localhost:9000",
		CertFile:         "./cert.pem",
		KeyFile:          "./key.pem",
		DdbEndpoint:      "http://localhost:8000",
		ReadTimeoutSec:   30,
		WriteTimeoutSec:  30,
		IdleTimeoutSec:   30,
		ClientTimeoutSec: 30,
		DebugRequest:     false,
		Users:            []*user{{Name: "username", Secret: "secret"}},
	}
}

func createConfigFile(configFile string, createOnly bool) string {
	if !createOnly {
		return configFile
	}

	cfg := defaultConfig()

	f, err := os.Create(configFile)
	if err != nil {
		log.Fatalf("failed to create config file: %+v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	if err := yaml.NewEncoder(f).Encode(cfg); err != nil {
		log.Fatalf("failed to encode config file: %+v\n", err)
		os.Exit(1)
	}

	os.Exit(0)
	panic("unreachable")
}

func parseFlag() (configFile string, createOnly bool) {
	flag.StringVar(&configFile, "f", "./config.yaml", "config file")
	flag.BoolVar(&createOnly, "c", false, "create config file and exit")
	flag.Parse()

	if len(flag.Args()) > 0 {
		flag.Usage()
		os.Exit(1)
	}
	return
}

func loadConfig(configFile string) error {
	f, err := os.Open(configFile)
	if err != nil {
		return fmt.Errorf("failed to open config file: %+v\n", err)
	}
	defer f.Close()

	cfg := &config{}
	if err := yaml.NewDecoder(f).Decode(cfg); err != nil {
		return fmt.Errorf("failed to decode config file: %+v\n", err)
	}

	gConfig.Store(cfg)

	return nil
}

func convNumerToValue(value any) any {
	switch t := value.(type) {
	case json.Number:
		if n, err := t.Int64(); err == nil {
			return n
		}
		if n, err := t.Float64(); err == nil {
			return n
		}
		return t.String()

	case map[string]any:
		for k, v := range t {
			t[k] = convNumerToValue(v)
		}
		return t

	case []any:
		for i, v := range t {
			t[i] = convNumerToValue(v)
		}
		return t

	default:
		return value
	}
}

func refreshConfig(ctx context.Context, configFile string) {
	ticker := time.NewTicker(refreshConfigTime)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := loadConfig(configFile); err != nil {
				log.Printf("failed to load config file: %+v\n", err)
			}
		}
	}
}

type tlsCert struct {
	certFile string
	keyFile  string
	cert     atomic.Pointer[tls.Certificate]
}

func newTlsCert(ctx context.Context, certFile, keyFile string) (*tlsCert, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load certificate: %w", err)
	}

	ret := &tlsCert{
		certFile: certFile,
		keyFile:  keyFile,
	}
	ret.cert.Store(&cert)

	go ret.update(ctx)

	return ret, nil
}

func (c *tlsCert) update(ctx context.Context) {
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			newval, err := tls.LoadX509KeyPair(c.certFile, c.keyFile)
			if err != nil {
				log.Printf("failed to load certificate: %+v\n", err)
				return
			}
			c.cert.Store(&newval)

			log.Println("cert updated.")
		}
	}
}

func (c *tlsCert) getCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return c.cert.Load(), nil
}

func newServer(ctx context.Context) (*http.Server, func() error) {
	cfg := gConfig.Load()
	server := &http.Server{
		Addr:         cfg.Addr,
		Handler:      http.HandlerFunc(newDdbProxy(cfg)),
		ReadTimeout:  time.Duration(cfg.ReadTimeoutSec) * time.Second,
		WriteTimeout: time.Duration(cfg.WriteTimeoutSec) * time.Second,
		IdleTimeout:  time.Duration(cfg.IdleTimeoutSec) * time.Second,
	}
	serverRunFn := server.ListenAndServe
	if cfg.CertFile != "" || cfg.KeyFile != "" {
		tlsCert, err := newTlsCert(ctx, cfg.CertFile, cfg.KeyFile)
		if err != nil {
			log.Fatalf("%+v", err)
		}

		server.TLSConfig = &tls.Config{
			GetCertificate: tlsCert.getCertificate,
		}

		serverRunFn = func() error { return server.ListenAndServeTLS("", "") }
	}

	return server, serverRunFn
}

func debugRequest(cfg *config, r *http.Request) io.Reader {
	if !cfg.DebugRequest {
		return r.Body
	}

	btBody, err := io.ReadAll(r.Body)
	var bodyAsMap map[string]any
	if err == nil {
		dec := json.NewDecoder(bytes.NewReader(btBody))
		dec.UseNumber()
		if err := dec.Decode(&bodyAsMap); err != nil {
			bodyAsMap = map[string]any{"no-map": string(btBody)}
		} else {
			bodyAsMap = convNumerToValue(bodyAsMap).(map[string]any)
		}
	}
	debugInfo := map[string]any{
		"method":     r.Method,
		"url":        r.URL.String(),
		"header":     r.Header,
		"body":       bodyAsMap,
		"host":       r.Host,
		"remote":     r.RemoteAddr,
		"requestURI": r.RequestURI,
	}
	debugYaml, _ := yaml.Marshal(debugInfo)
	fmt.Println(string(debugYaml))

	return bytes.NewReader(btBody)
}
