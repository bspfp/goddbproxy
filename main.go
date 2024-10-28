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
