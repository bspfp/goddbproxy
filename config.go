package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync/atomic"
	"time"

	"gopkg.in/yaml.v3"
)

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
