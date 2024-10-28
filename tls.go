package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"sync/atomic"
	"time"
)

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
