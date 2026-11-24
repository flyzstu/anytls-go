package main

import (
	"crypto/tls"
	"time"
)

type myServer struct {
	tlsConfig *tls.Config

	heartbeatInterval time.Duration
	heartbeatTimeout  time.Duration
}

func NewMyServer(tlsConfig *tls.Config, heartbeatInterval, heartbeatTimeout time.Duration) *myServer {
	s := &myServer{
		tlsConfig:         tlsConfig,
		heartbeatInterval: heartbeatInterval,
		heartbeatTimeout:  heartbeatTimeout,
	}
	return s
}
