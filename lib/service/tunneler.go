/*
Copyright 2021 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package service

import (
	"crypto/tls"
	"net"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/lib/reversetunnel"
	"github.com/gravitational/teleport/lib/tunnel"

	nodetrackerimpl "github.com/gravitational/teleport/lib/nodetracker/implementation"
	tunnelerimpl "github.com/gravitational/teleport/lib/tunnel/implementation"

	"github.com/gravitational/trace"
	"github.com/sirupsen/logrus"
)

// initProxy2Proxy setups a proxy to proxy client and server.
// This is enabled if the node tracking feature is enabled and
// a node tracker address was provided.
func (process *TeleportProcess) initProxy2Proxy(listener net.Listener, tsrv reversetunnel.Server, tlsConfig *tls.Config) {
	process.RegisterCriticalFunc("proxy2proxy.init", func() error {
		return trace.Wrap(process.initProxy2ProxyService(listener, tsrv, tlsConfig))
	})
}

func (process *TeleportProcess) initProxy2ProxyService(listener net.Listener, tsrv reversetunnel.Server, tlsConfig *tls.Config) error {
	log := process.log.WithFields(logrus.Fields{
		trace.Component: teleport.Component(teleport.ComponentProxy, process.id),
	})

	if !process.proxy2proxyEnabled() {
		log.Info("this Teleport cluster is not licensed for node tracker service access, please contact the cluster administrator")
		return nil
	}

	if err := nodetrackerimpl.NewClient(process.Config.Proxy.NodeTrackerAddr.String()); err != nil {
		return trace.Wrap(err)
	}

	err := tunnelerimpl.NewServer(listener, tsrv, tlsConfig) // this should ultimately be initialized somewhere else
	if err != nil {
		return trace.Wrap(err)
	}

	err = tunnelerimpl.NewClient(tlsConfig)
	if err != nil {
		return trace.Wrap(err)
	}

	process.RegisterCriticalFunc("proxy2proxy.service", func() error {
		log.Infof("Starting proxy2proxy service on %v.", listener.Addr().String())
		if err := tunnel.GetServer().Start(); err != nil {
			return trace.Wrap(err)
		}
		return nil
	})

	process.OnExit("proxy2proxy.shutdown", func(payload interface{}) {
		log.Infof("Shutting down gracefully.")
		tunnel.GetServer().Stop()
		if listener != nil {
			listener.Close()
		}
		log.Infof("Exited.")
	})

	return nil
}
