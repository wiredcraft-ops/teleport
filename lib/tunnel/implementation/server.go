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

package implementation

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strings"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/reversetunnel"
	"github.com/gravitational/teleport/lib/tunnel"
	"github.com/gravitational/teleport/lib/tunnel/api"
	"github.com/gravitational/teleport/lib/utils"

	"github.com/gravitational/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// Server is a tunnel server implementation of api.Server
// This might be moved to teleport/e or somewhere else private
type Server struct {
	listener net.Listener
	server   *grpc.Server
}

// NewServerImpl initializes a tunnel service grpc server
func NewServer(listener net.Listener, reverse reversetunnel.Server, tlsConfig *tls.Config) error {
	service := &tunnelerService{
		reverse: reverse,
	}

	// TODO (david) patching the client auth and client CAs
	// should only impact server side use of the TLS config
	// but need to double check this doesn't impact the use
	// of the config in other parts of the code.
	tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	tlsConfig.ClientCAs = tlsConfig.RootCAs

	creds := newProxyCredentials(credentials.NewTLS(tlsConfig))
	server := grpc.NewServer(grpc.Creds(creds))

	api.RegisterTunnelerServiceServer(server, service)

	s := Server{
		listener: listener,
		server:   server,
	}

	tunnel.SetServer(&s)

	return nil
}

// Serve starts the grpc server
func (s *Server) Start() error {
	if err := s.server.Serve(s.listener); err != nil {
		return trace.Wrap(err)
	}
	return nil
}

// Stop stops the grpc server
func (s *Server) Stop() {
	s.server.GracefulStop()
	s.listener.Close()
}

// Addr returns the address the server is listening on.
func (s *Server) Addr() net.Addr {
	return s.listener.Addr()
}

type tunnelerService struct {
	api.UnimplementedTunnelerServiceServer
	reverse reversetunnel.Server
}

func (s *tunnelerService) Tunnel(stream api.TunnelerService_TunnelServer) error {
	frame, err := stream.Recv()
	if err != nil {
		return trace.Wrap(err)
	}

	dial := frame.GetDialRequest()
	if dial == nil {
		return trace.Errorf("invalid dial request")
	}

	_, clusterName, err := splitServerID(dial.ServerID)
	if err != nil {
		return trace.Wrap(err)
	}

	site, err := s.reverse.GetSite(clusterName)
	if err != nil {
		fmt.Println(err)
		return trace.Wrap(err)
	}

	conn, err := site.Dial(
		reversetunnel.DialParams{
			To: &utils.NetAddr{
				Addr:        dial.To.Address,
				AddrNetwork: dial.To.Network,
			},
			ServerID:             dial.ServerID,
			ConnType:             types.TunnelType(dial.ConnType),
			IgnoreProxyRecording: true,
		},
	)
	if err != nil {
		return trace.Wrap(err)
	}

	tunnelConn := tunnel.NewConn(stream)
	go tunnelConn.Start()

	go io.Copy(tunnelConn, conn)
	go io.Copy(conn, tunnelConn)

	<-stream.Context().Done()
	return nil
}

// splitServerID splits a server id in to a node id and cluster name.
func splitServerID(address string) (string, string, error) {
	split := strings.Split(address, ".")
	if len(split) != 2 {
		return "", "", trace.Errorf("invalid server ID.")
	}

	return split[0], split[1], nil
}
