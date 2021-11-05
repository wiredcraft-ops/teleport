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
	"context"
	"crypto/tls"
	"net"

	alpncommon "github.com/gravitational/teleport/lib/srv/alpnproxy/common"
	"github.com/gravitational/teleport/lib/tunnel"
	"github.com/gravitational/teleport/lib/tunnel/api"

	"github.com/gravitational/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// Client is a tunnel client implementation of api.Client
// This might be moved to teleport/e or somewhere else private
type Client struct {
	tlsConfig *tls.Config
}

func NewClient(tlsConfig *tls.Config) error {
	c := Client{
		tlsConfig: tlsConfig,
	}
	tunnel.SetClient(&c)
	return nil
}

func (c *Client) DialContext(
	ctx context.Context,
	proxyAddr string,
	toAddr net.Addr,
	serverID string,
	connType string,
) (net.Conn, error) {
	// TODO (david) Check if the tlsConfig is used anywhere else.
	// we may need to create a deep copy before we modify it.
	c.tlsConfig.NextProtos = alpncommon.ProtocolsToString([]alpncommon.Protocol{alpncommon.ProtocolProxy2Proxy})

	creds := newProxyCredentials(credentials.NewTLS(c.tlsConfig))
	grpcConn, err := grpc.Dial(proxyAddr, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, trace.Wrap(err)
	}

	client := api.NewTunnelerServiceClient(grpcConn)

	stream, err := client.Tunnel(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	err = stream.Send(&api.Frame{
		Message: &api.Frame_DialRequest{
			DialRequest: &api.DialRequest{
				ServerID: serverID,
				ConnType: connType,
				To: &api.Addr{
					Address: toAddr.String(),
					Network: toAddr.Network(),
				},
			},
		},
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	conn := tunnel.NewConn(stream)
	go conn.Start()
	return conn, nil
}
