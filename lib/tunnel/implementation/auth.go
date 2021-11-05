package implementation

import (
	"context"
	"net"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/tlsca"
	"github.com/gravitational/trace"
	"google.golang.org/grpc/credentials"
)

func newProxyCredentials(creds credentials.TransportCredentials) credentials.TransportCredentials {
	return &proxyCredentials{
		creds,
	}
}

// proxyCredentials wraps TransportCredentials server and client handshakes
// to ensure the credentials contain the proxy system role.
type proxyCredentials struct {
	credentials.TransportCredentials
}

func (c *proxyCredentials) ServerHandshake(conn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	conn, authInfo, err := c.TransportCredentials.ServerHandshake(conn)
	if err != nil {
		return conn, authInfo, err
	}

	err = checkProxyRole(authInfo)
	return conn, authInfo, trace.Wrap(err)
}

func (c *proxyCredentials) ClientHandshake(ctx context.Context, laddr string, conn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	conn, authInfo, err := c.TransportCredentials.ClientHandshake(ctx, laddr, conn)
	if err != nil {
		return conn, authInfo, err
	}

	err = checkProxyRole(authInfo)
	return conn, authInfo, trace.Wrap(err)
}

// hasProxyRole checks the context for a certificate with the role types.RoleProxy.
func checkProxyRole(authInfo credentials.AuthInfo) error {
	tlsInfo, ok := authInfo.(credentials.TLSInfo)
	if !ok {
		return trace.AccessDenied("missing authentication")
	}

	certs := tlsInfo.State.PeerCertificates
	if len(certs) == 0 {
		return trace.AccessDenied("missing authentication")
	}

	clientCert := certs[0]
	identity, err := tlsca.FromSubject(clientCert.Subject, clientCert.NotAfter)
	if err != nil {
		return trace.Wrap(err)
	}

	// Ensure the proxy system role is present.
	for _, role := range identity.Groups {
		if types.SystemRole(role) != types.RoleProxy {
			continue
		}
		return nil
	}

	return trace.AccessDenied("proxy system role required")
}
