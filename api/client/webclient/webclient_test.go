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

package webclient

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/gravitational/teleport/api/defaults"
)

func newPingHandler(path string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.RequestURI != path {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(PingResponse{ServerVersion: "test"})
	})
}

func TestPlainHttpFallback(t *testing.T) {
	testCases := []struct {
		desc            string
		handler         http.Handler
		actionUnderTest func(addr string, insecure bool) error
	}{
		{
			desc:    "Ping",
			handler: newPingHandler("/webapi/ping"),
			actionUnderTest: func(addr string, insecure bool) error {
				_, err := Ping(context.Background(), addr, insecure, nil /*pool*/, "")
				return err
			},
		}, {
			desc:    "Find",
			handler: newPingHandler("/webapi/find"),
			actionUnderTest: func(addr string, insecure bool) error {
				_, err := Find(context.Background(), addr, insecure, nil /*pool*/)
				return err
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.desc, func(t *testing.T) {
			t.Run("Allowed on insecure & loopback", func(t *testing.T) {
				httpSvr := httptest.NewServer(testCase.handler)
				defer httpSvr.Close()

				err := testCase.actionUnderTest(httpSvr.Listener.Addr().String(), true /* insecure */)
				require.NoError(t, err)
			})

			t.Run("Denied on secure", func(t *testing.T) {
				httpSvr := httptest.NewServer(testCase.handler)
				defer httpSvr.Close()

				err := testCase.actionUnderTest(httpSvr.Listener.Addr().String(), false /* secure */)
				require.Error(t, err)
			})

			t.Run("Denied on non-loopback", func(t *testing.T) {
				nonLoopbackSvr := httptest.NewUnstartedServer(testCase.handler)

				// replace the test-supplied loopback listener with the first available
				// non-loopback address
				nonLoopbackSvr.Listener.Close()
				l, err := net.Listen("tcp", "0.0.0.0:0")
				require.NoError(t, err)
				nonLoopbackSvr.Listener = l
				nonLoopbackSvr.Start()
				defer nonLoopbackSvr.Close()

				err = testCase.actionUnderTest(nonLoopbackSvr.Listener.Addr().String(), true /* insecure */)
				require.Error(t, err)
			})
		})
	}
}

func TestGetTunnelAddr(t *testing.T) {
	t.Setenv(defaults.TunnelPublicAddrEnvar, "tunnel.example.com:4024")
	tunnelAddr, err := GetTunnelAddr(context.Background(), "", true, nil)
	require.NoError(t, err)
	require.Equal(t, "tunnel.example.com:4024", tunnelAddr)
}

func TestTunnelAddr(t *testing.T) {
	type testCase struct {
		proxyAddr          string
		settings           ProxySettings
		expectedTunnelAddr string
	}

	testTunnelAddr := func(tc testCase) func(*testing.T) {
		return func(t *testing.T) {
			t.Parallel()
			tunnelAddr, err := tunnelAddr(tc.proxyAddr, tc.settings)
			require.NoError(t, err)
			require.Equal(t, tc.expectedTunnelAddr, tunnelAddr)
		}
	}

	t.Run("should use TunnelPublicAddr", testTunnelAddr(testCase{
		proxyAddr: "proxy.example.com",
		settings: ProxySettings{
			SSH: SSHProxySettings{
				TunnelPublicAddr: "tunnel.example.com:4024",
				PublicAddr:       "public.example.com",
				SSHPublicAddr:    "ssh.example.com",
				TunnelListenAddr: "[::]:5024",
			},
		},
		expectedTunnelAddr: "tunnel.example.com:4024",
	}))
	t.Run("should use SSHPublicAddr and TunnelListenAddr", testTunnelAddr(testCase{
		proxyAddr: "proxy.example.com",
		settings: ProxySettings{
			SSH: SSHProxySettings{
				SSHPublicAddr:    "ssh.example.com",
				PublicAddr:       "public.example.com",
				TunnelListenAddr: "[::]:5024",
			},
		},
		expectedTunnelAddr: "ssh.example.com:5024",
	}))
	t.Run("should use PublicAddr and TunnelListenAddr", testTunnelAddr(testCase{
		proxyAddr: "proxy.example.com",
		settings: ProxySettings{
			SSH: SSHProxySettings{
				PublicAddr:       "public.example.com",
				TunnelListenAddr: "[::]:5024",
			},
		},
		expectedTunnelAddr: "public.example.com:5024",
	}))
	t.Run("should use PublicAddr and SSHProxyTunnelListenPort", testTunnelAddr(testCase{
		proxyAddr: "proxy.example.com",
		settings: ProxySettings{
			SSH: SSHProxySettings{
				PublicAddr: "public.example.com",
			},
		},
		expectedTunnelAddr: "public.example.com:3024",
	}))
	t.Run("should use proxyAddr and SSHProxyTunnelListenPort", testTunnelAddr(testCase{
		proxyAddr:          "proxy.example.com",
		settings:           ProxySettings{SSH: SSHProxySettings{}},
		expectedTunnelAddr: "proxy.example.com:3024",
	}))
	t.Run("should use PublicAddr with ProxyWebPort if TLSRoutingEnabled was enabled", testTunnelAddr(testCase{
		proxyAddr: "proxy.example.com:443",
		settings: ProxySettings{
			SSH: SSHProxySettings{
				PublicAddr:       "public.example.com",
				TunnelListenAddr: "[::]:5024",
				TunnelPublicAddr: "tpa.example.com:3032",
			},
			TLSRoutingEnabled: true,
		},
		expectedTunnelAddr: "public.example.com:443",
	}))
	t.Run("should use PublicAddr with custom port if TLSRoutingEnabled was enabled", testTunnelAddr(testCase{
		proxyAddr: "proxy.example.com:443",
		settings: ProxySettings{
			SSH: SSHProxySettings{
				PublicAddr:       "public.example.com:443",
				TunnelListenAddr: "[::]:5024",
				TunnelPublicAddr: "tpa.example.com:3032",
			},
			TLSRoutingEnabled: true,
		},
		expectedTunnelAddr: "public.example.com:443",
	}))
	t.Run("should use proxyAddr with custom ProxyWebPort if TLSRoutingEnabled was enabled", testTunnelAddr(testCase{
		proxyAddr: "proxy.example.com:443",
		settings: ProxySettings{
			SSH: SSHProxySettings{
				TunnelListenAddr: "[::]:5024",
				TunnelPublicAddr: "tpa.example.com:3032",
			},
			TLSRoutingEnabled: true,
		},
		expectedTunnelAddr: "proxy.example.com:443",
	}))
	t.Run("should use proxyAddr with default https port if TLSRoutingEnabled was enabled", testTunnelAddr(testCase{
		proxyAddr: "proxy.example.com",
		settings: ProxySettings{
			SSH: SSHProxySettings{
				TunnelListenAddr: "[::]:5024",
				TunnelPublicAddr: "tpa.example.com:3032",
			},
			TLSRoutingEnabled: true,
		},
		expectedTunnelAddr: "proxy.example.com:443",
	}))
}

func TestExtract(t *testing.T) {
	testCases := []struct {
		addr     string
		hostPort string
		host     string
		port     string
	}{
		{
			addr:     "example.com",
			hostPort: "example.com",
			host:     "example.com",
			port:     "",
		}, {
			addr:     "example.com:443",
			hostPort: "example.com:443",
			host:     "example.com",
			port:     "443",
		}, {
			addr:     "http://example.com:443",
			hostPort: "example.com:443",
			host:     "example.com",
			port:     "443",
		}, {
			addr:     "https://example.com:443",
			hostPort: "example.com:443",
			host:     "example.com",
			port:     "443",
		}, {
			addr:     "tcp://example.com:443",
			hostPort: "example.com:443",
			host:     "example.com",
			port:     "443",
		}, {
			addr:     "file://host/path",
			hostPort: "",
			host:     "",
			port:     "",
		}, {
			addr:     "[::]:443",
			hostPort: "[::]:443",
			host:     "::",
			port:     "443",
		}, {
			addr:     "https://example.com:443/path?query=query#fragment",
			hostPort: "example.com:443",
			host:     "example.com",
			port:     "443",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.addr, func(t *testing.T) {
			hostPort, err := extractHostPort(tc.addr)
			// Expect err if expected value is empty
			require.True(t, (tc.hostPort == "") == (err != nil))
			require.Equal(t, tc.hostPort, hostPort)

			host, err := extractHost(tc.addr)
			// Expect err if expected value is empty
			require.True(t, (tc.host == "") == (err != nil))
			require.Equal(t, tc.host, host)

			port, err := extractPort(tc.addr)
			// Expect err if expected value is empty
			require.True(t, (tc.port == "") == (err != nil))
			require.Equal(t, tc.port, port)
		})
	}
}
