/*
Copyright 2015 Gravitational, Inc.

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
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"golang.org/x/crypto/ssh"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/backend/memory"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/reversetunnel"
	"github.com/gravitational/teleport/lib/utils"

	"github.com/gravitational/trace"

	"github.com/jonboulle/clockwork"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	utils.InitLoggerForTests()
	os.Exit(m.Run())
}

func TestServiceDebugModeEnv(t *testing.T) {
	require.False(t, isDebugMode())

	for _, test := range []struct {
		debugVal string
		isDebug  bool
	}{
		{"no", false},
		{"0", false},
		{"1", true},
		{"true", true},
	} {
		t.Run(fmt.Sprintf("%v=%v", teleport.DebugEnvVar, test.debugVal), func(t *testing.T) {
			t.Setenv(teleport.DebugEnvVar, test.debugVal)
			require.Equal(t, test.isDebug, isDebugMode())
		})
	}
}

func TestServiceSelfSignedHTTPS(t *testing.T) {
	cfg := &Config{
		DataDir:  t.TempDir(),
		Hostname: "example.com",
		Log:      utils.WrapLogger(logrus.New().WithField("test", "TestServiceSelfSignedHTTPS")),
	}
	require.NoError(t, initSelfSignedHTTPSCert(cfg))
	require.Len(t, cfg.Proxy.KeyPairs, 1)
	require.FileExists(t, cfg.Proxy.KeyPairs[0].Certificate)
	require.FileExists(t, cfg.Proxy.KeyPairs[0].PrivateKey)
}

func TestMonitor(t *testing.T) {
	t.Parallel()
	fakeClock := clockwork.NewFakeClock()

	cfg := MakeDefaultConfig()
	cfg.Clock = fakeClock
	var err error
	cfg.DataDir, err = ioutil.TempDir("", "teleport")
	require.NoError(t, err)
	defer os.RemoveAll(cfg.DataDir)
	cfg.DiagnosticAddr = utils.NetAddr{AddrNetwork: "tcp", Addr: "127.0.0.1:0"}
	cfg.AuthServers = []utils.NetAddr{{AddrNetwork: "tcp", Addr: "127.0.0.1:0"}}
	cfg.Auth.Enabled = true
	cfg.Auth.StorageConfig.Params["path"], err = ioutil.TempDir("", "teleport")
	require.NoError(t, err)
	defer os.RemoveAll(cfg.DataDir)
	cfg.Auth.SSHAddr = utils.NetAddr{AddrNetwork: "tcp", Addr: "127.0.0.1:0"}
	cfg.Proxy.Enabled = false
	cfg.SSH.Enabled = false

	process, err := NewTeleport(cfg)
	require.NoError(t, err)

	diagAddr, err := process.DiagnosticAddr()
	require.NoError(t, err)
	require.NotNil(t, diagAddr)
	endpoint := fmt.Sprintf("http://%v/readyz", diagAddr.String())

	// Start Teleport and make sure the status is OK.
	go func() {
		require.NoError(t, process.Run())
	}()
	err = waitForStatus(endpoint, http.StatusOK)
	require.NoError(t, err)

	tests := []struct {
		desc         string
		event        Event
		advanceClock time.Duration
		wantStatus   []int
	}{
		{
			desc:       "degraded event causes degraded state",
			event:      Event{Name: TeleportDegradedEvent, Payload: teleport.ComponentAuth},
			wantStatus: []int{http.StatusServiceUnavailable, http.StatusBadRequest},
		},
		{
			desc:       "ok event causes recovering state",
			event:      Event{Name: TeleportOKEvent, Payload: teleport.ComponentAuth},
			wantStatus: []int{http.StatusBadRequest},
		},
		{
			desc:       "ok event remains in recovering state because not enough time passed",
			event:      Event{Name: TeleportOKEvent, Payload: teleport.ComponentAuth},
			wantStatus: []int{http.StatusBadRequest},
		},
		{
			desc:         "ok event after enough time causes OK state",
			event:        Event{Name: TeleportOKEvent, Payload: teleport.ComponentAuth},
			advanceClock: defaults.HeartbeatCheckPeriod*2 + 1,
			wantStatus:   []int{http.StatusOK},
		},
		{
			desc:       "degraded event in a new component causes degraded state",
			event:      Event{Name: TeleportDegradedEvent, Payload: teleport.ComponentNode},
			wantStatus: []int{http.StatusServiceUnavailable, http.StatusBadRequest},
		},
		{
			desc:         "ok event in one component keeps overall status degraded due to other component",
			advanceClock: defaults.HeartbeatCheckPeriod*2 + 1,
			event:        Event{Name: TeleportOKEvent, Payload: teleport.ComponentAuth},
			wantStatus:   []int{http.StatusServiceUnavailable, http.StatusBadRequest},
		},
		{
			desc:         "ok event in new component causes overall recovering state",
			advanceClock: defaults.HeartbeatCheckPeriod*2 + 1,
			event:        Event{Name: TeleportOKEvent, Payload: teleport.ComponentNode},
			wantStatus:   []int{http.StatusBadRequest},
		},
		{
			desc:         "ok event in new component causes overall OK state",
			advanceClock: defaults.HeartbeatCheckPeriod*2 + 1,
			event:        Event{Name: TeleportOKEvent, Payload: teleport.ComponentNode},
			wantStatus:   []int{http.StatusOK},
		},
	}
	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			fakeClock.Advance(tt.advanceClock)
			process.BroadcastEvent(tt.event)
			err = waitForStatus(endpoint, tt.wantStatus...)
			require.NoError(t, err)
		})
	}
}

// TestServiceCheckPrincipals checks certificates regeneration only requests
// regeneration when the principals change.
func TestServiceCheckPrincipals(t *testing.T) {
	// Create a test auth server to extract the server identity (SSH and TLS
	// certificates).
	testAuthServer, err := auth.NewTestAuthServer(auth.TestAuthServerConfig{
		Dir: t.TempDir(),
	})
	require.NoError(t, err)
	tlsServer, err := testAuthServer.NewTestTLSServer()
	require.NoError(t, err)
	defer tlsServer.Close()

	testConnector := &Connector{
		ServerIdentity: tlsServer.Identity,
	}

	var tests = []struct {
		inPrincipals  []string
		inDNS         []string
		outRegenerate bool
	}{
		// If nothing has been updated, don't regenerate certificate.
		{
			inPrincipals:  []string{},
			inDNS:         []string{},
			outRegenerate: false,
		},
		// Don't regenerate certificate if the node does not know it's own address.
		{
			inPrincipals:  []string{"0.0.0.0"},
			inDNS:         []string{},
			outRegenerate: false,
		},
		// If a new SSH principal is found, regenerate certificate.
		{
			inPrincipals:  []string{"1.1.1.1"},
			inDNS:         []string{},
			outRegenerate: true,
		},
		// If a new TLS DNS name is found, regenerate certificate.
		{
			inPrincipals:  []string{},
			inDNS:         []string{"server.example.com"},
			outRegenerate: true,
		},
		// Don't regenerate certificate if additional principals is already on the
		// certificate.
		{
			inPrincipals:  []string{"test-tls-server"},
			inDNS:         []string{},
			outRegenerate: false,
		},
	}
	for i, tt := range tests {
		ok := checkServerIdentity(testConnector, tt.inPrincipals, tt.inDNS, logrus.New().WithField("test", "TestServiceCheckPrincipals"))
		require.Equal(t, tt.outRegenerate, ok, "test %d", i)
	}
}

// TestServiceInitExternalLog verifies that external logging can be used both as a means of
// overriding the local audit event target.  Ideally, this test would also verify
// setup of true external loggers, but at the time of writing there isn't good
// support for setting up fake external logging endpoints.
func TestServiceInitExternalLog(t *testing.T) {
	tts := []struct {
		events []string
		isNil  bool
		isErr  bool
	}{
		// no URIs => no external logger
		{isNil: true},
		// local-only event uri w/o hostname => ok
		{events: []string{"file:///tmp/teleport-test/events"}},
		// local-only event uri w/ localhost => ok
		{events: []string{"file://localhost/tmp/teleport-test/events"}},
		// invalid host parameter => rejected
		{events: []string{"file://example.com/should/fail"}, isErr: true},
		// missing path specifier => rejected
		{events: []string{"file://localhost"}, isErr: true},
	}

	backend, err := memory.New(memory.Config{})
	require.NoError(t, err)

	for _, tt := range tts {
		t.Run(strings.Join(tt.events, ","), func(t *testing.T) {
			// isErr implies isNil.
			if tt.isErr {
				tt.isNil = true
			}

			auditConfig, err := types.NewClusterAuditConfig(types.ClusterAuditConfigSpecV2{
				AuditEventsURI: tt.events,
			})
			require.NoError(t, err)

			loggers, err := initExternalLog(context.Background(), auditConfig, logrus.New(), backend)
			if tt.isErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			if tt.isNil {
				require.Nil(t, loggers)
			} else {
				require.NotNil(t, loggers)
			}
		})
	}
}

func TestGetAdditionalPrincipals(t *testing.T) {
	p := &TeleportProcess{
		Config: &Config{
			Hostname:    "global-hostname",
			HostUUID:    "global-uuid",
			AdvertiseIP: "1.2.3.4",
			Proxy: ProxyConfig{
				PublicAddrs:         utils.MustParseAddrList("proxy-public-1", "proxy-public-2"),
				SSHPublicAddrs:      utils.MustParseAddrList("proxy-ssh-public-1", "proxy-ssh-public-2"),
				TunnelPublicAddrs:   utils.MustParseAddrList("proxy-tunnel-public-1", "proxy-tunnel-public-2"),
				PostgresPublicAddrs: utils.MustParseAddrList("proxy-postgres-public-1", "proxy-postgres-public-2"),
				MySQLPublicAddrs:    utils.MustParseAddrList("proxy-mysql-public-1", "proxy-mysql-public-2"),
				Kube: KubeProxyConfig{
					Enabled:     true,
					PublicAddrs: utils.MustParseAddrList("proxy-kube-public-1", "proxy-kube-public-2"),
				},
				WebAddr: *utils.MustParseAddr(":443"),
			},
			Auth: AuthConfig{
				PublicAddrs: utils.MustParseAddrList("auth-public-1", "auth-public-2"),
			},
			SSH: SSHConfig{
				PublicAddrs: utils.MustParseAddrList("node-public-1", "node-public-2"),
			},
			Kube: KubeConfig{
				PublicAddrs: utils.MustParseAddrList("kube-public-1", "kube-public-2"),
			},
		},
	}
	tests := []struct {
		role           types.SystemRole
		wantPrincipals []string
		wantDNS        []string
	}{
		{
			role: types.RoleProxy,
			wantPrincipals: []string{
				"global-hostname",
				"proxy-public-1",
				"proxy-public-2",
				defaults.BindIP,
				string(teleport.PrincipalLocalhost),
				string(teleport.PrincipalLoopbackV4),
				string(teleport.PrincipalLoopbackV6),
				reversetunnel.LocalKubernetes,
				"proxy-ssh-public-1",
				"proxy-ssh-public-2",
				"proxy-tunnel-public-1",
				"proxy-tunnel-public-2",
				"proxy-postgres-public-1",
				"proxy-postgres-public-2",
				"proxy-mysql-public-1",
				"proxy-mysql-public-2",
				"proxy-kube-public-1",
				"proxy-kube-public-2",
			},
			wantDNS: []string{
				"*.proxy-public-1",
				"*.proxy-public-2",
				"*.proxy-kube-public-1",
				"*.proxy-kube-public-2",
			},
		},
		{
			role: types.RoleAuth,
			wantPrincipals: []string{
				"global-hostname",
				"auth-public-1",
				"auth-public-2",
			},
			wantDNS: []string{},
		},
		{
			role: types.RoleAdmin,
			wantPrincipals: []string{
				"global-hostname",
				"auth-public-1",
				"auth-public-2",
			},
			wantDNS: []string{},
		},
		{
			role: types.RoleNode,
			wantPrincipals: []string{
				"global-hostname",
				"global-uuid",
				"node-public-1",
				"node-public-2",
				"1.2.3.4",
			},
			wantDNS: []string{},
		},
		{
			role: types.RoleKube,
			wantPrincipals: []string{
				"global-hostname",
				string(teleport.PrincipalLocalhost),
				string(teleport.PrincipalLoopbackV4),
				string(teleport.PrincipalLoopbackV6),
				reversetunnel.LocalKubernetes,
				"kube-public-1",
				"kube-public-2",
			},
			wantDNS: []string{},
		},
		{
			role: types.RoleApp,
			wantPrincipals: []string{
				"global-hostname",
				"global-uuid",
			},
			wantDNS: []string{},
		},
		{
			role: types.SystemRole("unknown"),
			wantPrincipals: []string{
				"global-hostname",
			},
			wantDNS: []string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.role.String(), func(t *testing.T) {
			principals, dns, err := p.getAdditionalPrincipals(tt.role)
			require.NoError(t, err)
			require.Empty(t, cmp.Diff(principals, tt.wantPrincipals))
			require.Empty(t, cmp.Diff(dns, tt.wantDNS, cmpopts.EquateEmpty()))
		})
	}
}

// TestDesktopAccessFIPS makes sure that Desktop Access can not be started in
// FIPS mode. Remove this test once Rust code has been updated to use
// BoringCrypto instead of OpenSSL.
func TestDesktopAccessFIPS(t *testing.T) {
	t.Parallel()

	// Create and configure a default Teleport configuration.
	cfg := MakeDefaultConfig()
	cfg.AuthServers = []utils.NetAddr{{AddrNetwork: "tcp", Addr: "127.0.0.1:0"}}
	cfg.Clock = clockwork.NewFakeClock()
	cfg.DataDir = t.TempDir()
	cfg.Auth.Enabled = false
	cfg.Proxy.Enabled = false
	cfg.SSH.Enabled = false

	// Enable FIPS mode and Desktop Access, this should fail.
	cfg.FIPS = true
	cfg.WindowsDesktop.Enabled = true
	_, err := NewTeleport(cfg)
	require.Error(t, err)
}

func waitForStatus(diagAddr string, statusCodes ...int) error {
	tickCh := time.Tick(100 * time.Millisecond)
	timeoutCh := time.After(10 * time.Second)
	var lastStatus int
	for {
		select {
		case <-tickCh:
			resp, err := http.Get(diagAddr)
			if err != nil {
				return trace.Wrap(err)
			}
			resp.Body.Close()
			lastStatus = resp.StatusCode
			for _, statusCode := range statusCodes {
				if resp.StatusCode == statusCode {
					return nil
				}
			}
		case <-timeoutCh:
			return trace.BadParameter("timeout waiting for status: %v; last status: %v", statusCodes, lastStatus)
		}
	}
}

type mockAccessPoint struct {
	auth.ProxyAccessPoint
}

type mockReverseTunnelServer struct {
	reversetunnel.Server
}

func TestSetupProxyTLSConfig(t *testing.T) {
	testCases := []struct {
		name           string
		acmeEnabled    bool
		wantNextProtos []string
	}{
		{
			name:        "ACME enabled, teleport ALPN protocols should be appended",
			acmeEnabled: true,
			wantNextProtos: []string{
				"h2",
				"http/1.1",
				"acme-tls/1",
				"teleport-postgres",
				"teleport-mysql",
				"teleport-mongodb",
				"teleport-proxy-ssh",
				"teleport-reversetunnel",
				"teleport-auth@",
			},
		},
		{
			name:        "ACME disabled",
			acmeEnabled: false,
			// If server NextProtos list is empty server allows for connection with any protocol.
			wantNextProtos: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := MakeDefaultConfig()
			cfg.Proxy.ACME.Enabled = tc.acmeEnabled
			cfg.DataDir = t.TempDir()
			cfg.Proxy.PublicAddrs = utils.MustParseAddrList("localhost")
			process := TeleportProcess{
				Config: cfg,
			}
			conn := &Connector{
				ServerIdentity: &auth.Identity{
					Cert: &ssh.Certificate{
						Permissions: ssh.Permissions{
							Extensions: map[string]string{},
						},
					},
				},
			}
			tls, err := process.setupProxyTLSConfig(
				conn,
				&mockReverseTunnelServer{},
				&mockAccessPoint{},
				"cluster",
			)
			require.NoError(t, err)
			require.Equal(t, tc.wantNextProtos, tls.NextProtos)
		})
	}
}
