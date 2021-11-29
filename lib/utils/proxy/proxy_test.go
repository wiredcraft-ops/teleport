/*
Copyright 2017 Gravitational, Inc.

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

package proxy

import (
	"fmt"
	"os"
	"testing"

	"github.com/gravitational/teleport/lib/utils"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	utils.InitLoggerForTests()
	os.Exit(m.Run())
}

func TestGetProxyAddress(t *testing.T) {
	type env struct {
		name string
		val  string
	}
	var tests = []struct {
		info       string
		env        []env
		targetAddr string
		proxyAddr  string
	}{
		{
			info:       "valid, can be raw host:port",
			env:        []env{{name: "http_proxy", val: "proxy:1234"}},
			proxyAddr:  "proxy:1234",
			targetAddr: "192.168.1.1:3030",
		},
		{
			info:       "valid, raw host:port works for https",
			env:        []env{{name: "HTTPS_PROXY", val: "proxy:1234"}},
			proxyAddr:  "proxy:1234",
			targetAddr: "192.168.1.1:3030",
		},
		{
			info:       "valid, correct full url",
			env:        []env{{name: "https_proxy", val: "https://proxy:1234"}},
			proxyAddr:  "proxy:1234",
			targetAddr: "192.168.1.1:3030",
		},
		{
			info:       "valid, http endpoint can be set in https_proxy",
			env:        []env{{name: "https_proxy", val: "http://proxy:1234"}},
			proxyAddr:  "proxy:1234",
			targetAddr: "192.168.1.1:3030",
		},
		{
			info: "valid, http endpoint can be set in https_proxy, but no_proxy override matches domain",
			env: []env{
				{name: "https_proxy", val: "http://proxy:1234"},
				{name: "no_proxy", val: "proxy"}},
			proxyAddr:  "",
			targetAddr: "proxy:1234",
		},
		{
			info: "valid, http endpoint can be set in https_proxy, but no_proxy override matches ip",
			env: []env{
				{name: "https_proxy", val: "http://proxy:1234"},
				{name: "no_proxy", val: "192.168.1.1"}},
			proxyAddr:  "",
			targetAddr: "192.168.1.1:1234",
		},
		{
			info: "valid, http endpoint can be set in https_proxy, but no_proxy override matches subdomain",
			env: []env{
				{name: "https_proxy", val: "http://proxy:1234"},
				{name: "no_proxy", val: ".example.com"}},
			proxyAddr:  "",
			targetAddr: "bla.example.com:1234",
		},
	}

	for i, tt := range tests {
		t.Run(fmt.Sprintf("%v: %v", i, tt.info), func(t *testing.T) {
			for _, env := range tt.env {
				t.Setenv(env.name, env.val)
			}
			p := getProxyAddress(tt.targetAddr)
			require.Equal(t, tt.proxyAddr, p)
		})
	}
}
