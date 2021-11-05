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

package tunnel

import (
	"net"
	"sync"

	"github.com/gravitational/teleport/lib/tunnel/api"
)

var (
	sm     sync.RWMutex
	server api.Server = &noopServer{}
)

// SetServer sets the tunnel server interface
func SetServer(s api.Server) {
	sm.Lock()
	defer sm.Unlock()
	server = s
}

// GetServer returns the tunnel server interface
func GetServer() api.Server {
	sm.RLock()
	defer sm.RUnlock()
	return server
}

// noopServer is a no-op tunnel server that does nothing
type noopServer struct{}

// Serve does nothing
func (s *noopServer) Start() error { return nil }

// Stop does nothing
func (s *noopServer) Stop() {}

// Addr does nothing
func (s *noopServer) Addr() net.Addr { return nil }
