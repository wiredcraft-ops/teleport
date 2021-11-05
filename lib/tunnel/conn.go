package tunnel

import (
	"context"
	"net"
	"time"

	"github.com/gravitational/teleport/lib/tunnel/api"

	"github.com/gravitational/trace"
	"google.golang.org/grpc"
)

// stream is a common interface for client and server streams.
type Stream interface {
	Context() context.Context
	Send(*api.Frame) error
	Recv() (*api.Frame, error)
}

type Conn struct {
	ctx    context.Context
	cancel func()

	local  net.Conn
	remote net.Conn

	tunnel Stream
}

func (c *Conn) String() string {
	return ""
}

func NewConn(tunnel Stream) *Conn {
	ctx, cancel := context.WithCancel(tunnel.Context())
	local, remote := net.Pipe()

	return &Conn{
		ctx:    ctx,
		cancel: cancel,
		tunnel: tunnel,
		local:  local,
		remote: remote,
	}
}

func (c *Conn) Start() {
	errCh := make(chan error)

	go func() {
		errCh <- c.receive()
	}()
	go func() {
		errCh <- c.send()
	}()

	<-errCh
	c.Close()
}

func (c *Conn) receive() error {
	var (
		frame *api.Frame
		err   error
	)

	for err == nil {
		frame, err = c.tunnel.Recv()
		data := frame.GetData()
		if data == nil {
			break
		}

		_, err := c.remote.Write(data.Bytes)
		if err != nil {
			break
		}

		frame = nil
	}

	return trace.Wrap(err)
}

func (c *Conn) send() error {
	var (
		frame *api.Frame
		n     int
		err   error
	)
	b := make([]byte, 1024)

	for err == nil {
		n, err = c.remote.Read(b)
		if err != nil {
			break
		}

		frame = &api.Frame{Message: &api.Frame_Data{Data: &api.Data{Bytes: b[:n]}}}
		err = c.tunnel.Send(frame)
	}

	return trace.Wrap(err)
}

func (c *Conn) Read(b []byte) (n int, err error) {
	return c.local.Read(b)
}

func (c *Conn) Write(b []byte) (n int, err error) {
	return c.local.Write(b)
}

func (c *Conn) Close() error {
	defer c.cancel()
	defer c.local.Close()
	defer c.remote.Close()

	if client, ok := c.tunnel.(grpc.ClientStream); ok {
		return client.CloseSend()
	}

	return nil
}

func (c *Conn) LocalAddr() net.Addr {
	return nil
}

func (c *Conn) RemoteAddr() net.Addr {
	return nil
}

func (c *Conn) SetDeadline(t time.Time) error {
	return c.local.SetDeadline(t)
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.local.SetReadDeadline(t)
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.local.SetWriteDeadline(t)
}
