package tunnel

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"git.sequentialread.com/forest/threshold/tunnel-lib/proto"

	"github.com/cenkalti/backoff"
)

// async is a helper function to convert a blocking function to a function
// returning an error. Useful for plugging function closures into select and co
func async(fn func() error) <-chan error {
	errChan := make(chan error, 0)
	go func() {
		select {
		case errChan <- fn():
		default:
		}

		close(errChan)
	}()

	return errChan
}

type expBackoff struct {
	mu sync.Mutex
	bk *backoff.ExponentialBackOff
}

func NewExponentialBackoff() *expBackoff {
	eb := &expBackoff{
		bk: backoff.NewExponentialBackOff(),
	}
	eb.bk.MaxElapsedTime = 0 // never stops
	return eb
}

func (eb *expBackoff) NextBackOff() time.Duration {
	eb.mu.Lock()
	defer eb.mu.Unlock()

	return eb.bk.NextBackOff()
}

func (eb *expBackoff) Reset() {
	eb.mu.Lock()
	eb.bk.Reset()
	eb.mu.Unlock()
}

type callbacks struct {
	mu    sync.Mutex
	name  string
	funcs map[string]func() error
}

func newCallbacks(name string) *callbacks {
	return &callbacks{
		name:  name,
		funcs: make(map[string]func() error),
	}
}

func (c *callbacks) add(identifier string, fn func() error) {
	c.mu.Lock()
	c.funcs[identifier] = fn
	c.mu.Unlock()
}

func (c *callbacks) pop(identifier string) (func() error, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	fn, ok := c.funcs[identifier]
	if !ok {
		return nil, nil // nop
	}

	delete(c.funcs, identifier)

	if fn == nil {
		return nil, fmt.Errorf("nil callback set for %q client", identifier)
	}

	return fn, nil
}

func (c *callbacks) call(identifier string) error {
	fn, err := c.pop(identifier)
	if err != nil {
		return err
	}

	if fn == nil {
		return nil // nop
	}

	return fn()
}

// Returns server control url as a string. Reads scheme and remote address from connection.
func controlURL(conn net.Conn) string {
	return fmt.Sprint(scheme(conn), "://", conn.RemoteAddr(), proto.ControlPath)
}

func scheme(conn net.Conn) (scheme string) {
	switch conn.(type) {
	case *tls.Conn:
		scheme = "https"
	default:
		scheme = "http"
	}

	return
}

func blockingBidirectionalPipe(conn1, conn2 net.Conn, name1, name2 string, connectionId string, debugLog bool) {
	chanFromConn := func(conn net.Conn, name, connectionId string) chan []byte {
		c := make(chan []byte)

		go func() {
			b := make([]byte, 1024)

			for {
				n, err := conn.Read(b)
				if n > 0 {
					res := make([]byte, n)
					// Copy the buffer so it doesn't get changed while read by the recipient.
					copy(res, b[:n])
					c <- res
				}
				if err != nil {
					log.Printf("%s %s read error %s\n", connectionId, name, err)
					c <- nil
					break
				}
			}
		}()

		return c
	}

	chan1 := chanFromConn(conn1, fmt.Sprint(name1, "->", name2), connectionId)
	chan2 := chanFromConn(conn2, fmt.Sprint(name2, "->", name1), connectionId)

	for {
		select {
		case b1 := <-chan1:
			if b1 == nil {
				if debugLog {
					log.Printf("connection %s %s EOF\n", connectionId, name1)
				}
				return
			} else {
				conn2.Write(b1)
			}
		case b2 := <-chan2:
			if b2 == nil {
				if debugLog {
					log.Printf("connection %s %s EOF\n", connectionId, name2)
				}
				return
			} else {
				conn1.Write(b2)
			}
		}
	}
}

// copied from the go standard library source code (io.Copy) with metric collection added.
func ioCopyWithMetrics(dst io.Writer, src io.Reader, metric BandwidthMetric, bandwidth chan<- BandwidthMetric) (written int64, err error) {
	size := 32 * 1024
	if l, ok := src.(*io.LimitedReader); ok && int64(size) > l.N {
		if l.N < 1 {
			size = 1
		} else {
			size = int(l.N)
		}
	}
	chunkForMetrics := 0
	buf := make([]byte, size)

	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			nw, ew := dst.Write(buf[0:nr])
			if nw > 0 {
				chunkForMetrics += nw
				if chunkForMetrics >= metricChunkSize {
					bandwidth <- BandwidthMetric{
						Inbound:       metric.Inbound,
						Service:       metric.Service,
						ClientId:      metric.ClientId,
						RemoteAddress: metric.RemoteAddress,
						Bytes:         chunkForMetrics,
					}
					chunkForMetrics = 0
				}
				written += int64(nw)
			}
			if ew != nil {
				err = ew
				break
			}
			if nr != nw {
				err = io.ErrShortWrite
				break
			}
		}
		if er != nil {
			if er != io.EOF {
				err = er
			}
			break
		}
	}
	if chunkForMetrics > 0 {
		bandwidth <- BandwidthMetric{
			Inbound:       metric.Inbound,
			Service:       metric.Service,
			ClientId:      metric.ClientId,
			RemoteAddress: metric.RemoteAddress,
			Bytes:         chunkForMetrics,
		}
	}
	return written, err
}

type ConnWithMetrics struct {
	underlying     net.Conn
	metricsChannel chan<- BandwidthMetric
	inbound        bool
	service        string
	clientId       string
	inboundBytes   int
	outboundBytes  int
	remoteAddress  net.Addr
}

func (conn ConnWithMetrics) Read(b []byte) (n int, err error) {
	n, err = conn.underlying.Read(b)
	conn.Accumulate(conn.inbound, n)
	return n, err
}

func (conn ConnWithMetrics) Write(b []byte) (n int, err error) {
	n, err = conn.underlying.Write(b)
	conn.Accumulate(!conn.inbound, n)
	return n, err
}

func (conn ConnWithMetrics) Close() error {
	if conn.inboundBytes > 0 {
		conn.PushMetric(true, conn.inboundBytes)
	}
	if conn.outboundBytes > 0 {
		conn.PushMetric(false, conn.outboundBytes)
	}
	return conn.underlying.Close()
}

func (conn ConnWithMetrics) Accumulate(inbound bool, n int) {
	if inbound {
		conn.inboundBytes += n

		if conn.inboundBytes > metricChunkSize {
			conn.PushMetric(true, conn.inboundBytes)
			conn.inboundBytes = 0
		}
	} else {
		conn.outboundBytes += n

		if conn.outboundBytes > metricChunkSize {
			conn.PushMetric(false, conn.outboundBytes)
			conn.outboundBytes = 0
		}
	}
}

func (conn ConnWithMetrics) PushMetric(inbound bool, n int) {
	conn.metricsChannel <- BandwidthMetric{
		Inbound:       inbound,
		ClientId:      conn.clientId,
		RemoteAddress: conn.remoteAddress,
		Service:       conn.service,
		Bytes:         n,
	}
}

func (conn ConnWithMetrics) LocalAddr() net.Addr {
	return conn.underlying.LocalAddr()
}

func (conn ConnWithMetrics) RemoteAddr() net.Addr {
	return conn.underlying.RemoteAddr()
}

func (conn ConnWithMetrics) SetDeadline(t time.Time) error {
	return conn.underlying.SetDeadline(t)
}

func (conn ConnWithMetrics) SetReadDeadline(t time.Time) error {
	return conn.underlying.SetReadDeadline(t)
}

func (conn ConnWithMetrics) SetWriteDeadline(t time.Time) error {
	return conn.underlying.SetWriteDeadline(t)
}
