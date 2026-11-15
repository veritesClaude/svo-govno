package transport

import (
	"io"
	"net"
	"sync"
)

// recordingReader wraps a net.Conn and remembers every byte actually read
// from it, so a failed/unauthenticated handshake attempt (ТЗ §6.2) can be
// replayed byte-for-byte to a real fallback site: the prober must see
// exactly what it would have seen talking to that site directly, our own
// parsing included.
type recordingReader struct {
	conn net.Conn
	buf  []byte
}

func newRecordingReader(conn net.Conn) *recordingReader {
	return &recordingReader{conn: conn}
}

func (r *recordingReader) Read(p []byte) (int, error) {
	n, err := r.conn.Read(p)
	if n > 0 {
		r.buf = append(r.buf, p[:n]...)
	}
	return n, err
}

// Consumed returns a copy of every byte read so far.
func (r *recordingReader) Consumed() []byte {
	out := make([]byte, len(r.buf))
	copy(out, r.buf)
	return out
}

// prefixConn presents `prefix` followed by the live conn's remaining bytes
// to readers, while writes pass straight through — used to hand stdlib
// crypto/tls.Server the exact bytes we already consumed while peeking the
// ClientHello (ТЗ §6.3), without having actually un-read them from the
// socket.
type prefixConn struct {
	net.Conn
	mu     sync.Mutex
	prefix []byte
}

func (c *prefixConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	if len(c.prefix) > 0 {
		n := copy(p, c.prefix)
		c.prefix = c.prefix[n:]
		c.mu.Unlock()
		return n, nil
	}
	c.mu.Unlock()
	return c.Conn.Read(p)
}

// spliceToFallback transparently proxies conn to a real fallback site:
// replay the bytes already consumed while peeking, then copy in both
// directions until either side closes. This is what makes an invalid or
// absent token indistinguishable from hitting the real site (ТЗ §6.2).
func spliceToFallback(conn net.Conn, consumed []byte, dial func(sni string) (net.Conn, error), sni string) error {
	upstream, err := dial(sni)
	if err != nil {
		return err
	}
	defer upstream.Close()

	if len(consumed) > 0 {
		if _, err := upstream.Write(consumed); err != nil {
			return err
		}
	}

	errc := make(chan error, 2)
	go func() {
		_, err := io.Copy(upstream, conn)
		errc <- err
	}()
	go func() {
		_, err := io.Copy(conn, upstream)
		errc <- err
	}()
	return <-errc
}
