package session

import (
	"crypto/ecdh"
	"crypto/rand"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/veritesclaude/svo-govno/pkg/poisonproto/crypto"
	"github.com/veritesclaude/svo-govno/pkg/poisonproto/frame"
)

// freezable wraps a real net.Conn so a test can simulate a DPI freeze: once
// frozen, outbound writes are silently swallowed (as a real stalled TCP
// connection would accept bytes into the local send buffer and then never
// deliver them) while reads keep working — the peer then naturally
// starves waiting for data that never arrives, with no error on either
// side until our own ACK-timeout logic notices.
type freezable struct {
	net.Conn
	mu     sync.Mutex
	frozen bool
}

func (f *freezable) Write(p []byte) (int, error) {
	f.mu.Lock()
	frozen := f.frozen
	f.mu.Unlock()
	if frozen {
		return len(p), nil
	}
	return f.Conn.Write(p)
}

func (f *freezable) Freeze() {
	f.mu.Lock()
	f.frozen = true
	f.mu.Unlock()
}

func tcpPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var serverConn net.Conn
	var acceptErr error
	accepted := make(chan struct{})
	go func() {
		serverConn, acceptErr = ln.Accept()
		close(accepted)
	}()
	clientConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	<-accepted
	if acceptErr != nil {
		t.Fatal(acceptErr)
	}
	return clientConn, serverConn
}

// testHarness drives a client Session against a server Session (with its
// own little registry, mirroring what transport.Server will do for real)
// entirely in-process over real loopback TCP, so pool growth, freezing,
// and migration all exercise genuine concurrent I/O.
type testHarness struct {
	t          *testing.T
	cfg        Config
	serverPriv *ecdh.PrivateKey

	mu         sync.Mutex
	serverSess *Session
	conns      []*freezable

	clientSess *Session
}

func newHarness(t *testing.T, cfg Config) *testHarness {
	t.Helper()
	serverPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	h := &testHarness{t: t, cfg: cfg, serverPriv: serverPriv}

	firstConn, err := h.dialOne()
	if err != nil {
		t.Fatalf("initial dial: %v", err)
	}
	id, err := NewID()
	if err != nil {
		t.Fatal(err)
	}
	clientSess, err := New(id, firstConn, true, cfg, func() (*crypto.Conn, error) { return h.dialOne() })
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	h.clientSess = clientSess
	t.Cleanup(func() {
		clientSess.Close()
		h.mu.Lock()
		if h.serverSess != nil {
			h.serverSess.Close()
		}
		h.mu.Unlock()
	})
	return h
}

func (h *testHarness) dialOne() (*crypto.Conn, error) {
	cRaw, sRaw := tcpPair(h.t)
	fc := &freezable{Conn: cRaw}

	h.mu.Lock()
	h.conns = append(h.conns, fc)
	h.mu.Unlock()

	clientStatic, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	type hsResult struct {
		keys *crypto.TransportKeys
		err  error
	}
	clientRes := make(chan hsResult, 1)
	serverRes := make(chan hsResult, 1)

	go func() {
		keys, err := crypto.Handshake(fc, true, crypto.DHKeyFromECDH(clientStatic), crypto.RemoteStaticFromECDH(h.serverPriv.PublicKey()))
		clientRes <- hsResult{keys, err}
	}()
	go func() {
		keys, err := crypto.Handshake(sRaw, false, crypto.DHKeyFromECDH(h.serverPriv), nil)
		serverRes <- hsResult{keys, err}
	}()

	cr := <-clientRes
	if cr.err != nil {
		return nil, cr.err
	}
	sr := <-serverRes
	if sr.err != nil {
		return nil, sr.err
	}

	clientConn := crypto.NewConn(fc, cr.keys)
	serverConn := crypto.NewConn(sRaw, sr.keys)
	go h.acceptServerSide(serverConn)
	return clientConn, nil
}

func (h *testHarness) acceptServerSide(c *crypto.Conn) {
	id, err := ReadAttach(c)
	if err != nil {
		return
	}
	if err := CompleteAttach(c, id); err != nil {
		return
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	if h.serverSess == nil {
		h.serverSess = NewFromAttached(id, c, false, h.cfg, nil)
		return
	}
	h.serverSess.AddConn(c)
}

func (h *testHarness) freeze(idx int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.conns[idx].Freeze()
}

func (h *testHarness) killUnderlying(idx int) {
	h.mu.Lock()
	c := h.conns[idx].Conn
	h.mu.Unlock()
	_ = c.Close()
}

func (h *testHarness) connCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.conns)
}

func waitFor(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("condition not met within %s", timeout)
}

func fastCfg() Config {
	return Config{
		PoolMin: 3, PoolMax: 6,
		BudgetMin: 1 << 30, BudgetMax: 1<<30 + 1, // effectively unlimited for tests that don't target budget
		Adaptive:      true,
		AckTimeoutMin: 80 * time.Millisecond,
		AckTimeoutMax: 150 * time.Millisecond,
	}
}

func TestPoolEstablishesMultipleConnections(t *testing.T) {
	h := newHarness(t, fastCfg())
	waitFor(t, 3*time.Second, func() bool { return h.clientSess.liveConnCount() >= 3 })
	waitFor(t, 3*time.Second, func() bool {
		h.mu.Lock()
		defer h.mu.Unlock()
		return h.serverSess != nil && h.serverSess.liveConnCount() >= 3
	})
}

func TestStreamDataSurvivesFrozenConnection(t *testing.T) {
	h := newHarness(t, fastCfg())
	waitFor(t, 3*time.Second, func() bool { return h.clientSess.liveConnCount() >= 3 })
	waitFor(t, 3*time.Second, func() bool {
		h.mu.Lock()
		defer h.mu.Unlock()
		return h.serverSess != nil
	})

	cst, err := h.clientSess.OpenStream(frame.NetworkTCP, "target:1")
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	var sst *Stream
	accepted := make(chan struct{})
	go func() {
		h.mu.Lock()
		srv := h.serverSess
		h.mu.Unlock()
		sst, err = srv.AcceptStream()
		close(accepted)
	}()
	select {
	case <-accepted:
		if err != nil {
			t.Fatalf("AcceptStream: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for AcceptStream")
	}

	// Freeze the connection a DATA frame would currently go out on: pin it
	// down by freezing connection 0, which is the oldest and so the one
	// pickConn's round robin will have used already.
	h.freeze(0)

	const chunks = 40
	payload := make([]byte, 500)
	for i := range payload {
		payload[i] = byte(i)
	}

	done := make(chan error, 1)
	go func() {
		for i := 0; i < chunks; i++ {
			if _, err := cst.Write(payload); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()

	buf := make([]byte, len(payload))
	for i := 0; i < chunks; i++ {
		if _, err := io.ReadFull(sst, buf); err != nil {
			t.Fatalf("chunk %d: server read: %v", i, err)
		}
		for j := range buf {
			if buf[j] != payload[j] {
				t.Fatalf("chunk %d: byte %d corrupted", i, j)
			}
		}
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("client write: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for client writer")
	}
}

func TestSessionMigratesWhenPoolDies(t *testing.T) {
	h := newHarness(t, fastCfg())
	waitFor(t, 3*time.Second, func() bool { return h.clientSess.liveConnCount() >= 3 })
	waitFor(t, 3*time.Second, func() bool {
		h.mu.Lock()
		defer h.mu.Unlock()
		return h.serverSess != nil
	})

	n := h.connCount()
	for i := 0; i < n; i++ {
		h.killUnderlying(i)
	}

	waitFor(t, 5*time.Second, func() bool { return h.clientSess.liveConnCount() >= 1 })

	cst, err := h.clientSess.OpenStream(frame.NetworkTCP, "post-migration:1")
	if err != nil {
		t.Fatalf("OpenStream after migration: %v", err)
	}
	h.mu.Lock()
	srv := h.serverSess
	h.mu.Unlock()
	sst, err := srv.AcceptStream()
	if err != nil {
		t.Fatalf("AcceptStream after migration: %v", err)
	}

	msg := []byte("still alive after migration")
	go cst.Write(msg)
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(sst, buf); err != nil {
		t.Fatalf("read after migration: %v", err)
	}
	if string(buf) != string(msg) {
		t.Fatalf("got %q want %q", buf, msg)
	}
}

func TestBudgetExhaustionRetiresAndAdapts(t *testing.T) {
	cfg := Config{
		PoolMin: 2, PoolMax: 4,
		BudgetMin: 2000, BudgetMax: 2000,
		Adaptive:      true,
		AckTimeoutMin: 80 * time.Millisecond,
		AckTimeoutMax: 150 * time.Millisecond,
	}
	h := newHarness(t, cfg)
	waitFor(t, 3*time.Second, func() bool { return h.clientSess.liveConnCount() >= 2 })

	cst, err := h.clientSess.OpenStream(frame.NetworkTCP, "budget:1")
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, 3*time.Second, func() bool {
		h.mu.Lock()
		defer h.mu.Unlock()
		return h.serverSess != nil
	})
	h.mu.Lock()
	srv := h.serverSess
	h.mu.Unlock()
	sst, err := srv.AcceptStream()
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		buf := make([]byte, 4096)
		for {
			if _, err := sst.Read(buf); err != nil {
				return
			}
		}
	}()

	// Push well past several connections' worth of send budget so at
	// least one clean retirement (and, given growAfterCleanRetires,
	// adaptive growth) has to happen.
	chunk := make([]byte, 1000)
	initialConnCount := h.connCount()
	for i := 0; i < 40; i++ {
		if _, err := cst.Write(chunk); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}

	// The adaptive-growth arithmetic itself is covered in isolation by
	// budget_test.go; here, over real concurrent I/O, we can't pin down
	// exactly how many retirements happen clean vs. get counted as a
	// freeze (test-harness scheduling jitter can trip the ACK-timeout on
	// an unrelated connection), so just confirm budget exhaustion actually
	// retires connections and the pool replaces them (ТЗ §8.2) rather than
	// stalling.
	waitFor(t, 5*time.Second, func() bool { return h.connCount() > initialConnCount })
}
