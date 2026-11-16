package session

import (
	"crypto/rand"
	"fmt"

	"github.com/veritesclaude/svo-govno/pkg/poisonproto/crypto"
	"github.com/veritesclaude/svo-govno/pkg/poisonproto/frame"
)

// ID is a session identifier (ТЗ §8.1: "случайный ID 16 байт").
type ID [16]byte

func NewID() (ID, error) {
	var id ID
	_, err := rand.Read(id[:])
	return id, err
}

// SESSION_ATTACH frames always carry Seq 0 and never enter the generic
// reliability bookkeeping (package doc in reliability.go) — the handshake
// below runs directly on a bare crypto.Conn before it is ever registered
// with a Session's pool, which is the only place that bookkeeping lives.

func sendAttachRequest(c *crypto.Conn, id ID) error {
	buf, err := frame.Encode(nil, &frame.Frame{Type: frame.TypeSessionAttach, Data: id[:]})
	if err != nil {
		return err
	}
	return c.Seal(buf, nil)
}

func readAttachReply(c *crypto.Conn, want ID) error {
	pt, err := c.Open(nil)
	if err != nil {
		return err
	}
	f, err := frame.Decode(pt)
	if err != nil {
		return err
	}
	if f.Type != frame.TypeSessionAttach || len(f.Data) < 16 || ID(f.Data[:16]) != want {
		return fmt.Errorf("session: attach reply mismatch")
	}
	return nil
}

// ReadAttach reads the first frame off a fresh connection, expecting
// SESSION_ATTACH, and returns the session ID it announced WITHOUT sending
// the echo reply yet. The server-side session registry (package
// transport) uses the ID to decide whether this is a brand new session or
// an additional pool connection for one already running, before calling
// CompleteAttach.
func ReadAttach(c *crypto.Conn) (ID, error) {
	pt, err := c.Open(nil)
	if err != nil {
		return ID{}, err
	}
	f, err := frame.Decode(pt)
	if err != nil {
		return ID{}, err
	}
	if f.Type != frame.TypeSessionAttach || len(f.Data) < 16 {
		return ID{}, fmt.Errorf("session: expected SESSION_ATTACH, got %s", f.Type)
	}
	var id ID
	copy(id[:], f.Data[:16])
	return id, nil
}

// CompleteAttach sends the SESSION_ATTACH echo, finishing the responder
// side of the handshake ReadAttach started.
func CompleteAttach(c *crypto.Conn, id ID) error {
	buf, err := frame.Encode(nil, &frame.Frame{Type: frame.TypeSessionAttach, Data: id[:]})
	if err != nil {
		return err
	}
	return c.Seal(buf, nil)
}
