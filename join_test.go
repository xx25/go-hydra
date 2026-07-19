package hydra

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// joinConn models the transport shape transfer drivers hand a Session
// on a serial line: reads only ever fail via a (possibly concurrently
// set) read deadline, and "Close" is not a real close but an
// expired-deadline poke on a conn that must stay usable afterwards.
// This is exactly the fidomail modem shim contract Close's join
// exists for.
type joinConn struct {
	mu       sync.Mutex
	deadline time.Time
	closed   bool

	reads atomic.Int32 // Read invocations, for leak detection
}

var errFakeTimeout = errors.New("joinConn: read deadline exceeded")

func (c *joinConn) Read(p []byte) (int, error) {
	c.reads.Add(1)
	for {
		c.mu.Lock()
		dl := c.deadline
		closed := c.closed
		c.mu.Unlock()
		if closed {
			return 0, net.ErrClosed
		}
		if !dl.IsZero() && !time.Now().Before(dl) {
			return 0, errFakeTimeout
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (c *joinConn) Write(p []byte) (int, error) { return len(p), nil }

func (c *joinConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.deadline = t
	c.mu.Unlock()
	return nil
}

// Close is the driver-shim poke: expire the read deadline, close
// nothing. The conn remains usable.
func (c *joinConn) Close() error {
	return c.SetReadDeadline(time.Now())
}

// TestCloseJoinsReader pins Close's barrier property: it must not
// return until the reader goroutine has exited, so a caller that
// immediately re-arms the read deadline (fidomail's clearDeadline)
// cannot re-block a still-parked reader forever.
func TestCloseJoinsReader(t *testing.T) {
	c := &joinConn{}
	s := NewSession(c, nil, nil, nil, &Config{Originator: true})

	runDone := make(chan error, 1)
	go func() { runDone <- s.Run(context.Background()) }()

	// Wait until the reader goroutine is parked inside c.Read.
	parkDeadline := time.Now().Add(2 * time.Second)
	for c.reads.Load() == 0 {
		if time.Now().After(parkDeadline) {
			t.Fatal("reader goroutine never parked in Read")
		}
		time.Sleep(5 * time.Millisecond)
	}

	start := time.Now()
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("Close took %v; the join should complete within one poll tick", elapsed)
	}

	// The barrier: reader must be GONE the moment Close returns.
	select {
	case <-s.readerDone:
	default:
		t.Fatal("Close returned but the reader goroutine is still running")
	}

	// The property the barrier exists for: the caller's deadline
	// re-arm after Close must not revive/re-block anything. No further
	// Read calls may occur.
	_ = c.SetReadDeadline(time.Time{})
	before := c.reads.Load()
	time.Sleep(150 * time.Millisecond)
	if after := c.reads.Load(); after != before {
		t.Fatalf("leaked reader: %d new Read call(s) after Close returned", after-before)
	}

	<-runDone // Run must terminate too (abortCh)
}

// TestCloseBeforeRunDoesNotWait pins the no-reader case: Close on a
// session whose Run never started must not wait for readerJoinTimeout.
func TestCloseBeforeRunDoesNotWait(t *testing.T) {
	s := NewSession(&joinConn{}, nil, nil, nil, &Config{})
	start := time.Now()
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 200*time.Millisecond {
		t.Fatalf("Close waited %v with no reader started", elapsed)
	}
}
