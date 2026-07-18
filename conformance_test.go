package hydra

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// tapConn records every byte a side writes and can flip one bit at a
// chosen absolute offset of the write stream (line-noise injection).
type tapConn struct {
	net.Conn
	mu        sync.Mutex
	wrote     bytes.Buffer
	written   int64
	corruptAt int64 // -1 = never
}

func newTap(c net.Conn, corruptAt int64) *tapConn {
	return &tapConn{Conn: c, corruptAt: corruptAt}
}

func (c *tapConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	c.wrote.Write(p)
	start := c.written
	c.written += int64(len(p))
	corrupt := -1
	if c.corruptAt >= start && c.corruptAt < c.written {
		corrupt = int(c.corruptAt - start)
	}
	c.mu.Unlock()
	if corrupt >= 0 {
		q := append([]byte(nil), p...)
		q[corrupt] ^= 0x01
		n, err := c.Conn.Write(q)
		return n, err
	}
	return c.Conn.Write(p)
}

func (c *tapConn) recorded() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.wrote.Bytes()...)
}

// countFrames decodes a recorded stream and tallies packet types.
// payloads returns each packet's payload for deeper asserts.
func countFrames(t *testing.T, recorded []byte, opts uint32) (map[byte]int, map[byte][][]byte) {
	t.Helper()
	var o atomic.Uint32
	o.Store(opts)
	r := newTransportReader(bytes.NewReader(recorded), &o)
	counts := make(map[byte]int)
	payloads := make(map[byte][][]byte)
	for {
		pkt, err := r.readPacket()
		if err != nil {
			return counts, payloads
		}
		counts[pkt.typ]++
		payloads[pkt.typ] = append(payloads[pkt.typ], pkt.payload)
	}
}

// Conformance AutostartEmission + EndHandshake: the autostart string
// precedes the first START frame, and each side emits 3–5 ENDs (2+3
// when it sends before hearing the peer's END, 3 when the peer's END
// arrives first — both orderings exist in HydraCom's own loop).
func TestConformanceAutostartAndEndCounts(t *testing.T) {
	connA, connB := net.Pipe()
	tapA, tapB := newTap(connA, -1), newTap(connB, -1)
	hA, hB := newTestHandler(nil), newTestHandler(nil)
	sa := NewSession(tapA, hA, hA, nil, testConfig(true))
	sb := NewSession(tapB, hB, hB, nil, testConfig(false))
	defer sa.Close()
	defer sb.Close()
	if errA, errB := runBoth(t, sa, sb); errA != nil || errB != nil {
		t.Fatalf("session errors: A=%v B=%v", errA, errB)
	}

	for side, tap := range map[string]*tapConn{"A": tapA, "B": tapB} {
		rec := tap.recorded()
		if !bytes.HasPrefix(rec, []byte(autostart)) {
			t.Errorf("%s: stream does not begin with %q: % x", side, autostart, rec[:8])
		}
		counts, _ := countFrames(t, rec, capC32)
		if n := counts[pktEND]; n < 3 || n > 5 {
			t.Errorf("%s emitted %d ENDs, want 3..5", side, n)
		}
		if counts[pktSTART] < 1 || counts[pktINIT] < 1 || counts[pktINITACK] < 1 {
			t.Errorf("%s handshake frames missing: %v", side, counts)
		}
	}
}

// Conformance ForcedReposition + EmitLongAcceptShort (emit half): a
// corrupted DATA frame forces the receiver to RPOS; the sender reseeks;
// the file arrives intact; and the RPOS on the wire is the 12-byte LONG
// form.
func TestConformanceRposRecoveryAndLongForm(t *testing.T) {
	data := randBytes(t, 200000)
	connA, connB := net.Pipe()
	tapA := newTap(connA, 50000) // mid-DATA in A's stream
	tapB := newTap(connB, -1)
	hA := newTestHandler([]testFile{{"noisy.bin", data}})
	hB := newTestHandler(nil)
	sa := NewSession(tapA, hA, hA, nil, testConfig(true))
	sb := NewSession(tapB, hB, hB, nil, testConfig(false))
	defer sa.Close()
	defer sb.Close()
	if errA, errB := runBoth(t, sa, sb); errA != nil || errB != nil {
		t.Fatalf("session errors: A=%v B=%v", errA, errB)
	}
	if !bytes.Equal(hB.got("noisy.bin"), data) {
		t.Fatal("file corrupted despite RPOS recovery")
	}
	counts, payloads := countFrames(t, tapB.recorded(), capC32)
	if counts[pktRPOS] == 0 {
		t.Fatal("no RPOS emitted after corruption")
	}
	for _, p := range payloads[pktRPOS] {
		if len(p) != 12 {
			t.Errorf("RPOS payload %d bytes, want 12 (LONG form)", len(p))
		}
	}
}

// --- scripted peer -----------------------------------------------------------

// scriptPeer drives the raw wire against one Session using the library's
// own framing primitives, for scenarios a well-behaved Session cannot
// produce.
type scriptPeer struct {
	t    *testing.T
	conn net.Conn
	w    *transportWriter
	r    *transportReader
	opts atomic.Uint32
}

func newScriptPeer(t *testing.T, conn net.Conn) *scriptPeer {
	sp := &scriptPeer{t: t, conn: conn}
	sp.opts.Store(0) // clean loopback: no strip, no filter
	sp.w = newTransportWriter(conn)
	sp.r = newTransportReader(conn, &sp.opts)
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
	return sp
}

func (sp *scriptPeer) send(typ byte, payload []byte) {
	sp.t.Helper()
	if err := sp.w.writePacket(typ, payload, sp.opts.Load(), ""); err != nil {
		sp.t.Fatalf("script send %c: %v", typ, err)
	}
}

// expect reads packets until one of the wanted types arrives.
func (sp *scriptPeer) expect(types ...byte) packet {
	sp.t.Helper()
	for {
		pkt, err := sp.r.readPacket()
		if err != nil {
			sp.t.Fatalf("script expect %q: %v", types, err)
		}
		if slices.Contains(types, pkt.typ) {
			return pkt
		}
		// Skip everything else (retries, IDLEs, chatter).
	}
}

// drainRest consumes everything else the session writes so its blocking
// writes into the synchronous pipe can complete (net.Pipe has no
// buffer). Call once no further expectations remain.
func (sp *scriptPeer) drainRest() {
	go func() { _, _ = io.Copy(io.Discard, sp.conn) }()
}

// handshake completes START/INIT/INITACK with the given flag lists and
// flips the script's decode options to the negotiated effective set.
func (sp *scriptPeer) handshake(supported, desired string) {
	sp.t.Helper()
	sp.expect(pktSTART)
	sp.send(pktINIT, marshalInit(initPkt{
		appID:     "2b1aab00script,1.0",
		supported: parseCaps(supported),
		desired:   parseCaps(desired),
	}))
	sp.expect(pktINITACK)
	sp.expect(pktINIT)
	sp.send(pktINITACK, nil)
	sp.opts.Store(capC32) // both sides support C32 in these scripts
}

func scriptedPair(t *testing.T, h *testHandler, cfg *Config) (*Session, *scriptPeer, chan error) {
	t.Helper()
	connA, connB := net.Pipe()
	sess := NewSession(connA, h, h, nil, cfg)
	sp := newScriptPeer(t, connB)
	errCh := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
		defer cancel()
		errCh <- sess.Run(ctx)
	}()
	return sess, sp, errCh
}

// Conformance UnknownCapability: an INIT carrying PLZ/FOO/XYZ must
// negotiate cleanly with the unknown codes dropped.
func TestConformanceUnknownCapability(t *testing.T) {
	sess, sp, errCh := scriptedPair(t, newTestHandler(nil), testConfig(true))
	defer sess.Close()
	sp.handshake("XON,TLN,CTL,HIC,HI8,BRK,C32,DEV,FPT,PLZ,FOO,XYZ", "PLZ,FOO")

	// Session has nothing to send: EOB FINFO arrives; ack it, send our
	// own EOB, and complete the END dance.
	fi := sp.expect(pktFINFO)
	if !isFinfoEOB(fi.payload) {
		t.Fatalf("expected EOB FINFO, got %d bytes", len(fi.payload))
	}
	sp.send(pktFINFOACK, marshalOffset(0))
	sp.send(pktFINFO, finfoEOB)
	sp.expect(pktFINFOACK)
	sp.expect(pktEND)
	sp.send(pktEND, nil)
	sp.drainRest()

	if err := <-errCh; err != nil {
		t.Fatalf("session error: %v", err)
	}
	eff := sess.effOpts.Load()
	if eff&capC32 == 0 || eff&capDEV == 0 {
		t.Errorf("effective set %#x missing C32/DEV (union rule)", eff)
	}
	if eff&(capASC|capUUE) != 0 {
		t.Errorf("effective set %#x contains decode-only encodings", eff)
	}
}

// Conformance EmitLongAcceptShort (accept half): a 10-byte WORD-form
// RPOS from a bforce-style peer must trigger a reseek to the requested
// offset.
func TestConformanceAcceptShortRpos(t *testing.T) {
	data := randBytes(t, 120000)
	h := newTestHandler([]testFile{{"w.bin", data}})
	cfg := testConfig(true)
	sess, sp, errCh := scriptedPair(t, h, cfg)
	defer sess.Close()
	sp.handshake("XON,TLN,CTL,HIC,HI8,BRK,C32,DEV,FPT", "")

	sp.expect(pktFINFO)
	sp.send(pktFINFOACK, marshalOffset(0))

	// Let a few blocks through, then demand a rewind to 0 in the
	// 10-byte WORD form (offset 0, blocksize 256, id 1).
	for range 3 {
		sp.expect(pktDATA)
	}
	word := []byte{0, 0, 0, 0, 0x00, 0x01, 1, 0, 0, 0}
	sp.send(pktRPOS, word)

	// The sender must come back to offset 0.
	deadline := time.Now().Add(10 * time.Second)
	for {
		pkt := sp.expect(pktDATA)
		off, _, err := parseData(pkt.payload)
		if err == nil && off == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("sender never rewound to offset 0")
		}
	}
	// Drain the rest of the transfer and finish the batch.
	var got int64
	for {
		pkt, err := sp.r.readPacket()
		if err != nil {
			t.Fatalf("script read: %v", err)
		}
		if pkt.typ == pktDATA {
			off, d, derr := parseData(pkt.payload)
			if derr == nil && off == got {
				got += int64(len(d))
			}
			continue
		}
		if pkt.typ == pktEOF {
			off, _ := parseOffset(pkt.payload)
			if int64(off) == got {
				break
			}
			// EOF at wrong position (blocks crossed our RPOS): ask
			// for a resync at our position, LONG form like HydraCom.
			sp.send(pktRPOS, marshalRpos(rposPkt{offset: got, blocksize: 512, id: 2}))
		}
	}
	sp.send(pktEOFACK, nil)
	fi := sp.expect(pktFINFO)
	if !isFinfoEOB(fi.payload) {
		t.Fatalf("expected EOB after file, got %d bytes", len(fi.payload))
	}
	sp.send(pktFINFOACK, marshalOffset(0))
	sp.send(pktFINFO, finfoEOB)
	sp.expect(pktFINFOACK)
	sp.expect(pktEND)
	sp.send(pktEND, nil)
	sp.drainRest()

	if err := <-errCh; err != nil {
		t.Fatalf("session error: %v", err)
	}
	if got != int64(len(data)) {
		t.Errorf("script received %d bytes, want %d", got, len(data))
	}
}

// Conformance IdleResetsBraindead: IDLE during active transfer states
// must keep the session alive past BrainDead; silence must not.
func TestConformanceIdleResetsBraindead(t *testing.T) {
	mk := func() (*Config, []testFile) {
		cfg := testConfig(true)
		cfg.BrainDead = 1 * time.Second
		cfg.Timeout = 3 * time.Second
		return cfg, []testFile{{"x.bin", randBytes(t, 1000)}}
	}

	// With IDLEs: alive well past BrainDead, then killed by cancel.
	cfg, files := mk()
	sess, sp, errCh := scriptedPair(t, newTestHandler(files), cfg)
	defer sess.Close()
	sp.handshake("XON,TLN,CTL,HIC,HI8,BRK,C32,DEV,FPT", "")
	sp.expect(pktFINFO) // withhold the ack; keep the peer waiting
	sp.drainRest()      // absorb FINFO retries so the peer never blocks
	stop := time.After(3 * time.Second)
	tick := time.NewTicker(300 * time.Millisecond)
	defer tick.Stop()
idleLoop:
	for {
		select {
		case <-tick.C:
			sp.send(pktIDLE, nil)
		case <-stop:
			break idleLoop
		}
	}
	if _, err := sp.conn.Write(bytes.Repeat([]byte{DLE}, detectCancelCount)); err != nil {
		t.Fatal(err)
	}
	if err := <-errCh; !errors.Is(err, ErrPeerCancel) {
		t.Fatalf("with IDLEs: err = %v, want ErrPeerCancel (not braindead)", err)
	}

	// Without IDLEs: braindead fires.
	cfg2, files2 := mk()
	sess2, sp2, errCh2 := scriptedPair(t, newTestHandler(files2), cfg2)
	defer sess2.Close()
	sp2.handshake("XON,TLN,CTL,HIC,HI8,BRK,C32,DEV,FPT", "")
	sp2.expect(pktFINFO)
	sp2.drainRest() // absorb the courtesy cancel after braindead
	if err := <-errCh2; !errors.Is(err, ErrBrainDead) {
		t.Fatalf("silent peer: err = %v, want ErrBrainDead", err)
	}
	// Drain the reader so the pipe close doesn't block anything.
	_ = sp2.conn.Close()
}

// Conformance CancelTolerance at session level: 5 raw DLEs mid-session
// abort with ErrPeerCancel.
func TestConformancePeerCancel(t *testing.T) {
	sess, sp, errCh := scriptedPair(t, newTestHandler(nil), testConfig(true))
	defer sess.Close()
	sp.expect(pktSTART)
	if _, err := sp.conn.Write(bytes.Repeat([]byte{DLE}, detectCancelCount)); err != nil {
		t.Fatal(err)
	}
	if err := <-errCh; !errors.Is(err, ErrPeerCancel) {
		t.Fatalf("err = %v, want ErrPeerCancel", err)
	}
}

// Regression (review SEV-1): a batch that dies mid-file must still fire
// FileCompleted exactly once for the in-flight receive and close its
// writer.
func TestConformanceTeardownOnError(t *testing.T) {
	h := newTestHandler(nil)
	sess, sp, errCh := scriptedPair(t, h, testConfig(true))
	defer sess.Close()
	sp.handshake("XON,TLN,CTL,HIC,HI8,BRK,C32,DEV,FPT", "")
	sp.expect(pktFINFO) // session's EOB
	sp.send(pktFINFOACK, marshalOffset(0))

	// Announce a file, stream two blocks, then cancel mid-transfer.
	sp.send(pktFINFO, marshalFinfo(fileMeta{size: 10000, name: "dead.bin"}, false))
	sp.expect(pktFINFOACK)
	sp.send(pktDATA, marshalData(0, bytes.Repeat([]byte{1}, 512)))
	sp.send(pktDATA, marshalData(512, bytes.Repeat([]byte{2}, 512)))
	sp.drainRest()
	if _, err := sp.conn.Write(bytes.Repeat([]byte{DLE}, detectCancelCount)); err != nil {
		t.Fatal(err)
	}
	if err := <-errCh; !errors.Is(err, ErrPeerCancel) {
		t.Fatalf("err = %v, want ErrPeerCancel", err)
	}
	done, errs := h.completions()
	if len(done) != 1 || done[0].Name != "dead.bin" {
		t.Fatalf("completions = %v, want exactly dead.bin", done)
	}
	if errs[0] == nil {
		t.Error("in-flight file completed with nil error on abort")
	}
	if _, ok := h.received["dead.bin"]; !ok {
		t.Error("writer was never closed (Close stores the buffer)")
	}
}

// Regression (review SEV-1): Abort before the first Run must not panic
// and must poison later Runs.
func TestConformanceAbortBeforeRun(t *testing.T) {
	connA, _ := net.Pipe()
	h := newTestHandler(nil)
	sess := NewSession(connA, h, h, nil, testConfig(true))
	if err := sess.Abort(); err != nil {
		t.Fatalf("Abort: %v", err)
	}
	if err := sess.Run(context.Background()); !errors.Is(err, ErrSessionAborted) {
		t.Fatalf("Run after Abort = %v, want ErrSessionAborted", err)
	}
}

// Run after Close must not report a successful batch.
func TestConformanceRunAfterClose(t *testing.T) {
	connA, _ := net.Pipe()
	h := newTestHandler(nil)
	sess := NewSession(connA, h, h, nil, testConfig(true))
	_ = sess.Close()
	if err := sess.Run(context.Background()); !errors.Is(err, ErrSessionClosed) {
		t.Fatalf("Run after Close = %v, want ErrSessionClosed", err)
	}
}

// Regression (peer review): a DEVDATA landing in the inter-batch gap
// must not leak into the next batch's context — no OnDeviceData
// delivery, no pre-negotiation DEVDACK.
func TestConformanceStaleDevDataBetweenBatches(t *testing.T) {
	dev := &recordingDev{}
	connA, connB := net.Pipe()
	h := newTestHandler(nil)
	sess := NewSession(connA, h, h, dev, testConfig(true))
	defer sess.Close()
	sp := newScriptPeer(t, connB)
	errCh := make(chan error, 1)
	runOnce := func() {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
			defer cancel()
			errCh <- sess.Run(ctx)
		}()
	}

	completeBatch := func() {
		fi := sp.expect(pktFINFO)
		if !isFinfoEOB(fi.payload) {
			t.Fatalf("expected EOB FINFO, got %d bytes", len(fi.payload))
		}
		sp.send(pktFINFOACK, marshalOffset(0))
		sp.send(pktFINFO, finfoEOB)
		sp.expect(pktFINFOACK)
		sp.expect(pktEND)
		sp.send(pktEND, nil)
		// Consume the session's remaining ENDs inline (its second
		// initial END plus the 3-END response) — net.Pipe writes block
		// until read, and we keep using the script reader in batch 2 so
		// a background drainer is not an option here.
		for range 4 {
			sp.expect(pktEND)
		}
	}

	runOnce()
	sp.handshake("XON,TLN,CTL,HIC,HI8,BRK,C32,DEV,FPT", "")
	completeBatch()
	if err := <-errCh; err != nil {
		t.Fatalf("batch 1: %v", err)
	}

	// Inter-batch gap: peer sends a trailing DEVDATA.
	sp.send(pktDEVDATA, marshalDevData(devDataPkt{id: 99, device: "CON", payload: []byte("stale")}))
	time.Sleep(100 * time.Millisecond) // let the reader queue it

	runOnce()
	sp.opts.Store(0) // batch 2 renegotiates from the assumed state
	sp.handshake("XON,TLN,CTL,HIC,HI8,BRK,C32,DEV,FPT", "")
	completeBatch()
	sp.drainRest()
	if err := <-errCh; err != nil {
		t.Fatalf("batch 2: %v", err)
	}
	dev.mu.Lock()
	defer dev.mu.Unlock()
	if len(dev.msgs) != 0 {
		t.Errorf("stale inter-batch DEVDATA was delivered: %q", dev.msgs)
	}
}

// A vital-flag mismatch must abort with ErrIncompatible: we desire CTL
// but the peer's supported set lacks it.
func TestConformanceIncompatible(t *testing.T) {
	cfg := testConfig(true)
	cfg.Desired = []string{"CTL"}
	sess, sp, errCh := scriptedPair(t, newTestHandler(nil), cfg)
	defer sess.Close()
	sp.expect(pktSTART)
	sp.send(pktINIT, marshalInit(initPkt{
		appID:     "2b1aab00script,1.0",
		supported: capXON | capTLN | capC32, // no CTL
		desired:   0,
	}))
	sp.drainRest() // absorb the courtesy cancel
	if err := <-errCh; !errors.Is(err, ErrIncompatible) {
		t.Fatalf("err = %v, want ErrIncompatible", err)
	}
}

var _ io.ReadWriter = (*tapConn)(nil)
