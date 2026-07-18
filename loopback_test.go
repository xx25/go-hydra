package hydra

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type testFile struct {
	name string
	data []byte
}

// testHandler implements SendHandler + RecvHandler for both sides of a
// loopback session.
type testHandler struct {
	mu sync.Mutex

	pending  []*FileOffer
	received map[string][]byte

	skip       map[string]bool // AcceptFile → ErrSkip
	deferFiles map[string]bool // AcceptFile → ErrDefer
	resumeFrom map[string]int64

	completed []FileInfo
	errs      []error
}

func newTestHandler(out []testFile) *testHandler {
	h := &testHandler{
		received:   make(map[string][]byte),
		skip:       make(map[string]bool),
		deferFiles: make(map[string]bool),
		resumeFrom: make(map[string]int64),
	}
	for _, f := range out {
		h.pending = append(h.pending, &FileOffer{
			Name:    f.name,
			Size:    int64(len(f.data)),
			ModTime: time.Unix(1700000000, 0),
			Reader:  bytes.NewReader(f.data),
		})
	}
	return h
}

func (h *testHandler) NextFile() *FileOffer {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.pending) == 0 {
		return nil
	}
	o := h.pending[0]
	h.pending = h.pending[1:]
	return o
}

func (h *testHandler) AcceptFile(info FileInfo) (io.WriteCloser, int64, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.skip[info.Name] {
		return nil, 0, ErrSkip
	}
	if h.deferFiles[info.Name] {
		return nil, 0, ErrDefer
	}
	offset := h.resumeFrom[info.Name]
	bw := &bufferWriteCloser{h: h, name: info.Name}
	if offset > 0 {
		bw.buf = append(bw.buf, h.received[info.Name][:offset]...)
	}
	return bw, offset, nil
}

func (h *testHandler) FileProgress(_ FileInfo, _ int64) {}

func (h *testHandler) FileCompleted(info FileInfo, _ int64, err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.completed = append(h.completed, info)
	h.errs = append(h.errs, err)
}

func (h *testHandler) got(name string) []byte {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.received[name]
}

func (h *testHandler) completions() ([]FileInfo, []error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]FileInfo(nil), h.completed...), append([]error(nil), h.errs...)
}

type bufferWriteCloser struct {
	h    *testHandler
	name string
	buf  []byte
}

func (b *bufferWriteCloser) Write(p []byte) (int, error) {
	b.buf = append(b.buf, p...)
	return len(p), nil
}

func (b *bufferWriteCloser) Close() error {
	b.h.mu.Lock()
	b.h.received[b.name] = b.buf
	b.h.mu.Unlock()
	return nil
}

func testConfig(orig bool) *Config {
	return &Config{
		Originator:   orig,
		Timeout:      500 * time.Millisecond,
		BrainDead:    10 * time.Second,
		idleOverride: 200 * time.Millisecond,
	}
}

// runLoopback drives one batch on both ends of an in-memory pipe. The
// symmetric testHandler serves as both directions' handler.
func runLoopback(t *testing.T, hA, hB *testHandler, devA, devB DeviceHandler, cfgA, cfgB *Config) (*Session, *Session, error, error) {
	t.Helper()
	connA, connB := net.Pipe()
	if cfgA == nil {
		cfgA = testConfig(true)
	}
	if cfgB == nil {
		cfgB = testConfig(false)
	}
	sa := NewSession(connA, hA, hA, devA, cfgA)
	sb := NewSession(connB, hB, hB, devB, cfgB)
	errA, errB := runBoth(t, sa, sb)
	return sa, sb, errA, errB
}

func runBoth(t *testing.T, sa, sb *Session) (errA, errB error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); errA = sa.Run(ctx) }()
	go func() { defer wg.Done(); errB = sb.Run(ctx) }()
	wg.Wait()
	if ctx.Err() != nil {
		t.Fatal("loopback deadlocked (context timeout)")
	}
	return errA, errB
}

func randBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func TestLoopbackSymmetric(t *testing.T) {
	filesA := []testFile{
		{"a1.dat", randBytes(t, 10000)},
		{"a2.dat", randBytes(t, 1)},
		{"a3.dat", randBytes(t, 60000)},
	}
	filesB := []testFile{
		{"b1.dat", randBytes(t, 4096)},
		{"b2.dat", randBytes(t, 100000)},
		{"b3.dat", []byte("tiny")},
	}
	hA, hB := newTestHandler(filesA), newTestHandler(filesB)
	sa, sb, errA, errB := runLoopback(t, hA, hB, nil, nil, nil, nil)
	defer sa.Close()
	defer sb.Close()
	if errA != nil || errB != nil {
		t.Fatalf("session errors: A=%v B=%v", errA, errB)
	}
	for _, f := range filesA {
		if !bytes.Equal(hB.got(f.name), f.data) {
			t.Errorf("B's copy of %s wrong (%d vs %d bytes)", f.name, len(hB.got(f.name)), len(f.data))
		}
	}
	for _, f := range filesB {
		if !bytes.Equal(hA.got(f.name), f.data) {
			t.Errorf("A's copy of %s wrong", f.name)
		}
	}
	// 3 sent + 3 received per side, all clean.
	for side, h := range map[string]*testHandler{"A": hA, "B": hB} {
		done, errs := h.completions()
		if len(done) != 6 {
			t.Errorf("%s completions = %d, want 6", side, len(done))
		}
		for i, e := range errs {
			if e != nil {
				t.Errorf("%s completion %s: %v", side, done[i].Name, e)
			}
		}
	}
}

func TestLoopbackAsymmetric(t *testing.T) {
	files := []testFile{{"one.bin", randBytes(t, 30000)}, {"two.bin", randBytes(t, 500)}}
	hA, hB := newTestHandler(files), newTestHandler(nil)
	sa, sb, errA, errB := runLoopback(t, hA, hB, nil, nil, nil, nil)
	defer sa.Close()
	defer sb.Close()
	if errA != nil || errB != nil {
		t.Fatalf("session errors: A=%v B=%v", errA, errB)
	}
	for _, f := range files {
		if !bytes.Equal(hB.got(f.name), f.data) {
			t.Errorf("B's copy of %s wrong", f.name)
		}
	}
}

func TestLoopbackEmptyBatch(t *testing.T) {
	hA, hB := newTestHandler(nil), newTestHandler(nil)
	sa, sb, errA, errB := runLoopback(t, hA, hB, nil, nil, nil, nil)
	defer sa.Close()
	defer sb.Close()
	if errA != nil || errB != nil {
		t.Fatalf("session errors: A=%v B=%v", errA, errB)
	}
}

func TestLoopbackZeroSizeFile(t *testing.T) {
	files := []testFile{{"empty.dat", nil}}
	hA, hB := newTestHandler(files), newTestHandler(nil)
	sa, sb, errA, errB := runLoopback(t, hA, hB, nil, nil, nil, nil)
	defer sa.Close()
	defer sb.Close()
	if errA != nil || errB != nil {
		t.Fatalf("session errors: A=%v B=%v", errA, errB)
	}
	if got, ok := hB.received["empty.dat"]; !ok || len(got) != 0 {
		t.Errorf("empty file not delivered: present=%v len=%d", ok, len(got))
	}
}

func TestLoopbackBigFile(t *testing.T) {
	data := randBytes(t, 1<<20)
	hA, hB := newTestHandler([]testFile{{"big.bin", data}}), newTestHandler(nil)
	sa, sb, errA, errB := runLoopback(t, hA, hB, nil, nil, nil, nil)
	defer sa.Close()
	defer sb.Close()
	if errA != nil || errB != nil {
		t.Fatalf("session errors: A=%v B=%v", errA, errB)
	}
	if !bytes.Equal(hB.got("big.bin"), data) {
		t.Error("1 MiB file corrupted in transit")
	}
}

func TestLoopbackSkipAndDefer(t *testing.T) {
	files := []testFile{
		{"keep.dat", randBytes(t, 2000)},
		{"skipme.dat", randBytes(t, 2000)},
		{"deferme.dat", randBytes(t, 2000)},
	}
	hA, hB := newTestHandler(files), newTestHandler(nil)
	hB.skip["skipme.dat"] = true
	hB.deferFiles["deferme.dat"] = true
	sa, sb, errA, errB := runLoopback(t, hA, hB, nil, nil, nil, nil)
	defer sa.Close()
	defer sb.Close()
	if errA != nil || errB != nil {
		t.Fatalf("session errors: A=%v B=%v", errA, errB)
	}
	if !bytes.Equal(hB.got("keep.dat"), files[0].data) {
		t.Error("keep.dat corrupted")
	}
	if _, ok := hB.received["skipme.dat"]; ok {
		t.Error("skipme.dat transferred despite skip")
	}

	// Sender-side outcomes: FINFOACK -1 ("already have it") surfaces as
	// ErrSkip so the app can tell it from a real transfer; -2 as
	// ErrDefer.
	done, errs := hA.completions()
	outcome := map[string]error{}
	for i, info := range done {
		outcome[info.Name] = errs[i]
	}
	if outcome["keep.dat"] != nil {
		t.Errorf("keep.dat: %v", outcome["keep.dat"])
	}
	if !errors.Is(outcome["skipme.dat"], ErrSkip) {
		t.Errorf("skipme.dat sender outcome: %v, want ErrSkip", outcome["skipme.dat"])
	}
	if !errors.Is(outcome["deferme.dat"], ErrDefer) {
		t.Errorf("deferme.dat sender outcome: %v, want ErrDefer", outcome["deferme.dat"])
	}
}

func TestLoopbackResume(t *testing.T) {
	data := randBytes(t, 50000)
	hA, hB := newTestHandler([]testFile{{"resume.bin", data}}), newTestHandler(nil)
	// B already has the first 20000 bytes.
	hB.received["resume.bin"] = append([]byte(nil), data[:20000]...)
	hB.resumeFrom["resume.bin"] = 20000
	sa, sb, errA, errB := runLoopback(t, hA, hB, nil, nil, nil, nil)
	defer sa.Close()
	defer sb.Close()
	if errA != nil || errB != nil {
		t.Fatalf("session errors: A=%v B=%v", errA, errB)
	}
	if !bytes.Equal(hB.got("resume.bin"), data) {
		t.Error("resumed file corrupted")
	}
}

func TestLoopbackSlidingWindow(t *testing.T) {
	data := randBytes(t, 200000)
	hA, hB := newTestHandler([]testFile{{"win.bin", data}}), newTestHandler(nil)
	cfgB := testConfig(false)
	cfgB.RxWindowBytes = 8192 // B demands DATAACK flow from itself, throttling A
	sa, sb, errA, errB := runLoopback(t, hA, hB, nil, nil, nil, cfgB)
	defer sa.Close()
	defer sb.Close()
	if errA != nil || errB != nil {
		t.Fatalf("session errors: A=%v B=%v", errA, errB)
	}
	if !bytes.Equal(hB.got("win.bin"), data) {
		t.Error("windowed transfer corrupted")
	}
}

type recordingDev struct {
	mu   sync.Mutex
	msgs []string
}

func (d *recordingDev) OnDeviceData(device string, payload []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.msgs = append(d.msgs, device+":"+string(payload))
}

func TestLoopbackDeviceChannel(t *testing.T) {
	hA := newTestHandler([]testFile{{"f.dat", randBytes(t, 30000)}})
	hB := newTestHandler(nil)
	devB := &recordingDev{}
	connA, connB := net.Pipe()
	sa := NewSession(connA, hA, hA, nil, testConfig(true))
	sb := NewSession(connB, hB, hB, devB, testConfig(false))
	defer sa.Close()
	defer sb.Close()

	if err := sa.SendDevice("CON", []byte("hello from A")); err != nil {
		t.Fatalf("SendDevice: %v", err)
	}
	errA, errB := runBoth(t, sa, sb)
	if errA != nil || errB != nil {
		t.Fatalf("session errors: A=%v B=%v", errA, errB)
	}
	devB.mu.Lock()
	defer devB.mu.Unlock()
	if len(devB.msgs) != 1 || devB.msgs[0] != "CON:hello from A" {
		t.Errorf("device messages = %q", devB.msgs)
	}
}

// A nil SendHandler is an immediately-empty TX batch; a nil RecvHandler
// defers every offer with FINFOACK(-2). Both at once must still
// complete a clean batch, and the offering side must see ErrDefer (its
// files stay queued — the non-destructive refusal).
func TestLoopbackNilHandlers(t *testing.T) {
	files := []testFile{{"undeliverable.dat", randBytes(t, 3000)}}
	hA := newTestHandler(files)
	connA, connB := net.Pipe()
	sa := NewSession(connA, hA, nil, nil, testConfig(true))
	sb := NewSession(connB, nil, nil, nil, testConfig(false))
	defer sa.Close()
	defer sb.Close()
	if errA, errB := runBoth(t, sa, sb); errA != nil || errB != nil {
		t.Fatalf("session errors: A=%v B=%v", errA, errB)
	}
	done, errs := hA.completions()
	if len(done) != 1 || done[0].Name != "undeliverable.dat" {
		t.Fatalf("completions = %v, want exactly undeliverable.dat", done)
	}
	if !errors.Is(errs[0], ErrDefer) {
		t.Errorf("nil-recv peer outcome = %v, want ErrDefer", errs[0])
	}
}

// closeCounter wraps an offer's Close hook and counts invocations.
type closeCounter struct{ n atomic.Int32 }

func (c *closeCounter) hook() func() error {
	return func() error { c.n.Add(1); return nil }
}

// FileOffer.Close must fire exactly once per offered file, on every
// outcome: transferred, skipped by the peer, deferred by the peer.
func TestLoopbackOfferCloseOutcomes(t *testing.T) {
	files := []testFile{
		{"sent.dat", randBytes(t, 2000)},
		{"skipme.dat", randBytes(t, 2000)},
		{"deferme.dat", randBytes(t, 2000)},
	}
	hA, hB := newTestHandler(files), newTestHandler(nil)
	hB.skip["skipme.dat"] = true
	hB.deferFiles["deferme.dat"] = true
	counters := make(map[string]*closeCounter)
	for _, o := range hA.pending {
		c := &closeCounter{}
		counters[o.Name] = c
		o.Close = c.hook()
	}
	sa, sb, errA, errB := runLoopback(t, hA, hB, nil, nil, nil, nil)
	defer sa.Close()
	defer sb.Close()
	if errA != nil || errB != nil {
		t.Fatalf("session errors: A=%v B=%v", errA, errB)
	}
	for name, c := range counters {
		if got := c.n.Load(); got != 1 {
			t.Errorf("%s: Close fired %d times, want 1", name, got)
		}
	}
}

// FileOffer.Close must also fire exactly once when the batch tears down
// with the file still in flight.
func TestLoopbackOfferCloseOnTeardown(t *testing.T) {
	hA := newTestHandler([]testFile{{"inflight.dat", randBytes(t, 500000)}})
	c := &closeCounter{}
	hA.pending[0].Close = c.hook()
	hB := newTestHandler(nil)
	connA, connB := net.Pipe()
	sa := NewSession(connA, hA, hA, nil, testConfig(true))
	sb := NewSession(connB, hB, hB, nil, testConfig(false))
	defer sa.Close()
	defer sb.Close()

	var wg sync.WaitGroup
	wg.Add(2)
	var errA, errB error
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	go func() { defer wg.Done(); errA = sa.Run(ctx) }()
	go func() { defer wg.Done(); errB = sb.Run(ctx) }()
	// Kill the receiving side once the transfer is under way.
	for {
		hA.mu.Lock()
		started := len(hA.pending) == 0
		hA.mu.Unlock()
		if started {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	_ = sb.Abort()
	wg.Wait()
	if errA == nil && errB == nil {
		t.Fatal("expected at least one side to error after Abort")
	}
	if got := c.n.Load(); got != 1 {
		t.Errorf("Close fired %d times on teardown, want 1", got)
	}
	done, _ := hA.completions()
	if len(done) != 1 {
		t.Errorf("completions = %d, want exactly 1 for the in-flight file", len(done))
	}
}

// bforce runs two batches per connection; Run must be callable again
// after a clean batch on the same transport.
func TestLoopbackSecondBatch(t *testing.T) {
	first := []testFile{{"batch1.dat", randBytes(t, 5000)}}
	second := []testFile{{"batch2.dat", randBytes(t, 7000)}}
	hA, hB := newTestHandler(first), newTestHandler(nil)
	connA, connB := net.Pipe()
	sa := NewSession(connA, hA, hA, nil, testConfig(true))
	sb := NewSession(connB, hB, hB, nil, testConfig(false))
	defer sa.Close()
	defer sb.Close()

	if errA, errB := runBoth(t, sa, sb); errA != nil || errB != nil {
		t.Fatalf("batch 1: A=%v B=%v", errA, errB)
	}
	// Refill A's queue for batch 2.
	hA.mu.Lock()
	for _, f := range second {
		hA.pending = append(hA.pending, &FileOffer{
			Name: f.name, Size: int64(len(f.data)),
			ModTime: time.Unix(1700000000, 0), Reader: bytes.NewReader(f.data),
		})
	}
	hA.mu.Unlock()
	if errA, errB := runBoth(t, sa, sb); errA != nil || errB != nil {
		t.Fatalf("batch 2: A=%v B=%v", errA, errB)
	}
	if !bytes.Equal(hB.got("batch1.dat"), first[0].data) ||
		!bytes.Equal(hB.got("batch2.dat"), second[0].data) {
		t.Error("two-batch transfer corrupted")
	}
}
