package hydra

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// Session is one Hydra conversation over a transport. Create via
// NewSession, drive via Run — once per batch. A batch is one full
// START/INIT … END cycle; mailers habitually run several per connection
// (bforce always runs two), so Run leaves the transport open after a
// clean batch and may be called again. Close releases the transport when
// the caller is done; Abort tears down mid-batch.
type Session struct {
	config    *Config
	send      SendHandler
	recv      RecvHandler
	dev       DeviceHandler
	transport io.ReadWriter
	closer    io.Closer

	writer *transportWriter
	reader *transportReader

	// rxOpts feeds the reader goroutine the active RX option set:
	// capAssumed before negotiation, the effective set after.
	rxOpts atomic.Uint32

	// effOpts mirrors the negotiated set for API queries (SendDevice).
	effOpts    atomic.Uint32
	negotiated atomic.Bool

	inbox   *pktInbox
	readErr chan error
	devQ    chan devRequest

	abortCh   chan struct{}
	abortOnce sync.Once
	closeOnce sync.Once
	err       error
	errOnce   sync.Once

	started     bool
	writerReady atomic.Bool
	runActive   atomic.Bool

	// readerStarted/readerDone let Close join the reader goroutine.
	// Close is the teardown barrier: callers (e.g. a transfer driver
	// that un-blocks the reader by poking an expired read deadline
	// through the transport's Close, then re-arms the deadline for
	// whoever uses the conn next) need the reader to be GONE before
	// they touch the transport again — otherwise the re-arm can land
	// before the parked reader observes the poke, re-blocking it
	// forever on a transport whose reads only fail via deadline.
	readerStarted atomic.Bool
	readerDone    chan struct{} // closed when readerLoop exits
}

// cancelGraceTimeout bounds how long teardown waits for the courtesy
// cancel sequence to flush before closing the transport regardless.
const cancelGraceTimeout = 250 * time.Millisecond

// readerJoinTimeout bounds how long Close waits for the reader
// goroutine to exit after the transport is closed. On a deadline-capable
// transport the reader unparks within one poll tick (≤50 ms); the cap
// only matters on a transport whose Close cannot unblock a read at all,
// where waiting longer would wedge teardown for nothing (that case
// keeps the pre-join behaviour: the reader parks until the session
// owner really closes the conn).
const readerJoinTimeout = time.Second

type devRequest struct {
	device  string
	payload []byte
}

// pktInbox is the elastic reader→event-loop queue. It must never block
// the reader: HydraCom's cooperative loop keeps consuming input even
// while its output buffer is full (com_outfull), and a bounded channel
// here recreates the classic bidirectional deadlock — both event loops
// stuck in a blocking write, both readers stuck on a full channel. With
// an elastic inbox the readers always drain, so peer writes always
// complete and the loops always progress. Growth is bounded in practice
// by what the peer can put in flight during one of our writes.
type pktInbox struct {
	mu  sync.Mutex
	q   []packet
	sig chan struct{} // cap 1: "inbox non-empty" edge signal
}

// inboxCap bounds the queue against a hostile flood while the event
// loop sits in a slow handler callback. Orders of magnitude above any
// legitimate in-flight backlog; overflow aborts the session.
const inboxCap = 4096

var errInboxOverflow = errors.New("hydra: inbound packet queue overflow")

func newPktInbox() *pktInbox {
	return &pktInbox{sig: make(chan struct{}, 1)}
}

// push enqueues without ever blocking. Reports false on overflow.
func (in *pktInbox) push(p packet) bool {
	in.mu.Lock()
	if len(in.q) >= inboxCap {
		in.mu.Unlock()
		return false
	}
	in.q = append(in.q, p)
	in.mu.Unlock()
	select {
	case in.sig <- struct{}{}:
	default:
	}
	return true
}

// reset discards everything queued. Called between batches: whatever
// sits in the inbox when a new Run starts is tail traffic of the
// previous batch (trailing ENDs, IDLEs, DEVDATA) and must not be
// interpreted under the fresh batch's context — devRx in particular is
// deliberately ungated (HydraCom fidelity) and would otherwise ack a
// stale datagram before negotiation. A peer's new-batch START racing
// the reset is retransmitted every 5 s, so dropping it is harmless.
// The sig token is left alone: a stale token only causes one empty
// drain, while clearing it could eat a concurrent push's wakeup.
func (in *pktInbox) reset() {
	in.mu.Lock()
	in.q = nil
	in.mu.Unlock()
}

// kick re-arms the non-empty signal (used when a bounded drain leaves
// items queued).
func (in *pktInbox) kick() {
	select {
	case in.sig <- struct{}{}:
	default:
	}
}

func (in *pktInbox) tryPop() (packet, bool) {
	in.mu.Lock()
	defer in.mu.Unlock()
	if len(in.q) == 0 {
		return packet{}, false
	}
	p := in.q[0]
	in.q = in.q[1:]
	return p, true
}

// NewSession constructs a Session. Either handler may be nil: a nil
// send means the local TX batch is immediately empty (end-of-batch
// FINFO right after negotiation); a nil recv defers every incoming file
// with FINFOACK(-2), so a receive-less side never marks peer files
// delivered. One object implementing both interfaces may be passed as
// both arguments. dev may be nil — incoming DEVDATA is then
// acknowledged and dropped. cfg may be nil for defaults.
//
// The transport must be closable: either it implements io.Closer or
// cfg.Closer is set; Run refuses to start otherwise. It is closed on
// error, on Abort, and by Close — but NOT after a clean batch, so
// another Run (next batch) can follow.
func NewSession(transport io.ReadWriter, send SendHandler, recv RecvHandler, dev DeviceHandler, cfg *Config) *Session {
	if send == nil {
		send = noSend{}
	}
	if recv == nil {
		recv = noRecv{}
	}
	return &Session{
		config:     cfg.defaults(),
		send:       send,
		recv:       recv,
		dev:        dev,
		transport:  transport,
		inbox:      newPktInbox(),
		readErr:    make(chan error, 1),
		devQ:       make(chan devRequest, 8),
		abortCh:    make(chan struct{}),
		readerDone: make(chan struct{}),
	}
}

// Run drives one complete batch: autostart/START handshake, INIT
// negotiation, bidirectional file transfer, END exchange. It returns nil
// on a clean batch (transport still open, Run may be called again) or
// the terminal error (transport closed).
//
// Handler callbacks are invoked from Run's goroutine.
//
// Limitation: ctx cancellation is observed between transport writes. If
// the transport's Write blocks indefinitely (peer stopped reading and
// the transport buffers filled), only Abort or Close — which close the
// transport — can interrupt it.
func (s *Session) Run(ctx context.Context) error {
	if !s.runActive.CompareAndSwap(false, true) {
		return ErrRunActive
	}
	defer s.runActive.Store(false)

	if s.config.Closer != nil {
		s.closer = s.config.Closer
	} else if cl, ok := s.transport.(io.Closer); ok {
		s.closer = cl
	} else {
		return ErrTransportNotClosable
	}

	select {
	case <-s.abortCh:
		return s.err
	default:
	}

	if !s.started {
		s.started = true
		s.writer = newTransportWriter(s.transport)
		s.rxOpts.Store(capAssumed)
		s.reader = newTransportReader(s.transport, &s.rxOpts)
		s.writerReady.Store(true)
		s.readerStarted.Store(true)
		go func() {
			defer close(s.readerDone)
			s.readerLoop()
		}()
	}

	// Fresh batch: negotiation state resets, the assumed RX options
	// apply again (multi-batch peers renegotiate every batch).
	// negotiated flips first so a concurrent SendDevice never pairs a
	// stale "negotiated" with a cleared option set. Stale inbound
	// packets from the previous batch's tail are discarded (devQ is
	// kept — queued SendDevice datagrams are user intent, not wire
	// residue).
	s.negotiated.Store(false)
	s.effOpts.Store(0)
	s.rxOpts.Store(capAssumed)
	s.inbox.reset()

	b := newBatch(s)
	err := b.run(ctx)
	if err != nil && b.endPhaseHangup(err) {
		// The peer vanished during the END courtesy exchange, after
		// both directions' transfers had fully completed. FSC-0072
		// counts END retry exhaustion as success ("the transfers
		// completed; the peer just left") — a transport error there is
		// the same event observed sooner. The next Run on this
		// session fails fast on the dead transport, which multi-batch
		// callers already classify as the peer being done.
		err = nil
	}
	if err != nil {
		s.recordError(err)
		s.triggerAbort()
		// Best-effort courtesy cancel unless the peer is already gone;
		// bounded so a stalled peer cannot keep Run from closing.
		if !errors.Is(err, ErrPeerCancel) && !isTransportErr(err) {
			s.courtesyCancel()
		}
		s.close()
		return s.err
	}
	return nil
}

// Abort tears the session down from any goroutine: records
// ErrSessionAborted, emits the cancel sequence (best-effort, bounded),
// and closes the transport (which also unblocks the reader and any
// stalled write). The active Run returns the error.
func (s *Session) Abort() error {
	s.recordError(ErrSessionAborted)
	s.triggerAbort()
	s.courtesyCancel()
	s.close()
	return nil
}

// courtesyCancel tries to put the 8×DLE+10×BS cancel sequence on the
// wire without ever wedging the teardown: a stalled transport (peer
// stopped reading) must not keep Abort or an errored Run from reaching
// close(), which is the only thing that unblocks a stuck write.
func (s *Session) courtesyCancel() {
	if !s.writerReady.Load() {
		return
	}
	done := make(chan struct{})
	go func() {
		_ = s.writer.writeCancel()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(cancelGraceTimeout):
		// The pending write errors out once close() lands; the
		// goroutine exits then.
	}
}

// Close releases the transport. Call after the final batch. Safe to call
// multiple times and alongside Abort. A Run attempted after Close
// returns ErrSessionClosed.
//
// Close is the teardown BARRIER: it does not return until the reader
// goroutine has exited (bounded by readerJoinTimeout). Callers may
// therefore re-arm transport deadlines or reuse the conn immediately
// after Close without racing a still-parked reader — the property
// transfer drivers rely on when their transport "Close" is really a
// deadline poke on a conn they must hand back usable.
func (s *Session) Close() error {
	s.recordError(ErrSessionClosed)
	s.triggerAbort()
	s.close()
	if s.readerStarted.Load() {
		select {
		case <-s.readerDone:
		case <-time.After(readerJoinTimeout):
			// Transport whose Close cannot unblock a read (no deadline
			// support, nothing actually closed): don't wedge teardown —
			// the reader parks until the session owner closes the conn
			// for real, exactly the pre-join behaviour.
		}
	}
	return nil
}

// SendDevice queues one device-channel datagram (SPEC §3.13). device
// should be a 3-character name ("CON" for chat). Returns
// ErrDevUnsupported once negotiation has shown the peer lacks DEV;
// before negotiation the datagram is queued optimistically and dropped
// later if DEV does not activate. Payloads are clamped to DataBufMax.
//
// Non-blocking: a full queue returns ErrDevBusy immediately. It must —
// handler callbacks run on the session's event loop, and a blocking
// send from inside one would deadlock the session.
func (s *Session) SendDevice(device string, payload []byte) error {
	if s.negotiated.Load() && s.effOpts.Load()&capDEV == 0 {
		return ErrDevUnsupported
	}
	if len(payload) > DataBufMax {
		payload = payload[:DataBufMax]
	}
	req := devRequest{device: device, payload: append([]byte(nil), payload...)}
	select {
	case <-s.abortCh:
		return ErrSessionAborted
	default:
	}
	select {
	case s.devQ <- req:
		return nil
	default:
		return ErrDevBusy
	}
}

func (s *Session) readerLoop() {
	for {
		pkt, err := s.reader.readPacket()
		if err != nil {
			select {
			case s.readErr <- err:
			default:
			}
			return
		}
		if !s.inbox.push(pkt) {
			select {
			case s.readErr <- errInboxOverflow:
			default:
			}
			return
		}
	}
}

func (s *Session) recordError(err error) {
	if err == nil {
		return
	}
	s.errOnce.Do(func() { s.err = err })
}

func (s *Session) triggerAbort() {
	s.abortOnce.Do(func() { close(s.abortCh) })
}

func (s *Session) close() {
	s.closeOnce.Do(func() {
		if s.closer != nil {
			_ = s.closer.Close()
		}
	})
}

func isTransportErr(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, io.ErrClosedPipe) ||
		errors.Is(err, syscall.EPIPE) || errors.Is(err, syscall.ECONNRESET)
}

// endPhaseHangup reports whether a batch error is a peer hangup
// arriving after all transfer work was done — the TX machine had
// entered the END exchange, which the sync gate only permits once the
// RX machine and the device queue are finished too. Only the END
// courtesies remained, and those are best-effort by specification.
func (b *batch) endPhaseHangup(err error) bool {
	return b.txState >= htxEnd && b.rxState == hrxDone && isTransportErr(err)
}

// --- batch ------------------------------------------------------------------

// txState mirrors HydraCom's HTX_* cursor (hydra.h:84-99). Relative
// order matters: several rules are range checks (IDLE braindead reset in
// [htxFinfo, htxRend), DEV send gate in (htxRinit, htxEnd), HDX trigger
// below htxRend).
type txState int

const (
	htxStart txState = iota
	htxSwait
	htxInit
	htxInitAck
	htxRinit
	htxFinfo
	htxFinfoAck
	htxXdata
	htxDataAck
	htxXwait
	htxEOF
	htxEOFAck
	htxRend
	htxEnd
	htxEndAck
	htxDone
)

// rxState mirrors HRX_* — only four states exist; the bad-position
// machinery is inline counters, not states (hydra.h:107-110).
type rxState int

const (
	hrxInit rxState = iota
	hrxFinfo
	hrxData
	hrxDone
)

// devState mirrors HTD_*.
type devState int

const (
	htdDone devState = iota
	htdData
	htdDack
)

// batch is the per-batch protocol state: all three state machines, run
// by a single event-loop goroutine exactly like the C reference's
// cooperative loop — no locking between machines.
type batch struct {
	s   *Session
	cfg *Config

	// Negotiated link state.
	opts     uint32
	txWindow int64 // our unacked-bytes limit (peer's rx window merged with cfg)
	rxWindow int64 // our DATAACK duty (peer's tx window merged with cfg)
	prefix   string

	productive bool // txAction wants another pass without blocking

	// Timers: zero time = disarmed.
	txTimer   time.Time
	devTimer  time.Time
	braindead time.Time

	// TX machine.
	txState    txState
	txRetries  int
	txSyncID   uint32
	blk        *blockSizer
	txLastAck  int64
	hdxlink    bool
	txOffer    *FileOffer
	txReader   io.Reader
	txSeeker   io.Seeker
	txInfo     FileInfo
	txPos      int64
	txSkip     bool
	txErr      error
	txEOB      bool
	lastFinfo  []byte
	filesSent  int
	txDataBuf  []byte
	batchEnded bool
	// finfoAckWait / eofAckWait arm when the corresponding packet has
	// actually been sent and disarm on the first matching ack, so
	// duplicate acks (the peer re-acks every FINFO/EOF retransmit)
	// cannot double-complete a file or complete one never announced.
	finfoAckWait bool
	eofAckWait   bool

	// RX machine.
	rxState    rxState
	filesRcvd  int
	// lastRefusedFinfo caches the payload and ack of the most recently
	// refused announcement so a retransmit is re-acked without a second
	// AcceptFile/FileCompleted round.
	lastRefusedFinfo []byte
	lastRefusedAck   int32
	rxWriter   io.WriteCloser
	rxOpen     bool
	rxInfo     FileInfo
	rxPos      int64
	rxRetries  int
	rxSyncID   uint32
	rxLastSync int64
	rxTimer    time.Time
	rxBlkLen   int

	// DEV TX machine.
	devState   devState
	devRetries int
	devTxID    uint32
	devRxID    uint32
	devPending *devDataPkt
	devQueue   []devDataPkt
}

func newBatch(s *Session) *batch {
	cfg := s.config
	initialBlk := 512
	if cfg.EffectiveBaud > 0 && cfg.EffectiveBaud < 2400 {
		initialBlk = 256
	}
	return &batch{
		s:        s,
		cfg:      cfg,
		txState:  htxStart,
		rxState:  hrxInit,
		devState: htdDone,
		blk:      newBlockSizer(cfg.EffectiveBaud, cfg.MaxBlockSize),
		rxBlkLen: initialBlk,
	}
}

// write sends one packet with the current effective options and peer
// prefix.
func (b *batch) write(typ byte, payload []byte) error {
	b.logPkt("tx", typ, payload)
	return b.s.writer.writePacket(typ, payload, b.opts, b.prefix)
}

// logPkt emits the per-packet Debug record on Config.Logger. The four
// offset-bearing BIN types get their leading 4-byte LE offset decoded so
// the trace correlates with file positions.
func (b *batch) logPkt(dir string, typ byte, payload []byte) {
	lg := b.cfg.Logger
	if lg == nil {
		return
	}
	switch typ {
	case pktDATA, pktDATAACK, pktFINFOACK, pktEOF:
		if off, err := parseOffset(payload); err == nil {
			lg.Debug("hydra packet", "dir", dir, "type", string(typ),
				"len", len(payload), "offset", off)
			return
		}
	}
	lg.Debug("hydra packet", "dir", dir, "type", string(typ), "len", len(payload))
}

func (b *batch) feedBraindead() {
	b.braindead = time.Now().Add(b.cfg.BrainDead)
}

// idle returns the IDLE emission interval (20 s on the wire; tests
// shorten it).
func (b *batch) idle() time.Duration {
	if b.cfg.idleOverride > 0 {
		return b.cfg.idleOverride
	}
	return idleInterval
}

// armTx arms the TX timer with the standard first-send/retry split
// (hydra.c: `txretries ? timeout/2 : timeout`).
func (b *batch) armTx() {
	d := b.cfg.Timeout
	if b.txRetries > 0 {
		d /= 2
	}
	b.txTimer = time.Now().Add(d)
}

// traceOn enables the temporary state trace (HYDRA_TRACE=1 go test).
var traceOn = os.Getenv("HYDRA_TRACE") != ""

func (b *batch) trace(format string, args ...any) {
	if !traceOn {
		return
	}
	role := "ANS"
	if b.cfg.Originator {
		role = "ORG"
	}
	fmt.Fprintf(os.Stderr, "[%s tx=%d rx=%d] "+format+"\n",
		append([]any{role, b.txState, b.rxState}, args...)...)
}

// run is the batch event loop.
func (b *batch) run(ctx context.Context) (err error) {
	// The teardown must run on EVERY exit — clean batches have nothing
	// open (no-op), errored ones owe a FileCompleted for in-flight
	// files and a Close on the receive writer.
	defer func() { b.teardown(err) }()
	b.feedBraindead()
	for b.txState != htxDone {
		if err := b.devAction(); err != nil {
			return err
		}
		if err := b.txAction(); err != nil {
			return err
		}
		b.sync()
		if b.txState == htxDone {
			break
		}
		if err := b.pump(ctx); err != nil {
			return err
		}
	}
	return nil
}

// teardown fires FileCompleted for any half-open file when the batch
// ends abnormally, so the exactly-once contract holds. Idempotent via
// the rxOpen flag and the txOffer nil check.
func (b *batch) teardown(err error) {
	if err == nil {
		err = ErrSessionAborted
	}
	b.rxCloseFile(err)
	if b.txOffer != nil {
		closeOffer(b.txOffer)
		b.s.send.FileCompleted(b.txInfo, b.txPos, err)
		b.txOffer = nil
	}
}

// pump waits for and processes events: packets, timer expiry, queued
// device sends, reader errors, abort, ctx cancellation. When txAction
// reported productive work, it only drains without blocking so the TX
// stream keeps flowing.
func (b *batch) pump(ctx context.Context) error {
	// Drain whatever is already queued.
	if err := b.drain(); err != nil {
		return err
	}
	if b.txState == htxDone {
		b.productive = false
		return nil
	}
	if b.productive {
		// Streaming fast path: no blocking, but ctx and timers must
		// not be starved for the length of a 2 GiB send.
		b.productive = false
		if err := ctx.Err(); err != nil {
			return err
		}
		_, err := b.fireTimers(time.Now())
		return err
	}

	now := time.Now()
	if fired, err := b.fireTimers(now); err != nil || fired {
		return err
	}

	var timerC <-chan time.Time
	if d := b.nearestDeadline(); !d.IsZero() {
		tm := time.NewTimer(time.Until(d))
		defer tm.Stop()
		timerC = tm.C
	}
	select {
	case <-b.s.inbox.sig:
		return b.drain()
	case req := <-b.s.devQ:
		b.queueDev(req)
	case <-timerC:
		if _, err := b.fireTimers(time.Now()); err != nil {
			return err
		}
	case rerr := <-b.s.readErr:
		if errors.Is(rerr, ErrPeerCancel) {
			return ErrPeerCancel
		}
		return fmt.Errorf("hydra: transport read: %w", rerr)
	case <-b.s.abortCh:
		if b.s.err != nil {
			return b.s.err
		}
		return ErrSessionAborted
	case <-ctx.Done():
		return ctx.Err()
	}
	return nil
}

// drain processes queued packets and device requests. Bounded per call
// so a sustained inbound stream cannot starve the caller's ctx and
// timer checks — leftovers keep their sig token and the next pump pass
// picks them up immediately.
func (b *batch) drain() error {
	for range 256 {
		if pkt, ok := b.s.inbox.tryPop(); ok {
			if err := b.handlePacket(pkt); err != nil {
				return err
			}
			b.sync()
			continue
		}
		select {
		case req := <-b.s.devQ:
			b.queueDev(req)
			continue
		default:
		}
		return nil
	}
	// Budget exhausted with the queue possibly non-empty: re-arm the
	// signal ourselves, since the token may already have been consumed
	// by the select that led here.
	b.s.inbox.kick()
	return nil
}

func (b *batch) nearestDeadline() time.Time {
	d := b.braindead
	if !b.txTimer.IsZero() && (d.IsZero() || b.txTimer.Before(d)) {
		d = b.txTimer
	}
	if !b.devTimer.IsZero() && (d.IsZero() || b.devTimer.Before(d)) {
		d = b.devTimer
	}
	return d
}

// fireTimers dispatches any expired timers. Returns fired=true when a
// timer acted (so the outer loop re-runs the state actions).
func (b *batch) fireTimers(now time.Time) (bool, error) {
	fired := false
	if !b.braindead.IsZero() && now.After(b.braindead) {
		return true, ErrBrainDead
	}
	if !b.txTimer.IsZero() && now.After(b.txTimer) {
		b.txTimer = time.Time{}
		fired = true
		if err := b.txTimeout(); err != nil {
			return true, err
		}
	}
	if !b.devTimer.IsZero() && now.After(b.devTimer) {
		b.devTimer = time.Time{}
		fired = true
		if err := b.devTimeout(); err != nil {
			return true, err
		}
	}
	return fired, nil
}

// handlePacket is the central dispatch (the C pkttype switch).
func (b *batch) handlePacket(pkt packet) error {
	b.trace("pkt %c len=%d", pkt.typ, len(pkt.payload))
	b.logPkt("rx", pkt.typ, pkt.payload)
	switch pkt.typ {
	case pktSTART:
		if b.txState == htxStart || b.txState == htxSwait {
			b.feedBraindead()
			b.txTimer = time.Time{}
			b.txRetries = 0
			b.txState = htxInit
		}
		return nil
	case pktINIT:
		return b.rxInit(pkt)
	case pktINITACK:
		if b.txState == htxInit || b.txState == htxInitAck {
			b.feedBraindead()
			b.txTimer = time.Time{}
			b.txRetries = 0
			b.txState = htxRinit
		}
		return nil
	case pktFINFO:
		return b.rxFinfo(pkt)
	case pktFINFOACK:
		return b.txFinfoAck(pkt)
	case pktDATA:
		return b.rxData(pkt)
	case pktDATAACK:
		b.txDataAck(pkt)
		return nil
	case pktRPOS:
		return b.txRpos(pkt)
	case pktEOF:
		return b.rxEOF(pkt)
	case pktEOFACK:
		b.txEOFAck()
		return nil
	case pktIDLE:
		b.txIdle()
		return nil
	case pktEND:
		return b.txEnd()
	case pktDEVDATA:
		return b.devRx(pkt)
	case pktDEVDACK:
		b.devDack(pkt)
		return nil
	default:
		// Unknown packet type — tolerate silently (forward compat).
		return nil
	}
}

// sync applies the cross-machine transitions HydraCom runs after each
// packet (hydra.c:1915-1969).
func (b *batch) sync() {
	switch b.txState {
	case htxStart, htxSwait:
		// Peer's INIT can arrive before its START: our RX leaving
		// HRX_INIT is as good as a START.
		if b.rxState != hrxInit {
			b.txTimer = time.Time{}
			b.txRetries = 0
			b.txState = htxInit
		}
	case htxRinit:
		// The sync point: our first FINFO waits until our RX has
		// processed the peer's INIT, guaranteeing both sides flipped
		// CRC/escape modes before any BIN packet flows.
		if b.rxState != hrxInit {
			b.txTimer = time.Time{}
			b.txRetries = 0
			b.txState = htxFinfo
		}
	case htxXdata:
		if b.hdxlink && b.rxState != hrxDone {
			// One-way fallback: pause our TX until the peer's batch
			// completes (answerer only; set in rxData).
			b.txTimer = time.Now().Add(b.idle())
			b.txState = htxXwait
		}
	case htxXwait:
		if b.rxState == hrxDone {
			b.txTimer = time.Time{}
			b.txRetries = 0
			b.txState = htxXdata
		}
	case htxRend:
		if b.rxState == hrxDone && b.devState == htdDone {
			b.txTimer = time.Time{}
			b.txRetries = 0
			b.txState = htxEnd
		}
	}
}

// txTimeout is H_TXTIME (hydra.c:1336-1362): IDLE emission in the two
// idle states, otherwise retry with the per-state fallback map.
func (b *batch) txTimeout() error {
	if b.txState == htxXwait || b.txState == htxRend {
		if err := b.write(pktIDLE, nil); err != nil {
			return err
		}
		b.txTimer = time.Now().Add(b.idle())
		return nil
	}
	b.txRetries++
	if b.txRetries > b.cfg.MaxRetries {
		if b.txState == htxEndAck {
			// Retry exhaustion during the END exchange counts as
			// success — the transfers completed; the peer just left
			// (FSC-0072 prose).
			b.txState = htxDone
			return nil
		}
		return ErrMaxRetries
	}
	switch b.txState {
	case htxSwait:
		b.txState = htxStart
	case htxInitAck:
		b.txState = htxInit
	case htxFinfoAck:
		b.txState = htxFinfo
	case htxDataAck:
		// Push one more block past the window per retry — the
		// anti-deadlock probe (hydra.c:1358).
		b.txState = htxXdata
	case htxEOFAck:
		b.txState = htxEOF
	case htxEndAck:
		b.txState = htxEnd
	}
	return nil
}
