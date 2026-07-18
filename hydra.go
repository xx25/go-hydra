// Package hydra is a pure-Go implementation of the HYDRA bidirectional
// file transfer protocol (FTSC FSC-0072). See SPEC.md for the wire-format
// details and the compatibility strategy.
package hydra

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"time"
)

// Public sentinel errors.
var (
	// ErrSkip is returned by RecvHandler.AcceptFile to refuse a single
	// incoming file. The library answers FINFOACK(-1) ("already have it")
	// on the wire; the batch continues with the next FINFO.
	ErrSkip = errors.New("hydra: skip file")

	// ErrDefer is returned by RecvHandler.AcceptFile to refuse a file for
	// now. The library answers FINFOACK(-2) ("try again in a later
	// batch"); the batch continues.
	ErrDefer = errors.New("hydra: defer file")

	// ErrTransportNotClosable is returned by Session.Run when neither the
	// transport implements io.Closer nor Config.Closer is supplied.
	// Returned before any goroutine is spawned and before the transport
	// is touched, so the caller still owns the transport.
	ErrTransportNotClosable = errors.New("hydra: transport is not closable")

	// ErrFileTooLarge is delivered to FileCompleted (send side when a
	// FileOffer.Size exceeds SafeMaxOffset, receive side when a peer
	// announces such a size). The file never transfers — Hydra's offset
	// fields are 32-bit signed.
	ErrFileTooLarge = errors.New("hydra: file size exceeds 0x7FFFFFFE")

	// ErrBrainDead is returned by Run when the brain-dead watchdog
	// expires (no protocol forward progress for Config.BrainDead).
	ErrBrainDead = errors.New("hydra: brain_dead timeout (no progress)")

	// ErrSessionAborted is returned by Run after Abort, or when the peer
	// signals the out-of-band cancel sequence.
	ErrSessionAborted = errors.New("hydra: session aborted")

	// ErrPeerCancel is returned by Run when the peer sent the DLE cancel
	// sequence (SPEC §2.4).
	ErrPeerCancel = errors.New("hydra: peer sent cancel sequence")

	// ErrMaxRetries is returned by Run when a supervisory packet
	// (START, INIT, FINFO, EOF, END) exceeded Config.MaxRetries
	// retransmissions without an acknowledgement.
	ErrMaxRetries = errors.New("hydra: retransmit limit exceeded")

	// ErrHandlerContract is delivered to FileCompleted when
	// RecvHandler.AcceptFile returns (nil, _, nil) — a handler must
	// return either a non-nil io.WriteCloser or a non-nil error — or
	// when a FileOffer carries a nil Reader.
	ErrHandlerContract = errors.New("hydra: handler returned nil writer with nil error")

	// ErrDevUnsupported is returned by Session.SendDevice when the peer
	// did not negotiate the DEV capability.
	ErrDevUnsupported = errors.New("hydra: peer does not support device data")

	// ErrIncompatible is returned by Run when capability negotiation
	// leaves a vital escape flag unsatisfied — the link cannot be made
	// byte-safe (HydraCom's "Incompatible on this link" abort).
	ErrIncompatible = errors.New("hydra: incompatible capabilities")

	// ErrResumeOutOfRange is delivered to FileCompleted when
	// RecvHandler.AcceptFile returns a resume offset outside
	// [0, announced size]. The library answers FINFOACK(-2); the batch
	// continues.
	ErrResumeOutOfRange = errors.New("hydra: resume offset out of range")

	// ErrSenderSkip is delivered to RecvHandler.FileCompleted when the
	// sender abandoned the file mid-transfer (EOF with a negative
	// offset).
	ErrSenderSkip = errors.New("hydra: sender skipped file")

	// ErrRunActive is returned by Run when another Run on the same
	// Session has not returned yet.
	ErrRunActive = errors.New("hydra: session Run already active")

	// ErrSessionClosed is returned by Run after Close.
	ErrSessionClosed = errors.New("hydra: session closed")

	// ErrDevBusy is returned by SendDevice when the outbound device
	// queue is full. SendDevice never blocks — it may be called from
	// handler callbacks, which run on the session's event loop.
	ErrDevBusy = errors.New("hydra: device queue full")
)

// FileOffer describes one file the local side wants to send. Reader
// provides the data; if it also implements io.ReadSeeker the library can
// honour resume offsets and RPOS repositioning, otherwise a mid-file
// reposition fails the file.
type FileOffer struct {
	Name    string    // short filename, no path components
	Path    string    // optional full path sent when FPT is negotiated
	Size    int64     // bytes; must be known (Hydra announces it)
	ModTime time.Time // zero means "unknown" (0 on the wire)
	Reader  io.Reader

	// Close, if non-nil, is called exactly once per offered file: when
	// the file's transfer completes (any outcome — sent, skipped,
	// deferred, failed) or when the batch tears down with the file still
	// in flight, whichever comes first. It releases whatever resource
	// backs Reader; its error is not propagated.
	Close func() error
}

// FileInfo describes an incoming file (parsed from FINFO).
type FileInfo struct {
	Name    string    // short filename as sent by the peer — UNTRUSTED
	Path    string    // full path if the peer sent one (FPT) — UNTRUSTED
	Size    int64     // announced size; 0 means unknown
	ModTime time.Time // zero if the peer sent no timestamp
	// FileNum and FileTotal mirror the FINFO file-count field: on the
	// first file of a batch the peer announces the total; on subsequent
	// files their ordinal (≥2). 0 = unknown. Advisory only (SPEC §3.4).
	FileNum   int
	FileTotal int
}

// SendHandler is the application callback interface for the transmit
// half of the session. Hydra runs both directions concurrently, so the
// send and receive callbacks are separate interfaces — an identically
// named file can be in flight in both directions at once, and each
// side's FileProgress/FileCompleted must be unambiguous. One object may
// implement both interfaces and be passed as both arguments (the
// per-direction method sets do not collide).
type SendHandler interface {
	// NextFile returns the next file to send, or nil when the local TX
	// batch is finished. Called repeatedly until it returns nil — at
	// that point the library emits the end-of-batch FINFO.
	NextFile() *FileOffer

	// FileProgress is called periodically during transmission with the
	// current byte count. No cadence guarantee.
	FileProgress(info FileInfo, bytesTransferred int64)

	// FileCompleted is invoked exactly once per offered file when its
	// transfer ends. err is nil on success; ErrSkip = the receiver
	// answered "already have it" (delivered as far as the wire is
	// concerned); ErrDefer = the receiver deferred the file to a later
	// batch. The offer's Close hook has already run when this fires.
	FileCompleted(info FileInfo, bytesTransferred int64, err error)
}

// RecvHandler is the application callback interface for the receive
// half of the session.
type RecvHandler interface {
	// AcceptFile is invoked for every incoming file. The handler returns
	//
	//	(writer, offset, nil)      -- accept, resume at offset
	//	(nil,    0,      ErrSkip)  -- refuse: already have it (FINFOACK -1;
	//	                              the SENDER counts the file delivered)
	//	(nil,    0,      ErrDefer) -- refuse for now          (FINFOACK -2)
	//	(_,      _,      err)      -- refuse with a custom error (FINFOACK -2)
	//
	// SECURITY: incoming filenames are untrusted. Call SanitizeFilename
	// before using info.Name as a path component.
	AcceptFile(info FileInfo) (io.WriteCloser, int64, error)

	// FileProgress is called periodically during reception with the
	// current byte count. No cadence guarantee.
	FileProgress(info FileInfo, bytesTransferred int64)

	// FileCompleted is invoked exactly once per incoming file when its
	// transfer ends. err is the write-time or protocol error, nil on
	// success. The writer has been Closed before this fires.
	FileCompleted(info FileInfo, bytesTransferred int64, err error)
}

// noSend is the nil-SendHandler stand-in: an immediately empty TX batch.
type noSend struct{}

func (noSend) NextFile() *FileOffer                { return nil }
func (noSend) FileProgress(FileInfo, int64)        {}
func (noSend) FileCompleted(FileInfo, int64, error) {}

// noRecv is the nil-RecvHandler stand-in: every incoming file is
// deferred with FINFOACK(-2), the non-destructive refusal — the peer
// keeps its files queued rather than marking them delivered.
type noRecv struct{}

func (noRecv) AcceptFile(FileInfo) (io.WriteCloser, int64, error) { return nil, 0, ErrDefer }
func (noRecv) FileProgress(FileInfo, int64)                       {}
func (noRecv) FileCompleted(FileInfo, int64, error)               {}

// DeviceHandler receives device-channel datagrams (SPEC §3.13). Optional:
// pass nil to NewSession and incoming DEVDATA is acknowledged and dropped.
type DeviceHandler interface {
	// OnDeviceData delivers one datagram. device is the peer's 3-char
	// channel name ("CON" chat, "MSG" protocol messages, or custom).
	OnDeviceData(device string, payload []byte)
}

// Config controls Session behaviour. nil selects defaults.
type Config struct {
	// Originator is true on the side that initiated the connection
	// (FidoNet convention: the caller). Controls the HDXLINK one-way
	// fallback, which only ever triggers on the answerer (SPEC §4.2).
	Originator bool

	// EffectiveBaud feeds the timer and block-size defaults. 0 means a
	// fast reliable link (TCP): 10 s timeout, 2048-byte max blocks.
	EffectiveBaud int

	// AppID is the identification string sent in INIT. Default
	// "2b1aab00gohydra,<version>" (H_REVSTAMP prefix per SPEC §13.1).
	AppID string

	// Supported overrides the advertised capability codes. Default:
	// XON,TLN,CTL,HIC,HI8,C32,DEV,FPT. Codes we cannot honour
	// (ASC, UUE) are stripped.
	Supported []string

	// Desired overrides the requested capability codes. Default: FPT
	// only — escape flags (XON/TLN/CTL/HIC/HI8) are for dirty serial
	// links and cost throughput, so they activate only when a side
	// asks; C32 and DEV activate on mutual support regardless
	// (HydraCom's union rule, SPEC §5 as corrected).
	Desired []string

	// TxWindowBytes / RxWindowBytes advertise sliding-window limits in
	// the INIT packet. 0 (the default) means full streaming, which is
	// what every modern peer expects on reliable transports (SPEC §13.1).
	TxWindowBytes int
	RxWindowBytes int

	// Timeout governs supervisory-packet ack waits. Default
	// max(10 s, min(60 s, 40960/baud)).
	Timeout time.Duration

	// BrainDead is the no-progress watchdog. Default 120 s. Reset rules
	// per SPEC §7 — deliberately narrow.
	BrainDead time.Duration

	// MaxRetries caps consecutive retransmits of one supervisory packet.
	// Default 10.
	MaxRetries int

	// MaxBlockSize caps the DATA block payload. Default and maximum 2048.
	MaxBlockSize int

	// Closer, if non-nil, is closed during Run shutdown to unblock the
	// reader goroutine on transports whose Read cannot otherwise be
	// interrupted. If nil, the library type-asserts the transport for
	// io.Closer; if neither is reachable, Run returns
	// ErrTransportNotClosable at startup.
	Closer io.Closer

	// Logger, if non-nil, receives a Debug record per decoded protocol
	// packet in both directions (type, payload length, offset where the
	// packet carries one), so protocol frames can interleave with a
	// transport-level byte trace. The HYDRA_TRACE=1 stderr trace remains
	// available as a zero-config fallback.
	Logger *slog.Logger

	// idleOverride shortens the 20 s IDLE emission interval in tests.
	idleOverride time.Duration
}

func (c *Config) defaults() *Config {
	out := &Config{}
	if c != nil {
		*out = *c
	}
	c = out
	if c.AppID == "" {
		c.AppID = fmt.Sprintf("%08xgohydra,0.1", uint32(hydraRevstamp))
	}
	if c.MaxBlockSize <= 0 || c.MaxBlockSize > DataBufMax {
		c.MaxBlockSize = DataBufMax
	}
	if c.MaxRetries <= 0 {
		c.MaxRetries = defaultMaxRetries
	}
	if c.BrainDead <= 0 {
		c.BrainDead = defaultBrainDead
	}
	if c.Timeout <= 0 {
		t := defaultTimeout
		if c.EffectiveBaud > 0 {
			calc := time.Duration(40960/c.EffectiveBaud) * time.Second
			if calc > t {
				t = calc
			}
			if t > maxTimeout {
				t = maxTimeout
			}
		}
		c.Timeout = t
	}
	if c.TxWindowBytes < 0 {
		c.TxWindowBytes = 0
	}
	if c.RxWindowBytes < 0 {
		c.RxWindowBytes = 0
	}
	return c
}

// localSupported resolves the advertised capability set. User-supplied
// lists are filtered down to what the library can actually honour.
func (c *Config) localSupported() uint32 {
	caps := capDefaultSupported
	if len(c.Supported) > 0 {
		caps = parseCaps(strings.Join(c.Supported, ","))
	}
	// Never advertise encodings we only decode.
	return caps &^ (capASC | capUUE)
}

func (c *Config) localDesired() uint32 {
	if len(c.Desired) > 0 {
		return parseCaps(strings.Join(c.Desired, ",")) &^ (capASC | capUUE)
	}
	return capFPT
}

// SanitizeFilename strips path components from a peer-provided filename so
// it is safe to pass to os.Create in the current working directory:
//
//   - filepath.Base on the raw name (strips any directory path)
//   - NUL bytes and separators inside the base are replaced with "_"
//   - "" / "." / ".." become "_"
//
// Intentionally aggressive — applications needing richer destination-path
// policy (e.g. honouring FPT paths) should implement their own.
func SanitizeFilename(name string) string {
	// Normalise Windows-style separators so filepath.Base on Linux also
	// strips them.
	name = strings.ReplaceAll(name, "\\", "/")
	name = filepath.Base(name)
	name = strings.ReplaceAll(name, "\x00", "_")
	if name == "" || name == "." || name == ".." {
		return "_"
	}
	return name
}
