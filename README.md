# hydra

Pure Go implementation of the HYDRA bidirectional file transfer protocol
(FTSC FSC-0072), as used by FidoNet mailers — HydraCom, bforce, FTNd,
qico, BinkleyTerm, Argus, Taurus.

This is a library package — there is no CLI. Users import the `hydra`
package, provide a `FileHandler`, and drive sessions over any
`io.ReadWriter` transport (TCP sockets, serial ports, PTYs). Zero
dependencies outside the Go standard library.

## Features

- Full bidirectional transfer: both sides send and receive concurrently
  over one byte stream
- Capability negotiation (HydraCom-compatible union semantics), CRC-16
  (poly 0x8408) and CRC-32, all four body encodings decoded (BIN, HEX,
  ASC, UUE; BIN/HEX emitted)
- Resume, receiver-driven repositioning (RPOS — emits the de facto
  12-byte form, accepts both widths), skip/defer per file
- Sliding-window flow control (DATAACK) when configured; full streaming
  by default
- Adaptive block sizing (256–2048 bytes, HydraCom ladder after errors)
- Device/chat channel (DEVDATA/DEVDACK) with an optional `DeviceHandler`
- Multi-batch sessions: `Run` completes one START…END cycle and leaves
  the transport open, matching mailers (bforce) that run several batches
  per connection
- Escape-set negotiation for dirty links (XON/TLN/CTL/HIC/HI8), cancel
  sequence, brain-dead watchdog with reference-exact reset rules

## Usage

```go
package main

import (
	"context"
	"io"
	"log"
	"net"
	"os"
	"time"

	"github.com/xx25/go-hydra"
)

// handler implements hydra.FileHandler for both directions.
type handler struct {
	outbound []*hydra.FileOffer
}

func (h *handler) NextFile() *hydra.FileOffer {
	if len(h.outbound) == 0 {
		return nil
	}
	f := h.outbound[0]
	h.outbound = h.outbound[1:]
	return f
}

func (h *handler) AcceptFile(info hydra.FileInfo) (io.WriteCloser, int64, error) {
	name := hydra.SanitizeFilename(info.Name) // peer names are untrusted
	f, err := os.Create("inbound/" + name)
	return f, 0, err // offset > 0 resumes a partial file
}

func (h *handler) FileProgress(info hydra.FileInfo, n int64) {}

func (h *handler) FileCompleted(info hydra.FileInfo, n int64, err error) {
	log.Printf("%s: %d bytes, err=%v", info.Name, n, err)
}

func main() {
	conn, err := net.Dial("tcp", "peer:24555")
	if err != nil {
		log.Fatal(err)
	}

	f, _ := os.Open("outbound/packet.zip")
	fi, _ := f.Stat()

	h := &handler{outbound: []*hydra.FileOffer{{
		Name:    fi.Name(),
		Size:    fi.Size(),
		ModTime: fi.ModTime(),
		Reader:  f, // io.ReadSeeker enables resume and RPOS
	}}}

	sess := hydra.NewSession(conn, h, nil, &hydra.Config{
		Originator: true,
	})
	defer sess.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	if err := sess.Run(ctx); err != nil { // one batch
		log.Fatal(err)
	}
}
```

Hydra runs *inside* a FidoNet mailer session — the EMSI/WaZOO handshake
that selects the protocol happens before `Run` and is out of scope for
this library.

## Testing

```
go test ./...          # unit + loopback + conformance
go test -race ./...
HYDRA_TRACE=1 go test -run TestLoopbackSymmetric ./...   # wire trace
```

The conformance suite pins the compatibility-critical behaviours
(RPOS widths, INIT field count, end-of-batch encoding, cancel handling,
END counts, braindead rules) against the surveyed C implementations.
See `SPEC.md` for the corrected protocol reference and `CLAUDE.md` for
the pitfall list.

## License

MIT
