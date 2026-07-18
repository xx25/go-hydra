package hydra

import (
	"os"
	"os/exec"
	"testing"
)

// Interop against real peers (SPEC §12).
//
// bforce (installed as /usr/bin/bforce on this machine) has no
// bare-protocol mode: every session starts with an EMSI or WaZOO
// handshake on stdio (`bforce -o <node>` / `bforce emsi`), and Hydra is
// selected via the EMSI link codes ("HYD"). Driving that requires an
// EMSI_DAT implementation (FSC-0056) plus a bforce config with a node
// entry and spool directories — a session-layer harness, not a protocol
// harness.
//
// The plan of record (PLAN.md Phase 9): the loopback + conformance
// suites gate v1; real-peer interop runs through fidomail's session
// layer once its hydra xfer driver exists, or through this harness when
// the EMSI shim is written. Until then these tests skip unless
// HYDRA_INTEROP=1 and a prepared bforce config is supplied via
// HYDRA_BFORCE_CONF.
func TestInteropBforce(t *testing.T) {
	if os.Getenv("HYDRA_INTEROP") == "" {
		t.Skip("interop: set HYDRA_INTEROP=1 and HYDRA_BFORCE_CONF (see comment)")
	}
	if _, err := exec.LookPath("bforce"); err != nil {
		t.Skip("interop: bforce not on PATH")
	}
	conf := os.Getenv("HYDRA_BFORCE_CONF")
	if conf == "" {
		t.Skip("interop: HYDRA_BFORCE_CONF not set")
	}
	t.Fatal("EMSI session shim not implemented yet — see file comment")
}
