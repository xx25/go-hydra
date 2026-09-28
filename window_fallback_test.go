package hydra

import "testing"

// A peer that never DATAACKs (bforce answers our TX window with IDLE only)
// must not cost the session: when the window fills and the timer fires
// with no DATAACK ever seen, the sender drops the window and streams on,
// without spending a retry. A peer that has ACKed keeps the anti-deadlock
// probe, which does count.
func TestTxWindowDroppedForPeerThatNeverAcks(t *testing.T) {
	b := &batch{cfg: (&Config{}).defaults(), txState: htxDataAck, txWindow: 64 << 10}
	if err := b.txTimeout(); err != nil {
		t.Fatalf("txTimeout: %v", err)
	}
	if b.txWindow != 0 || b.txState != htxXdata || b.txRetries != 0 {
		t.Fatalf("window=%d state=%v retries=%d; want 0, htxXdata, 0", b.txWindow, b.txState, b.txRetries)
	}

	b = &batch{cfg: (&Config{}).defaults(), txState: htxDataAck, txWindow: 64 << 10, peerAcked: true}
	if err := b.txTimeout(); err != nil {
		t.Fatalf("txTimeout: %v", err)
	}
	if b.txWindow == 0 || b.txState != htxXdata || b.txRetries != 1 {
		t.Fatalf("window=%d state=%v retries=%d; want kept, htxXdata, 1", b.txWindow, b.txState, b.txRetries)
	}
}
