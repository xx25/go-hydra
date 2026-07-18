package hydra

// blockSizer implements the TX block size adaptation of SPEC §6, matching
// HydraCom 1.00: start small on slow links, double after goodNeeded
// successfully sent bytes, and on every RPOS adopt the receiver's proposed
// size while raising the bar for the next doubling.
type blockSizer struct {
	cur        int
	max        int
	goodBytes  int
	goodNeeded int
}

// newBlockSizer keys the initial and maximum block sizes off the line
// speed. baud <= 0 means a fast reliable transport (TCP): start 512, max
// maxCap. maxCap is the configured ceiling (≤ DataBufMax).
func newBlockSizer(baud, maxCap int) *blockSizer {
	if maxCap <= 0 || maxCap > DataBufMax {
		maxCap = DataBufMax
	}
	initial := 512
	max := maxCap
	if baud > 0 {
		if baud < 2400 {
			initial = 256
		}
		fromBaud := (baud / 300) * 128
		if fromBaud < 256 {
			fromBaud = 256
		}
		if fromBaud < max {
			max = fromBaud
		}
	}
	if initial > max {
		initial = max
	}
	return &blockSizer{
		cur:        initial,
		max:        max,
		goodNeeded: defaultGoodNeeded,
	}
}

// size returns the current block size.
func (b *blockSizer) size() int { return b.cur }

// good records n successfully sent bytes; when the running total crosses
// goodNeeded the block size doubles. At the cap goodNeeded drops to 0 so
// the growth check short-circuits (hydra.c:1269-1277).
func (b *blockSizer) good(n int) {
	if b.cur >= b.max {
		return
	}
	b.goodBytes += n
	if b.goodBytes >= b.goodNeeded {
		b.cur *= 2
		if b.cur >= b.max {
			b.cur = b.max
			b.goodNeeded = 0
		}
		b.goodBytes = 0
	}
}

// ladder rounds n up into HydraCom's post-RPOS block ladder
// {64, 128, 256, 512, 1024} (hydra.c:1736-1740). Growth back to 2048 only
// happens through error-free doubling.
func ladder(n int) int {
	for _, step := range [...]int{minBlockSize, 128, 256, 512} {
		if n <= step {
			return step
		}
	}
	return rposMaxBlock
}

// rpos reacts to a receiver reposition (hydra.c:1732-1744): adopt the
// receiver's proposal when it is smaller, otherwise halve; round up into
// the ladder; raise goodNeeded by 1024, capped at maxGoodNeeded.
func (b *blockSizer) rpos(proposed int) {
	if proposed > 0 && b.cur > proposed {
		b.cur = proposed
	} else {
		b.cur /= 2
	}
	b.cur = ladder(b.cur)
	b.goodBytes = 0
	b.goodNeeded += 1024
	if b.goodNeeded > maxGoodNeeded {
		b.goodNeeded = maxGoodNeeded
	}
}
