package hydra

import (
	"testing"
	"time"
)

func TestConfigDefaults(t *testing.T) {
	c := (*Config)(nil).defaults()
	if c.AppID != "2b1aab00gohydra,0.1" {
		t.Errorf("AppID = %q", c.AppID)
	}
	if c.MaxBlockSize != DataBufMax || c.MaxRetries != defaultMaxRetries {
		t.Errorf("block/retries = %d/%d", c.MaxBlockSize, c.MaxRetries)
	}
	if c.BrainDead != defaultBrainDead || c.Timeout != defaultTimeout {
		t.Errorf("braindead/timeout = %v/%v", c.BrainDead, c.Timeout)
	}

	// Slow link: timeout = 40960/baud, clamped to [10s, 60s].
	slow := (&Config{EffectiveBaud: 1200}).defaults()
	if slow.Timeout != 34*time.Second {
		t.Errorf("1200 baud timeout = %v, want 34s", slow.Timeout)
	}
	crawl := (&Config{EffectiveBaud: 300}).defaults()
	if crawl.Timeout != 60*time.Second {
		t.Errorf("300 baud timeout = %v, want 60s (capped)", crawl.Timeout)
	}
	fast := (&Config{EffectiveBaud: 115200}).defaults()
	if fast.Timeout != defaultTimeout {
		t.Errorf("115200 baud timeout = %v, want 10s floor", fast.Timeout)
	}

	// defaults() must not mutate the caller's Config.
	orig := &Config{}
	_ = orig.defaults()
	if orig.AppID != "" || orig.MaxBlockSize != 0 {
		t.Error("defaults() mutated the caller's Config")
	}
}

func TestConfigCaps(t *testing.T) {
	c := (&Config{}).defaults()
	if c.localSupported() != capDefaultSupported {
		t.Errorf("default supported = %#x", c.localSupported())
	}
	// Default desired is FPT only — escape flags are opt-in, C32/DEV
	// ride the union rule.
	if c.localDesired() != capFPT {
		t.Errorf("default desired = %#x, want FPT", c.localDesired())
	}

	// ASC/UUE are decode-only: strip them even if the caller asks.
	c = (&Config{Supported: []string{"XON", "TLN", "CTL", "HIC", "HI8", "BRK", "ASC", "UUE", "C32"}}).defaults()
	want := capXON | capTLN | capCTL | capHIC | capHI8 | capBRK | capC32
	if c.localSupported() != want {
		t.Errorf("supported with ASC/UUE = %#x, want %#x", c.localSupported(), want)
	}

	// Explicit Desired is honoured (minus ASC/UUE).
	c = (&Config{Desired: []string{"CTL", "HI8", "ASC", "C32"}}).defaults()
	if c.localDesired() != capCTL|capHI8|capC32 {
		t.Errorf("explicit desired = %#x", c.localDesired())
	}
}

func TestBlockSizer(t *testing.T) {
	// TCP: start 512, max 2048.
	b := newBlockSizer(0, 0)
	if b.size() != 512 || b.max != DataBufMax {
		t.Fatalf("tcp sizer = %d/%d", b.size(), b.max)
	}
	// Grow after goodNeeded bytes.
	b.good(1024)
	if b.size() != 1024 {
		t.Fatalf("after 1024 good bytes size = %d, want 1024", b.size())
	}
	b.good(1024)
	if b.size() != 2048 {
		t.Fatalf("after 2048 good bytes size = %d, want 2048", b.size())
	}
	b.good(4096)
	if b.size() != 2048 {
		t.Fatalf("size exceeded max: %d", b.size())
	}
	if b.goodNeeded != 0 {
		t.Fatalf("goodNeeded at cap = %d, want 0 (hydra.c:1274)", b.goodNeeded)
	}

	// RPOS shrinks to the proposal and raises the doubling bar.
	b.rpos(256)
	if b.size() != 256 || b.goodNeeded != 1024 {
		t.Fatalf("after rpos: size=%d goodNeeded=%d", b.size(), b.goodNeeded)
	}
	b.good(512) // below the bar — no growth
	if b.size() != 256 {
		t.Fatalf("size grew below bar: %d", b.size())
	}

	// No proposal (0) means halve; results always land on the ladder.
	b.rpos(0)
	if b.size() != 128 || b.goodNeeded != 2048 {
		t.Fatalf("after rpos(0): size=%d goodNeeded=%d", b.size(), b.goodNeeded)
	}
	// A large proposal never exceeds the 1024 ladder cap.
	b.rpos(2048)
	if b.size() != minBlockSize {
		// cur was 128; proposal 2048 > cur → halve to 64.
		t.Fatalf("after rpos(2048) from 128: size=%d, want 64", b.size())
	}

	// Baud-derived sizes per SPEC §6.
	if s := newBlockSizer(300, 0); s.size() != 256 || s.max != 256 {
		t.Errorf("300 baud = %d/%d, want 256/256", s.size(), s.max)
	}
	if s := newBlockSizer(1200, 0); s.size() != 256 || s.max != 512 {
		t.Errorf("1200 baud = %d/%d, want 256/512", s.size(), s.max)
	}
	if s := newBlockSizer(2400, 0); s.size() != 512 || s.max != 1024 {
		t.Errorf("2400 baud = %d/%d, want 512/1024", s.size(), s.max)
	}
	if s := newBlockSizer(9600, 0); s.size() != 512 || s.max != 2048 {
		t.Errorf("9600 baud = %d/%d, want 512/2048", s.size(), s.max)
	}
}

func TestSanitizeFilename(t *testing.T) {
	cases := map[string]string{
		"file.txt":            "file.txt",
		"../../etc/passwd":    "passwd",
		"dir/sub/name":        "name",
		"C:\\evil\\name.txt":  "name.txt",
		"":                    "_",
		".":                   "_",
		"..":                  "_",
		"nul\x00byte":         "nul_byte",
		"/absolute/path/f.gz": "f.gz",
	}
	for in, want := range cases {
		if got := SanitizeFilename(in); got != want {
			t.Errorf("SanitizeFilename(%q) = %q, want %q", in, got, want)
		}
	}
}
