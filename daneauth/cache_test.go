package daneauth

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shuque/dane/v2"
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (f *fakeClock) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.t
}

func (f *fakeClock) Advance(d time.Duration) {
	f.mu.Lock()
	f.t = f.t.Add(d)
	f.mu.Unlock()
}

func newFakeClock() *fakeClock { return &fakeClock{t: time.Unix(1700000000, 0)} }

func countingLookup(n *atomic.Int32, rr *dane.RRset, err error) lookupFunc {
	return func(ctx context.Context, qname string) (*dane.RRset, error) {
		n.Add(1)
		return rr, err
	}
}

func TestCachePositive(t *testing.T) {
	var n atomic.Int32
	clk := newFakeClock()
	rr := &dane.RRset{Qname: "a.example.", TTL: 60}
	c := newTLSACache(countingLookup(&n, rr, nil), 0, clk.Now)
	got, cached, err := c.Lookup(context.Background(), "a.example.")
	if err != nil || cached || got != rr {
		t.Fatalf("first: %v %v %v", got, cached, err)
	}
	got, cached, err = c.Lookup(context.Background(), "a.example.")
	if err != nil || !cached || got != rr || n.Load() != 1 {
		t.Fatalf("second: %v %v %v calls=%d", got, cached, err, n.Load())
	}
	clk.Advance(61 * time.Second)
	if _, cached, _ = c.Lookup(context.Background(), "a.example."); cached || n.Load() != 2 {
		t.Fatalf("after expiry: cached=%v calls=%d", cached, n.Load())
	}
}

func TestCacheNegative(t *testing.T) {
	var n atomic.Int32
	clk := newFakeClock()
	le := &dane.LookupError{Qname: "a.example.", Err: dane.ErrNoData, NegTTL: 10}
	c := newTLSACache(countingLookup(&n, nil, le), 0, clk.Now)
	c.Lookup(context.Background(), "a.example.")
	_, cached, err := c.Lookup(context.Background(), "a.example.")
	if !cached || err != error(le) || !errors.Is(err, dane.ErrNoData) || n.Load() != 1 {
		t.Fatalf("cached=%v err=%v calls=%d", cached, err, n.Load())
	}
	var got *dane.LookupError
	if !errors.As(err, &got) || got.NegTTL != 10 {
		t.Fatalf("errors.As failed")
	}
	clk.Advance(11 * time.Second)
	c.Lookup(context.Background(), "a.example.")
	if n.Load() != 2 {
		t.Fatalf("calls=%d, want 2", n.Load())
	}
}

func TestCacheNXDOMAIN(t *testing.T) {
	var n atomic.Int32
	le := &dane.LookupError{Qname: "a.example.", Err: dane.ErrNXDOMAIN, NegTTL: 10}
	c := newTLSACache(countingLookup(&n, nil, le), 0, newFakeClock().Now)
	if _, cached, err := c.Lookup(context.Background(), "a.example."); cached || !errors.Is(err, dane.ErrNXDOMAIN) {
		t.Fatalf("first: cached=%v err=%v", cached, err)
	}
	_, cached, err := c.Lookup(context.Background(), "a.example.")
	if !cached || !errors.Is(err, dane.ErrNXDOMAIN) || n.Load() != 1 {
		t.Fatalf("second: cached=%v err=%v calls=%d", cached, err, n.Load())
	}
}

func TestCacheNegativeCap(t *testing.T) {
	var n atomic.Int32
	clk := newFakeClock()
	le := &dane.LookupError{Qname: "a.example.", Err: dane.ErrNXDOMAIN, NegTTL: 7200}
	c := newTLSACache(countingLookup(&n, nil, le), 0, clk.Now)
	c.Lookup(context.Background(), "a.example.")
	clk.Advance(3599 * time.Second)
	if _, cached, _ := c.Lookup(context.Background(), "a.example."); !cached {
		t.Fatal("want cached at 3599s")
	}
	clk.Advance(2 * time.Second)
	if _, cached, _ := c.Lookup(context.Background(), "a.example."); cached || n.Load() != 2 {
		t.Fatalf("want expired at 3601s (cap 3600); calls=%d", n.Load())
	}
}

func TestCacheNegativeDefault(t *testing.T) {
	var n atomic.Int32
	clk := newFakeClock()
	le := &dane.LookupError{Qname: "a.example.", Err: dane.ErrInsecure}
	c := newTLSACache(countingLookup(&n, nil, le), 0, clk.Now)
	c.Lookup(context.Background(), "a.example.")
	clk.Advance(29 * time.Second)
	if _, cached, _ := c.Lookup(context.Background(), "a.example."); !cached {
		t.Fatal("want cached at 29s")
	}
	clk.Advance(2 * time.Second)
	if _, cached, _ := c.Lookup(context.Background(), "a.example."); cached || n.Load() != 2 {
		t.Fatalf("want expired at 31s; calls=%d", n.Load())
	}
}

func TestCacheNoCacheServFail(t *testing.T) {
	for _, sentinel := range []error{dane.ErrServFail, dane.ErrTimeout} {
		var n atomic.Int32
		le := &dane.LookupError{Qname: "a.example.", Err: sentinel, NegTTL: 10}
		c := newTLSACache(countingLookup(&n, nil, le), 0, nil)
		if _, cached, err := c.Lookup(context.Background(), "a.example."); cached || !errors.Is(err, sentinel) {
			t.Fatalf("%v: first: cached=%v err=%v", sentinel, cached, err)
		}
		_, cached, err := c.Lookup(context.Background(), "a.example.")
		if cached || !errors.Is(err, sentinel) || n.Load() != 2 {
			t.Fatalf("%v: cached=%v calls=%d", sentinel, cached, n.Load())
		}
	}
}

func TestCacheZeroTTLAndCap(t *testing.T) {
	var n atomic.Int32
	clk := newFakeClock()
	c := newTLSACache(countingLookup(&n, &dane.RRset{TTL: 0}, nil), 0, clk.Now)
	c.Lookup(context.Background(), "z.example.")
	c.Lookup(context.Background(), "z.example.")
	if n.Load() != 2 {
		t.Fatalf("TTL 0 cached: calls=%d", n.Load())
	}
	var m atomic.Int32
	c = newTLSACache(countingLookup(&m, &dane.RRset{TTL: 86400}, nil), 0, clk.Now)
	c.Lookup(context.Background(), "big.example.")
	clk.Advance(3601 * time.Second)
	c.Lookup(context.Background(), "big.example.")
	if m.Load() != 2 {
		t.Fatalf("TTL not capped: calls=%d", m.Load())
	}
}

func TestCacheCaseInsensitive(t *testing.T) {
	var n atomic.Int32
	c := newTLSACache(countingLookup(&n, &dane.RRset{TTL: 60}, nil), 0, nil)
	c.Lookup(context.Background(), "A.Example.")
	_, cached, _ := c.Lookup(context.Background(), "a.example")
	if !cached || n.Load() != 1 {
		t.Fatalf("cached=%v calls=%d", cached, n.Load())
	}
}

func TestCacheEviction(t *testing.T) {
	var n atomic.Int32
	clk := newFakeClock()
	c := newTLSACache(countingLookup(&n, &dane.RRset{TTL: 60}, nil), 2, clk.Now)
	for _, name := range []string{"a.example.", "b.example.", "c.example."} {
		c.Lookup(context.Background(), name)
		clk.Advance(time.Second)
	}
	if got := len(c.entries); got != 2 {
		t.Fatalf("entries=%d, want 2", got)
	}
	if _, ok := c.entries["a.example."]; ok {
		t.Fatal("nearest-expiry entry a.example. not evicted")
	}
}

func TestCacheConcurrent(t *testing.T) {
	var n atomic.Int32
	c := newTLSACache(countingLookup(&n, &dane.RRset{TTL: 60}, nil), 0, nil)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, _, err := c.Lookup(context.Background(), "a.example."); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
}
