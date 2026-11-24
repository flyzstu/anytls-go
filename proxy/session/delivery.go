package session

// deliveryUnit is the accounting granularity of a stream delivery budget.
// Payloads are charged in whole units so the budget is a plain token count.
const deliveryUnit = 4096

// spillLimit is how many undelivered bytes one stream may queue before the
// session read loop stops reading from the socket. Without a limit a peer that
// keeps sending while the consumer stalls would grow memory without bound, and
// with a per-stream limit only that stream is throttled.
const spillLimit = 8 << 20

// delivered is one payload handed from the session read loop to a stream pump.
// Ownership of the pooled slice transfers with it.
type delivered struct {
	data []byte
}

func unitsFor(n int) int {
	return (n + deliveryUnit - 1) / deliveryUnit
}

// tokenPool is a byte-counted token pool. A token is held for as long as its
// payload sits in a queue, so the pool size is the queue's byte budget.
type tokenPool struct {
	tokens chan struct{}
}

func newTokenPool(bytes int) *tokenPool {
	return &tokenPool{tokens: make(chan struct{}, unitsFor(bytes))}
}

// acquire reserves n bytes, giving up when the stream or the session dies.
// Partially acquired tokens are returned on failure.
func (p *tokenPool) acquire(die, sessDie <-chan struct{}, n int) bool {
	want := unitsFor(n)
	for i := range want {
		select {
		case p.tokens <- struct{}{}:
		case <-die:
			p.releaseUnits(i)
			return false
		case <-sessDie:
			p.releaseUnits(i)
			return false
		}
	}
	return true
}

func (p *tokenPool) release(n int) {
	p.releaseUnits(unitsFor(n))
}

func (p *tokenPool) releaseUnits(units int) {
	for range units {
		select {
		case <-p.tokens:
		default:
			return
		}
	}
}
