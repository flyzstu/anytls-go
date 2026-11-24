package session

import (
	"anytls/proxy/pipe"
	"io"
	"net"
	"os"
	"sync"
	"time"
)

// Stream implements net.Conn.
//
// cmdFIN means "this stream is closed", not "this direction is closed"
// (docs/protocol.md), so a FIN ends the stream in both directions. What the
// stream does guarantee is ordering: payloads the peer sent before its FIN are
// delivered to the consumer before the read side reports EOF, because the
// session read loop only queues them and never writes into the pipe itself.
type Stream struct {
	id   uint32
	sess *Session

	pipeR *pipe.PipeReader
	pipeW *pipe.PipeWriter

	// queue carries frame payloads from the session read loop to a per-stream
	// pump goroutine, so a consumer that stops reading only stalls its own
	// stream instead of the whole session.
	queue  chan delivered
	budget *tokenPool

	// eof tells the pump that the peer closed the stream. It is consumed after
	// every payload queued before it, so the pump drains first.
	eof     chan struct{}
	eofOnce sync.Once

	dieOnce sync.Once
	die     chan struct{}

	dieMu     sync.Mutex
	readDone  bool
	writeDone bool
	readErr   error
	writeErr  error
	dieHook   func()
	dieHookMu sync.Mutex

	reportOnce sync.Once

	writeDeadline pipe.PipeDeadline
}

// newStream initiates a Stream struct
func newStream(id uint32, sess *Session, dieHook func()) *Stream {
	s := new(Stream)
	s.id = id
	s.sess = sess
	s.pipeR, s.pipeW = pipe.Pipe()
	s.queue = make(chan delivered, unitsFor(spillLimit))
	s.budget = newTokenPool(spillLimit)
	s.eof = make(chan struct{}, 1)
	s.die = make(chan struct{})
	s.writeDeadline = pipe.MakePipeDeadline()
	s.dieHook = dieHook
	go s.pump()
	return s
}

// reserve waits for delivery budget for one payload. Waiting is backpressure,
// not failure: it exits early only when the session or the stream dies.
func (s *Stream) reserve(n int) bool {
	return s.budget.acquire(s.die, s.sess.die, n)
}

// pump is the only writer of the read pipe. It ends the read side once the
// peer's FIN was seen and every queued payload has been delivered.
func (s *Stream) pump() {
	for {
		select {
		case item := <-s.queue:
			if !s.deliver(item.data) {
				return
			}
		case <-s.eof:
			for {
				select {
				case item := <-s.queue:
					if !s.deliver(item.data) {
						return
					}
					continue
				default:
				}
				break
			}
			_ = s.pipeW.CloseWithError(nil)
			s.finish(true, nil)
			s.finish(false, net.ErrClosed)
			return
		case <-s.die:
			s.drainQueue()
			return
		}
	}
}

func (s *Stream) deliver(data []byte) bool {
	_, err := s.pipeW.Write(data)
	s.budget.release(len(data))
	if err != nil {
		// The consumer closed its end: nothing more can be delivered.
		s.finish(true, net.ErrClosed)
		s.drainQueue()
		return false
	}
	return true
}

func (s *Stream) drainQueue() {
	for {
		select {
		case item := <-s.queue:
			s.budget.release(len(item.data))
		default:
			return
		}
	}
}

// push hands a payload to the stream pump. Ownership of data transfers to the
// stream on success; on failure the caller keeps the budget and the buffer.
func (s *Stream) push(data []byte) bool {
	select {
	case s.queue <- delivered{data: data}:
		return true
	case <-s.die:
		return false
	case <-s.sess.die:
		return false
	}
}

// finishRemote marks the peer's cmdFIN. Every payload it sent was queued
// before this call, so the pump delivers them and then reports EOF.
func (s *Stream) finishRemote() {
	s.eofOnce.Do(func() { s.eof <- struct{}{} })
}

// Read implements net.Conn
func (s *Stream) Read(b []byte) (n int, err error) {
	n, err = s.pipeR.Read(b)
	if n == 0 {
		s.dieMu.Lock()
		readErr := s.readErr
		s.dieMu.Unlock()
		if readErr != nil && err != io.EOF {
			err = readErr
		}
	}
	return
}

// Write implements net.Conn
func (s *Stream) Write(b []byte) (n int, err error) {
	select {
	case <-s.writeDeadline.Wait():
		return 0, os.ErrDeadlineExceeded
	default:
	}
	if err := s.writeDead(); err != nil {
		return 0, err
	}
	return s.sess.writeDataFrame(s.id, b)
}

// Close implements net.Conn. The protocol has one close command, so this ends
// the stream in both directions and tells the peer.
func (s *Stream) Close() error {
	if !s.finish(true, io.ErrClosedPipe) {
		return nil
	}
	s.finish(false, io.ErrClosedPipe)
	return s.sess.streamClosed(s.id)
}

// closeLocally closes the stream without notifying the peer.
func (s *Stream) closeLocally() {
	s.finish(true, net.ErrClosed)
	s.finish(false, net.ErrClosed)
}

// finish marks one direction as finished (or the whole stream dead) and
// reports whether this call made the change. Once both directions are done the
// stream leaves the session and its die channel closes exactly once.
func (s *Stream) finish(read bool, err error) bool {
	s.dieMu.Lock()
	done := &s.writeDone
	slot := &s.writeErr
	if read {
		done = &s.readDone
		slot = &s.readErr
	}
	if *done {
		s.dieMu.Unlock()
		return false
	}
	*done = true
	if err != nil || *slot == nil {
		*slot = err
	}
	whole := s.readDone && s.writeDone
	s.dieMu.Unlock()

	if read && err != nil {
		// Closing the read half discards buffered data, so it is only used to
		// abort a blocked consumer. A clean EOF comes from closing pipeW.
		_ = s.pipeR.Close()
	}
	if !whole {
		return true
	}

	s.dieOnce.Do(func() { close(s.die) })
	s.sess.removeStream(s.id)
	if hook := s.takeDieHook(); hook != nil {
		hook()
	}
	return true
}

func (s *Stream) takeDieHook() func() {
	s.dieHookMu.Lock()
	defer s.dieHookMu.Unlock()
	hook := s.dieHook
	s.dieHook = nil
	return hook
}

func (s *Stream) writeDead() error {
	s.dieMu.Lock()
	defer s.dieMu.Unlock()
	if s.writeErr != nil {
		return s.writeErr
	}
	if s.writeDone {
		return io.ErrClosedPipe
	}
	return nil
}

func (s *Stream) SetReadDeadline(t time.Time) error {
	return s.pipeR.SetReadDeadline(t)
}

func (s *Stream) SetWriteDeadline(t time.Time) error {
	s.writeDeadline.Set(t)
	return nil
}

func (s *Stream) SetDeadline(t time.Time) error {
	_ = s.SetWriteDeadline(t)
	return s.SetReadDeadline(t)
}

// LocalAddr satisfies net.Conn interface
func (s *Stream) LocalAddr() net.Addr {
	if ts, ok := s.sess.conn.(interface {
		LocalAddr() net.Addr
	}); ok {
		return ts.LocalAddr()
	}
	return nil
}

// RemoteAddr satisfies net.Conn interface
func (s *Stream) RemoteAddr() net.Addr {
	if ts, ok := s.sess.conn.(interface {
		RemoteAddr() net.Addr
	}); ok {
		return ts.RemoteAddr()
	}
	return nil
}

// HandshakeFailure should be called when Server fail to create outbound proxy
func (s *Stream) HandshakeFailure(err error) error {
	var once bool
	s.reportOnce.Do(func() {
		once = true
	})
	if once && err != nil && s.sess.peerVersion.Load() >= 2 {
		f := newFrame(cmdSYNACK, s.id)
		f.data = []byte(err.Error())
		if _, err := s.sess.writeControlFrame(f); err != nil {
			return err
		}
	}
	return nil
}

// HandshakeSuccess should be called when Server success to create outbound proxy
func (s *Stream) HandshakeSuccess() error {
	var once bool
	s.reportOnce.Do(func() {
		once = true
	})
	if once && s.sess.peerVersion.Load() >= 2 {
		if _, err := s.sess.writeControlFrame(newFrame(cmdSYNACK, s.id)); err != nil {
			return err
		}
	}
	return nil
}
