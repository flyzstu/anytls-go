package session

import (
	"bytes"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"anytls/proxy/padding"
)

// testPair returns the two ends of an in-memory session connection.
func testPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	client, server := net.Pipe()
	t.Cleanup(func() {
		client.Close()
		server.Close()
	})
	return client, server
}

// frameBytes builds a raw frame for the test peer to send.
func frameBytes(cmd byte, sid uint32, data []byte) []byte {
	out := make([]byte, headerOverHeadSize+len(data))
	out[0] = cmd
	out[1] = byte(sid >> 24)
	out[2] = byte(sid >> 16)
	out[3] = byte(sid >> 8)
	out[4] = byte(sid)
	out[5] = byte(len(data) >> 8)
	out[6] = byte(len(data))
	copy(out[headerOverHeadSize:], data)
	return out
}

type receivedFrame struct {
	cmd  byte
	sid  uint32
	data []byte
}

// peer is a fake remote end that reads frames in the background. net.Pipe is
// synchronous, so without a concurrent reader the session's writes would block.
type peer struct {
	conn   net.Conn
	frames chan receivedFrame
	stop   chan struct{}
	once   sync.Once
}

func newPeer(conn net.Conn) *peer {
	p := &peer{
		conn:   conn,
		frames: make(chan receivedFrame, 64),
		stop:   make(chan struct{}),
	}
	go p.readLoop()
	return p
}

func (p *peer) readLoop() {
	defer close(p.frames)
	for {
		hdr := make([]byte, headerOverHeadSize)
		if _, err := io.ReadFull(p.conn, hdr); err != nil {
			return
		}
		cmd := hdr[0]
		sid := uint32(hdr[1])<<24 | uint32(hdr[2])<<16 | uint32(hdr[3])<<8 | uint32(hdr[4])
		length := int(hdr[5])<<8 | int(hdr[6])
		var data []byte
		if length > 0 {
			data = make([]byte, length)
			if _, err := io.ReadFull(p.conn, data); err != nil {
				return
			}
		}
		if cmd == cmdWaste {
			continue
		}
		select {
		case p.frames <- receivedFrame{cmd: cmd, sid: sid, data: data}:
		case <-p.stop:
			return
		}
	}
}

// next returns the next non-padding frame the peer received.
func (p *peer) next(t *testing.T, timeout time.Duration) receivedFrame {
	t.Helper()
	select {
	case frame, ok := <-p.frames:
		if !ok {
			t.Fatal("peer connection closed")
		}
		return frame
	case <-time.After(timeout):
		t.Fatal("timed out waiting for a frame")
	}
	return receivedFrame{}
}

// expect waits for a frame with the given command and returns it.
func (p *peer) expect(t *testing.T, cmd byte, timeout time.Duration) receivedFrame {
	t.Helper()
	for {
		frame := p.next(t, timeout)
		if frame.cmd == cmd {
			return frame
		}
	}
}

func (p *peer) send(t *testing.T, cmd byte, sid uint32, data []byte) {
	t.Helper()
	if _, err := p.conn.Write(frameBytes(cmd, sid, data)); err != nil {
		t.Fatalf("peer send: %v", err)
	}
}

func (p *peer) close() { p.once.Do(func() { close(p.stop) }) }

// testSession starts a client session and returns it with a background peer.
func testSession(t *testing.T) (*Session, *peer) {
	t.Helper()
	clientConn, serverConn := testPair(t)
	session := NewClientSession(clientConn, &padding.DefaultPaddingFactory)
	p := newPeer(serverConn)
	t.Cleanup(func() {
		p.close()
		session.Close()
	})
	session.Run()
	// Settings is buffered until the first stream write, so it is not awaited
	// here; expect() skips it when the SYN is looked for.
	return session, p
}

// openStream opens a client stream and consumes its SYN.
func openStream(t *testing.T, session *Session, p *peer) *Stream {
	t.Helper()
	stream, err := session.OpenStream()
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	syn := p.expect(t, cmdSYN, 2*time.Second)
	if syn.sid != stream.id {
		t.Fatalf("syn for stream %d, opened %d", syn.sid, stream.id)
	}
	return stream
}

// TestStreamQueueSurvivesStalledConsumer is the head-of-line regression: a
// stream whose consumer never reads must not stop another stream on the same
// session from delivering data.
func TestStreamQueueSurvivesStalledConsumer(t *testing.T) {
	session, p := testSession(t)

	stalled, err := session.OpenStream()
	if err != nil {
		t.Fatalf("open stalled stream: %v", err)
	}
	live, err := session.OpenStream()
	if err != nil {
		t.Fatalf("open live stream: %v", err)
	}
	p.expect(t, cmdSYN, 2*time.Second)
	p.expect(t, cmdSYN, 2*time.Second)

	// Fill the stalled stream past its queue budget while it never reads.
	bulk := bytes.Repeat([]byte("a"), maxFramePayload)
	for range 3 {
		if _, err := p.conn.Write(frameBytes(cmdPSH, stalled.id, bulk)); err != nil {
			break
		}
	}

	if _, err := p.conn.Write(frameBytes(cmdPSH, live.id, []byte("hello"))); err != nil {
		t.Fatalf("write live payload: %v", err)
	}
	_ = live.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 5)
	if _, err := io.ReadFull(live, buf); err != nil {
		t.Fatalf("live stream starved by stalled stream: %v", err)
	}
	if string(buf) != "hello" {
		t.Fatalf("live stream got %q, want %q", buf, "hello")
	}
	if session.IsClosed() {
		t.Fatal("session closed while one stream was backpressured")
	}
}

// TestPayloadBeforeFINIsDelivered: a FIN must not discard payloads queued
// before it.
func TestPayloadBeforeFINIsDelivered(t *testing.T) {
	session, p := testSession(t)
	stream := openStream(t, session, p)

	want := bytes.Repeat([]byte("z"), maxFramePayload)
	p.send(t, cmdPSH, stream.id, want)
	p.send(t, cmdFIN, stream.id, nil)

	_ = stream.SetReadDeadline(time.Now().Add(5 * time.Second))
	got, err := io.ReadAll(stream)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("got %d bytes, want %d", len(got), len(want))
	}
}

// TestUnexpectedPayloadDoesNotDesync: a command carrying data it does not
// expect must still consume it, so later frames stay aligned.
func TestUnexpectedPayloadDoesNotDesync(t *testing.T) {
	session, p := testSession(t)
	stream := openStream(t, session, p)

	p.send(t, cmdSYN, 9, []byte("junk"))
	p.send(t, cmdPSH, stream.id, []byte("aligned"))

	_ = stream.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, len("aligned"))
	if _, err := io.ReadFull(stream, buf); err != nil {
		t.Fatalf("frame stream desynced: %v", err)
	}
	if string(buf) != "aligned" {
		t.Fatalf("got %q, want %q", buf, "aligned")
	}
}

// TestOversizedWriteIsSplit checks a write above the frame payload limit is
// split instead of silently truncating its length field.
func TestOversizedWriteIsSplit(t *testing.T) {
	session, p := testSession(t)
	stream := openStream(t, session, p)

	payload := make([]byte, maxFramePayload+1000)
	for i := range payload {
		payload[i] = byte(i)
	}
	go func() {
		n, err := stream.Write(payload)
		if err != nil {
			t.Errorf("write: %v", err)
			return
		}
		if n != len(payload) {
			t.Errorf("Write reported %d of %d bytes", n, len(payload))
		}
	}()

	got := make([]byte, 0, len(payload))
	for len(got) < len(payload) {
		frame := p.expect(t, cmdPSH, 3*time.Second)
		if len(frame.data) > maxFramePayload {
			t.Fatalf("frame payload %d exceeds the limit", len(frame.data))
		}
		got = append(got, frame.data...)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("payload corrupted across split frames")
	}
}

// TestCloseReturnsWithStuckWriter is the "Close hangs forever" regression: a
// writer blocked on the connection must not stop Close from completing.
func TestCloseReturnsWithStuckWriter(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()

	session := NewClientSession(clientConn, &padding.DefaultPaddingFactory)
	// Read exactly one frame (settings) then stop reading, so the next write
	// blocks on the unbuffered pipe.
	go func() {
		hdr := make([]byte, headerOverHeadSize)
		if _, err := io.ReadFull(serverConn, hdr); err != nil {
			return
		}
		length := int(hdr[5])<<8 | int(hdr[6])
		if length > 0 {
			io.ReadFull(serverConn, make([]byte, length))
		}
	}()
	session.Run()

	// Start a write that will block, then close from another goroutine.
	go session.OpenStream()

	done := make(chan struct{})
	go func() {
		session.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Close blocked on an in-flight write")
	}
}

// TestDieHookRunsOnImmediateFIN: the pool hook must exist before the SYN is
// announced, so a FIN arriving immediately still releases the session.
func TestDieHookRunsOnImmediateFIN(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()
	session := NewClientSession(clientConn, &padding.DefaultPaddingFactory)
	p := newPeer(serverConn)
	defer p.close()
	session.Run()
	defer session.Close()

	hookRan := make(chan struct{})
	go func() {
		for frame := range p.frames {
			if frame.cmd == cmdSYN {
				p.conn.Write(frameBytes(cmdFIN, frame.sid, nil))
				return
			}
		}
	}()

	stream, err := session.openStream(func() { close(hookRan) })
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	_ = stream.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _ = stream.Read(make([]byte, 1))

	select {
	case <-hookRan:
	case <-time.After(3 * time.Second):
		t.Fatal("die hook never ran: session stays out of the pool")
	}
}

// TestHeartbeatClosesSilentSession checks the keepalive closes a peer that
// answers nothing.
func TestHeartbeatClosesSilentSession(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()
	session := NewClientSession(clientConn, &padding.DefaultPaddingFactory)
	session.SetHeartbeat(50*time.Millisecond, 150*time.Millisecond)
	p := newPeer(serverConn)
	defer p.close()
	session.Run()
	defer session.Close()
	// Only a peer announcing protocol version 2 understands the probe.
	p.send(t, cmdServerSettings, 0, []byte("v=2"))

	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		if session.IsClosed() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("heartbeat did not close a silent session")
}

// TestHeartbeatKeepsLiveSession checks a peer that answers keeps the session.
func TestHeartbeatKeepsLiveSession(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()
	session := NewClientSession(clientConn, &padding.DefaultPaddingFactory)
	session.SetHeartbeat(50*time.Millisecond, 150*time.Millisecond)
	p := newPeer(serverConn)
	defer p.close()
	session.Run()
	defer session.Close()
	p.send(t, cmdServerSettings, 0, []byte("v=2"))

	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			select {
			case frame, ok := <-p.frames:
				if !ok {
					return
				}
				if frame.cmd == cmdHeartRequest {
					p.conn.Write(frameBytes(cmdHeartResponse, frame.sid, nil))
				}
			case <-done:
				return
			}
		}
	}()

	time.Sleep(800 * time.Millisecond)
	if session.IsClosed() {
		t.Fatal("heartbeat closed a responsive session")
	}
}

// TestConcurrentOpenStreamNoRace exercises the buffering flag from several
// goroutines; run with -race.
func TestConcurrentOpenStreamNoRace(t *testing.T) {
	session, p := testSession(t)

	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 10 {
				stream, err := session.OpenStream()
				if err != nil {
					return
				}
				_ = stream.Close()
			}
		}()
	}
	// Drain the peer so the session's writes never block.
	go func() {
		for range p.frames {
		}
	}()
	wg.Wait()
}
