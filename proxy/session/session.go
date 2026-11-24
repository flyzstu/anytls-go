package session

import (
	"anytls/proxy/padding"
	"anytls/util"
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"runtime/debug"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/sagernet/sing/common/atomic"
	"github.com/sagernet/sing/common/buf"
	"github.com/sirupsen/logrus"
)

var clientDebugPaddingScheme = os.Getenv("CLIENT_DEBUG_PADDING_SCHEME") == "1"

const (
	// maxFramePayload is the largest payload one frame can carry; the header
	// stores the payload length in 16 bits.
	maxFramePayload = 1<<16 - 1

	// controlWriteTimeout matches the deadline control frames have always used.
	// Data frames get a looser one so a slow link is not mistaken for a dead
	// peer, and it still stops a zero-window peer from blocking forever.
	controlWriteTimeout = 5 * time.Second
	dataWriteTimeout    = 30 * time.Second

	defaultHeartbeatInterval = 30 * time.Second
	defaultHeartbeatTimeout  = 30 * time.Second
)

type Session struct {
	conn     net.Conn
	connLock sync.Mutex

	streams    map[uint32]*Stream
	streamId   atomic.Uint32
	streamLock sync.RWMutex

	dieOnce sync.Once
	die     chan struct{}
	dieHook func()

	synDone     func()
	synDoneLock sync.Mutex

	// pool
	seq       uint64
	idleSince time.Time
	padding   *atomic.TypedValue[*padding.PaddingFactory]

	peerVersion atomic.Uint32

	// client
	isClient    bool
	sendPadding bool
	// buffering and buffer are guarded by connLock.
	buffering  bool
	buffer     []byte
	pktCounter atomic.Uint32

	// server
	onNewStream func(stream *Stream)

	// Liveness. lastRecv is the wall clock of the last complete frame, and
	// blocked counts read-loop goroutines parked on a stream delivery budget
	// (they are alive, just backpressured, so they must not trip the timeout).
	heartbeatInterval atomic.Int64
	heartbeatTimeout  atomic.Int64
	lastRecv          atomic.Int64
	blocked           atomic.Int32
}

func NewClientSession(conn net.Conn, _padding *atomic.TypedValue[*padding.PaddingFactory]) *Session {
	s := &Session{
		conn:        conn,
		isClient:    true,
		sendPadding: true,
		padding:     _padding,
	}
	s.die = make(chan struct{})
	s.streams = make(map[uint32]*Stream)
	s.heartbeatInterval.Store(int64(defaultHeartbeatInterval))
	s.heartbeatTimeout.Store(int64(defaultHeartbeatTimeout))
	return s
}

func NewServerSession(conn net.Conn, onNewStream func(stream *Stream), _padding *atomic.TypedValue[*padding.PaddingFactory]) *Session {
	s := &Session{
		conn:        conn,
		onNewStream: onNewStream,
		padding:     _padding,
	}
	s.die = make(chan struct{})
	s.streams = make(map[uint32]*Stream)
	s.heartbeatInterval.Store(int64(defaultHeartbeatInterval))
	s.heartbeatTimeout.Store(int64(defaultHeartbeatTimeout))
	return s
}

// SetHeartbeat sets how often an idle session probes the peer and how long it
// waits for any frame before declaring the session dead. A non-positive
// interval disables the probe.
func (s *Session) SetHeartbeat(interval, timeout time.Duration) {
	s.heartbeatInterval.Store(int64(interval))
	if timeout > 0 {
		s.heartbeatTimeout.Store(int64(timeout))
	}
}

func (s *Session) Run() {
	if !s.isClient {
		s.lastRecv.Store(time.Now().UnixNano())
		s.recvLoop()
		return
	}

	settings := util.StringMap{
		"v":           "2",
		"client":      util.ProgramVersionName,
		"padding-md5": s.padding.Load().Md5,
	}
	f := newFrame(cmdSettings, 0)
	f.data = settings.ToBytes()
	s.connLock.Lock()
	s.buffering = true
	s.connLock.Unlock()
	if _, err := s.writeControlFrame(f); err != nil {
		s.Close()
		return
	}

	s.lastRecv.Store(time.Now().UnixNano())
	go s.recvLoop()
	go s.heartbeatLoop()
}

// IsClosed does a safe check to see if we have shutdown
func (s *Session) IsClosed() bool {
	select {
	case <-s.die:
		return true
	default:
		return false
	}
}

// Close is used to close the session and all streams.
func (s *Session) Close() error {
	var once bool
	s.dieOnce.Do(func() {
		// SetDeadline aborts any in-flight read or write, which is what
		// unblocks recvLoop and Close itself without taking connLock.
		_ = s.conn.SetDeadline(time.Now())
		close(s.die)
		once = true
	})
	if once {
		if s.dieHook != nil {
			s.dieHook()
			s.dieHook = nil
		}
		s.streamLock.Lock()
		streams := s.streams
		s.streams = make(map[uint32]*Stream)
		s.streamLock.Unlock()
		// closeLocally removes the stream from the map, so it runs after the
		// map was swapped out.
		for _, stream := range streams {
			stream.closeLocally()
		}
		return s.conn.Close()
	} else {
		return io.ErrClosedPipe
	}
}

// OpenStream is used to create a new stream for CLIENT
func (s *Session) OpenStream() (*Stream, error) {
	return s.openStream(nil)
}

// openStream creates a client stream and installs dieHook before the stream
// can be observed by the remote peer, so a FIN arriving immediately after the
// SYN still runs the hook.
func (s *Session) openStream(dieHook func()) (*Stream, error) {
	if s.IsClosed() {
		return nil, io.ErrClosedPipe
	}

	sid := s.streamId.Add(1)
	stream := newStream(sid, s, dieHook)

	if sid >= 2 && s.peerVersion.Load() >= 2 {
		s.synDoneLock.Lock()
		if s.synDone != nil {
			s.synDone()
		}
		s.synDone = util.NewDeadlineWatcher(time.Second*3, func() {
			s.Close()
		})
		s.synDoneLock.Unlock()
	}

	// Register before announcing the stream: a PSH answering the SYN may
	// arrive before writeControlFrame returns.
	s.streamLock.Lock()
	select {
	case <-s.die:
		s.streamLock.Unlock()
		stream.closeLocally()
		return nil, io.ErrClosedPipe
	default:
		s.streams[sid] = stream
	}
	s.streamLock.Unlock()

	// The first write of a new stream flushes the buffered Settings frame.
	s.connLock.Lock()
	s.buffering = false
	s.connLock.Unlock()

	if _, err := s.writeControlFrame(newFrame(cmdSYN, sid)); err != nil {
		s.streamLock.Lock()
		delete(s.streams, sid)
		s.streamLock.Unlock()
		stream.closeLocally()
		return nil, err
	}

	return stream, nil
}

func (s *Session) getStream(sid uint32) (*Stream, bool) {
	s.streamLock.RLock()
	stream, ok := s.streams[sid]
	s.streamLock.RUnlock()
	return stream, ok
}

func (s *Session) recvLoop() error {
	defer func() {
		if r := recover(); r != nil {
			logrus.Errorln("[BUG]", r, string(debug.Stack()))
		}
	}()
	defer s.Close()

	var receivedSettingsFromClient bool
	var hdr rawHeader

	for {
		if s.IsClosed() {
			return io.ErrClosedPipe
		}

		if _, err := io.ReadFull(s.conn, hdr[:]); err != nil {
			return err
		}
		s.lastRecv.Store(time.Now().UnixNano())

		sid := hdr.StreamID()
		length := int(hdr.Length())

		// Every command's declared payload is consumed, whatever the command
		// is. A frame that carries an unexpected payload would otherwise
		// desync the whole session.
		var payload []byte
		if length > 0 {
			if hdr.Cmd() == cmdUpdatePaddingScheme {
				// The scheme is kept after the frame is handled, so it can not
				// come from the pooled allocator.
				payload = make([]byte, length)
			} else {
				payload = buf.Get(length)
			}
			if _, err := io.ReadFull(s.conn, payload); err != nil {
				if hdr.Cmd() != cmdUpdatePaddingScheme {
					buf.Put(payload)
				}
				return err
			}
		}

		switch hdr.Cmd() {
		case cmdPSH:
			if payload != nil {
				stream, ok := s.getStream(sid)
				if !ok {
					buf.Put(payload)
					break
				}
				// Waiting for delivery budget is backpressure, not death.
				s.blocked.Add(1)
				reserved := stream.reserve(len(payload))
				queued := false
				if reserved {
					queued = stream.push(payload)
				}
				s.blocked.Add(-1)
				if !queued {
					if reserved {
						stream.budget.release(len(payload))
					}
					buf.Put(payload)
				}
			}
		case cmdSYN: // should be server only
			if !s.isClient && !receivedSettingsFromClient {
				f := newFrame(cmdAlert, 0)
				f.data = []byte("client did not send its settings")
				s.writeControlFrame(f)
				return nil
			}
			s.streamLock.Lock()
			if _, ok := s.streams[sid]; !ok {
				stream := newStream(sid, s, nil)
				s.streams[sid] = stream
				go func() {
					if s.onNewStream != nil {
						s.onNewStream(stream)
					} else {
						stream.Close()
					}
				}()
			}
			s.streamLock.Unlock()
		case cmdSYNACK: // should be client only
			s.synDoneLock.Lock()
			if s.synDone != nil {
				s.synDone()
				s.synDone = nil
			}
			s.synDoneLock.Unlock()
			if payload != nil {
				if stream, ok := s.getStream(sid); ok {
					failure := fmt.Errorf("remote: %s", payload)
					stream.finish(true, failure)
					stream.finish(false, failure)
					s.removeStream(sid)
				}
			}
		case cmdFIN:
			s.streamLock.Lock()
			stream, ok := s.streams[sid]
			delete(s.streams, sid)
			s.streamLock.Unlock()
			if ok {
				// Queued payloads must reach the consumer before its read
				// side ends, so FIN becomes an end marker rather than a
				// hard close.
				stream.finishRemote()
			}
		case cmdWaste:
			// Padding: payload discarded below.
		case cmdSettings:
			if payload != nil && !s.isClient {
				receivedSettingsFromClient = true
				m := util.StringMapFromBytes(payload)
				paddingF := s.padding.Load()
				if m["padding-md5"] != paddingF.Md5 {
					f := newFrame(cmdUpdatePaddingScheme, 0)
					f.data = paddingF.RawScheme
					if _, err := s.writeControlFrame(f); err != nil {
						buf.Put(payload)
						return err
					}
				}
				// check client's version
				if v, err := strconv.Atoi(m["v"]); err == nil && v >= 2 {
					s.peerVersion.Store(uint32(v))
					f := newFrame(cmdServerSettings, 0)
					f.data = util.StringMap{
						"v": "2",
					}.ToBytes()
					if _, err := s.writeControlFrame(f); err != nil {
						buf.Put(payload)
						return err
					}
				}
			}
		case cmdAlert:
			if payload != nil {
				if s.isClient {
					logrus.Errorln("[Alert from server]", string(payload))
				}
				buf.Put(payload)
				return nil
			}
		case cmdUpdatePaddingScheme:
			if payload != nil && s.isClient && !clientDebugPaddingScheme {
				if padding.UpdatePaddingScheme(payload) {
					logrus.Debugf("[Update padding succeed] %x", md5.Sum(payload))
				} else {
					logrus.Warnf("[Update padding failed] %x", md5.Sum(payload))
				}
			}
		case cmdHeartRequest:
			if _, err := s.writeControlFrame(newFrame(cmdHeartResponse, sid)); err != nil {
				buf.Put(payload)
				return err
			}
		case cmdHeartResponse:
			// Liveness is tracked by lastRecv on every frame.
		case cmdServerSettings:
			if payload != nil && s.isClient {
				m := util.StringMapFromBytes(payload)
				if v, err := strconv.Atoi(m["v"]); err == nil {
					s.peerVersion.Store(uint32(v))
				}
			}
		default:
			// Unknown command: its payload was consumed above.
		}

		if payload != nil && hdr.Cmd() != cmdPSH && hdr.Cmd() != cmdUpdatePaddingScheme {
			buf.Put(payload)
		}
	}
}

// heartbeatLoop probes an idle session and closes it when the peer answers
// nothing for heartbeatTimeout. A peer that never announced protocol version 2
// does not understand the probe, so the timeout is not enforced for it.
func (s *Session) heartbeatLoop() {
	for {
		interval := time.Duration(s.heartbeatInterval.Load())
		if interval <= 0 {
			return
		}
		select {
		case <-s.die:
			return
		case <-time.After(interval):
		}
		if s.IsClosed() {
			return
		}
		if s.peerVersion.Load() < 2 {
			continue
		}
		timeout := time.Duration(s.heartbeatTimeout.Load())
		if timeout <= 0 {
			timeout = defaultHeartbeatTimeout
		}

		// The probe must go out now, not sit in the Settings buffer.
		s.connLock.Lock()
		s.buffering = false
		s.connLock.Unlock()

		sent := time.Now()
		if _, err := s.writeControlFrame(newFrame(cmdHeartRequest, 0)); err != nil {
			s.Close()
			return
		}
		deadline := sent.Add(timeout)
		for time.Now().Before(deadline) {
			if s.IsClosed() {
				return
			}
			// Any complete frame after the probe is a sign of life.
			if time.Unix(0, s.lastRecv.Load()).After(sent) {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if s.IsClosed() {
			return
		}
		if time.Unix(0, s.lastRecv.Load()).After(sent) {
			continue
		}
		// Read-loop goroutines parked on delivery budget have not seen the
		// peer's reply yet even though the peer is fine; do not judge them.
		if s.blocked.Load() > 0 {
			continue
		}
		logrus.Debugln("session heartbeat timeout")
		s.Close()
		return
	}
}

func (s *Session) streamClosed(sid uint32) error {
	if s.IsClosed() {
		return io.ErrClosedPipe
	}
	_, err := s.writeControlFrame(newFrame(cmdFIN, sid))
	s.removeStream(sid)
	return err
}

// streamFinishedWriting announces the local end of the writing direction. The
// stream stays registered because its reading direction may still be open.
func (s *Session) streamFinishedWriting(sid uint32) error {
	if s.IsClosed() {
		return io.ErrClosedPipe
	}
	_, err := s.writeControlFrame(newFrame(cmdFIN, sid))
	return err
}

func (s *Session) removeStream(sid uint32) {
	s.streamLock.Lock()
	delete(s.streams, sid)
	s.streamLock.Unlock()
}

func (s *Session) writeDataFrame(sid uint32, data []byte) (int, error) {
	written := 0
	for len(data) > 0 {
		chunk := data
		if len(chunk) > maxFramePayload {
			chunk = chunk[:maxFramePayload]
		}
		dataLen := len(chunk)

		buffer := buf.NewSize(dataLen + headerOverHeadSize)
		buffer.WriteByte(cmdPSH)
		binary.BigEndian.PutUint32(buffer.Extend(4), sid)
		binary.BigEndian.PutUint16(buffer.Extend(2), uint16(dataLen))
		buffer.Write(chunk)
		_, err := s.writeConn(buffer.Bytes(), dataWriteTimeout)
		buffer.Release()
		if err != nil {
			s.Close()
			return written, err
		}

		written += dataLen
		data = data[dataLen:]
	}
	return written, nil
}

func (s *Session) writeControlFrame(frame frame) (int, error) {
	dataLen := len(frame.data)

	buffer := buf.NewSize(dataLen + headerOverHeadSize)
	buffer.WriteByte(frame.cmd)
	binary.BigEndian.PutUint32(buffer.Extend(4), frame.sid)
	binary.BigEndian.PutUint16(buffer.Extend(2), uint16(dataLen))
	buffer.Write(frame.data)

	_, err := s.writeConn(buffer.Bytes(), controlWriteTimeout)
	buffer.Release()
	if err != nil {
		s.Close()
		return 0, err
	}

	return dataLen, nil
}

// writeConn serializes writes on the session connection and applies a write
// deadline so a peer that stops reading can not block the writer forever.
func (s *Session) writeConn(b []byte, timeout time.Duration) (n int, err error) {
	s.connLock.Lock()
	defer s.connLock.Unlock()

	if err := s.conn.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
		return 0, err
	}
	defer s.conn.SetWriteDeadline(time.Time{}) //nolint:errcheck

	if s.buffering {
		s.buffer = slices.Concat(s.buffer, b)
		return len(b), nil
	} else if len(s.buffer) > 0 {
		b = slices.Concat(s.buffer, b)
		s.buffer = nil
	}

	// calulate & send padding
	if s.sendPadding {
		pkt := s.pktCounter.Add(1)
		paddingF := s.padding.Load()
		if pkt < paddingF.Stop {
			pktSizes := paddingF.GenerateRecordPayloadSizes(pkt)
			for _, l := range pktSizes {
				remainPayloadLen := len(b)
				if l == padding.CheckMark {
					if remainPayloadLen == 0 {
						break
					} else {
						continue
					}
				}
				if remainPayloadLen > l { // this packet is all payload
					_, err = s.conn.Write(b[:l])
					if err != nil {
						return 0, err
					}
					n += l
					b = b[l:]
				} else if remainPayloadLen > 0 { // this packet contains padding and the last part of payload
					paddingLen := l - remainPayloadLen - headerOverHeadSize
					if paddingLen > 0 {
						padding := make([]byte, headerOverHeadSize+paddingLen)
						padding[0] = cmdWaste
						binary.BigEndian.PutUint32(padding[1:5], 0)
						binary.BigEndian.PutUint16(padding[5:7], uint16(paddingLen))
						b = slices.Concat(b, padding)
					}
					_, err = s.conn.Write(b)
					if err != nil {
						return 0, err
					}
					n += remainPayloadLen
					b = nil
				} else { // this packet is all padding
					padding := make([]byte, headerOverHeadSize+l)
					padding[0] = cmdWaste
					binary.BigEndian.PutUint32(padding[1:5], 0)
					binary.BigEndian.PutUint16(padding[5:7], uint16(l))
					_, err = s.conn.Write(padding)
					if err != nil {
						return 0, err
					}
					b = nil
				}
			}
			// maybe still remain payload to write
			if len(b) == 0 {
				return
			} else {
				n2, err := s.conn.Write(b)
				return n + n2, err
			}
		} else {
			s.sendPadding = false
		}
	}

	return s.conn.Write(b)
}
