package proxy

import (
	"errors"
	"io"
	"net"
)

// Relay copies between conn and peer until both directions are done.
//
// AnyTLS closes a stream as a whole (cmdFIN carries no direction flag), so an
// upload EOF - the caller half-closing its side, as a client does after sending
// an HTTP request - must NOT close the stream: the peer's response still has to
// arrive. Copying the download direction on this goroutine and letting it run
// to the peer's close is what makes such a half-close behave like plain TCP.
func Relay(conn, peer net.Conn) (uploaded, downloaded int64, err error) {
	type result struct {
		n   int64
		err error
	}

	up := make(chan result, 1)
	go func() {
		n, copyErr := io.Copy(peer, conn)
		up <- result{n, copyErr}
	}()

	downed, downErr := io.Copy(conn, peer)

	// The peer closed the stream, so nothing more can be written to it; stop
	// the upload copy instead of leaving it parked in a read on conn.
	_ = conn.Close()
	uped := <-up

	if downErr != nil && !isClosedConn(downErr) {
		err = downErr
	} else if uped.err != nil && !isClosedConn(uped.err) {
		err = uped.err
	}
	return uped.n, downed, err
}

// isClosedConn reports errors produced by our own conn.Close.
func isClosedConn(err error) bool {
	return errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrClosedPipe)
}
