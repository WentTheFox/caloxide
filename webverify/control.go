package webverify

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strings"
	"time"
)

// The control socket is how `caloxide verify`, run where the server runs (inside the container, for
// example with `docker exec`), asks the running bridge to open a verification
// window. It is a unix socket in the bridge's private config directory, mode 0600,
// so only the bridge's own user can use it. It is not a network service.

const ioTimeout = 5 * time.Second

type linkReply struct {
	URL     string    `json:"url,omitempty"`
	Expires time.Time `json:"expires,omitempty"`
	Error   string    `json:"error,omitempty"`
}

// Opener opens a window and returns its one-time token and expiry.
type Opener func() (token string, expires time.Time, err error)

// ValidatePublicURL checks the externally visible base URL used to build links.
// It must be https (plain http only for loopback) with no credentials, query or
// fragment. An empty value is allowed and yields path-only links.
func ValidatePublicURL(raw string) error {
	if raw == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return errors.New("not a valid URL")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("must not contain credentials, a query or a fragment")
	}
	switch u.Scheme {
	case "https":
	case "http":
		h := u.Hostname()
		if ip := net.ParseIP(h); h != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return errors.New("plain http is only allowed for a loopback host")
		}
	default:
		return errors.New("scheme must be https")
	}
	return nil
}

// Link builds the one-time URL for a token.
func Link(publicURL, token string) string {
	return strings.TrimRight(publicURL, "/") + PathPrefix + token
}

// ServeControl listens on the unix socket at path and answers each "open" request
// with a one-time link. The returned function stops the listener and removes the
// socket.
func ServeControl(path, publicURL string, open Opener) (stop func(), err error) {
	if err := ValidatePublicURL(publicURL); err != nil {
		return nil, fmt.Errorf("public URL: %v", err)
	}
	// Replace a stale socket left by a crash, but never delete anything else.
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("%s exists and is not a socket", path)
		}
		os.Remove(path)
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		os.Remove(path)
		return nil, err
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return // closed by stop
			}
			go serveOne(conn, publicURL, open)
		}
	}()
	return func() { ln.Close(); os.Remove(path) }, nil
}

func serveOne(conn net.Conn, publicURL string, open Opener) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(ioTimeout))
	line, err := bufio.NewReader(io.LimitReader(conn, 64)).ReadString('\n')
	if err != nil || strings.TrimSpace(line) != "open" {
		json.NewEncoder(conn).Encode(linkReply{Error: "unknown request"})
		return
	}
	token, expires, err := open()
	if err != nil {
		json.NewEncoder(conn).Encode(linkReply{Error: err.Error()})
		return
	}
	json.NewEncoder(conn).Encode(linkReply{URL: Link(publicURL, token), Expires: expires})
}

// RequestLink asks the bridge listening on the socket at path for a one-time link.
func RequestLink(path string) (link string, expires time.Time, err error) {
	conn, err := net.DialTimeout("unix", path, ioTimeout)
	if err != nil {
		return "", time.Time{}, errors.New("cannot reach the bridge's control socket; is the bridge running with the secrets backend enabled?")
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(ioTimeout))
	if _, err := io.WriteString(conn, "open\n"); err != nil {
		return "", time.Time{}, err
	}
	var r linkReply
	if err := json.NewDecoder(io.LimitReader(conn, 4096)).Decode(&r); err != nil {
		return "", time.Time{}, errors.New("unreadable reply from the bridge")
	}
	if r.Error != "" {
		return "", time.Time{}, errors.New(r.Error)
	}
	return r.URL, r.Expires, nil
}
