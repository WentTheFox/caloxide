package webverify

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func sockPath(t *testing.T) string {
	t.Helper()
	// Unix socket paths are limited to ~100 bytes, so avoid the long t.TempDir().
	dir, err := os.MkdirTemp("", "pxc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return filepath.Join(dir, "c.sock")
}

func TestControlRoundTripAndSocketMode(t *testing.T) {
	path := sockPath(t)
	exp := time.Now().Add(10 * time.Minute).Round(time.Second)
	stop, err := ServeControl(path, "https://caloxide.went.local/", func() (string, time.Time, error) { return "TOK123", exp, nil })
	if err != nil {
		t.Fatal(err)
	}
	defer stop()

	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Errorf("socket mode = %v, want 0600", fi.Mode().Perm())
	}
	link, expires, err := RequestLink(path)
	if err != nil {
		t.Fatal(err)
	}
	if link != "https://caloxide.went.local/verify/TOK123" {
		t.Errorf("link = %q", link)
	}
	if !expires.Equal(exp) {
		t.Errorf("expires = %v, want %v", expires, exp)
	}
}

func TestControlRefusalsReachTheClient(t *testing.T) {
	path := sockPath(t)
	stop, err := ServeControl(path, "", func() (string, time.Time, error) {
		return "", time.Time{}, errors.New("the bridge is not waiting for human verification")
	})
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	if _, _, err := RequestLink(path); err == nil || !strings.Contains(err.Error(), "not waiting") {
		t.Errorf("want the refusal, got %v", err)
	}
}

func TestControlRejectsOtherRequests(t *testing.T) {
	path := sockPath(t)
	called := false
	stop, _ := ServeControl(path, "", func() (string, time.Time, error) { called = true; return "T", time.Now(), nil })
	defer stop()
	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.Write([]byte("shutdown\n"))
	buf := make([]byte, 200)
	n, _ := conn.Read(buf)
	if !strings.Contains(string(buf[:n]), "unknown request") || called {
		t.Errorf("reply %q, opener called: %v", buf[:n], called)
	}
}

func TestControlStaleSocketIsReplacedButFilesAreNeverDeleted(t *testing.T) {
	path := sockPath(t)
	// A stale socket from a crashed run.
	ln, _ := net.Listen("unix", path)
	ln.(*net.UnixListener).SetUnlinkOnClose(false)
	ln.Close()
	stop, err := ServeControl(path, "", func() (string, time.Time, error) { return "T", time.Now(), nil })
	if err != nil {
		t.Fatalf("a stale socket must be replaced: %v", err)
	}
	stop()
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Error("stop must remove the socket")
	}

	// A regular file in the way is an error, not something to delete.
	if err := os.WriteFile(path, []byte("precious"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ServeControl(path, "", func() (string, time.Time, error) { return "", time.Time{}, nil }); err == nil {
		t.Error("must refuse to replace a regular file")
	}
	if b, _ := os.ReadFile(path); string(b) != "precious" {
		t.Error("the regular file was damaged")
	}
}

func TestClientWithoutABridge(t *testing.T) {
	_, _, err := RequestLink(sockPath(t))
	if err == nil || !strings.Contains(err.Error(), "control socket") {
		t.Errorf("want a helpful error, got %v", err)
	}
}

func TestValidatePublicURL(t *testing.T) {
	for _, ok := range []string{"", "https://caloxide.went.local", "https://x.example/base", "http://127.0.0.1:8081", "http://localhost"} {
		if err := ValidatePublicURL(ok); err != nil {
			t.Errorf("%q should be valid: %v", ok, err)
		}
	}
	for _, bad := range []string{"http://caloxide.went.local", "ftp://x", "https://user:pw@x.example", "https://x.example/?a=b", "https://x.example/#f", "::::", "https://"} {
		if err := ValidatePublicURL(bad); err == nil {
			t.Errorf("%q should be rejected", bad)
		}
	}
	if _, err := ServeControl(sockPath(t), "http://evil.example", nil); err == nil {
		t.Error("ServeControl must reject a non-https public URL")
	}
}

func TestStatusRequestReturnsWhatTheProviderSays(t *testing.T) {
	path := sockPath(t)
	stop, err := ServeControlWith(path, "", nil, func() ([]byte, error) { return []byte(`{"users":[{"user":"me"}]}`), nil })
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	raw, err := RequestStatus(path)
	if err != nil || string(raw) != `{"users":[{"user":"me"}]}` {
		t.Fatalf("got %q, %v", raw, err)
	}
}

func TestStatusNeedsNoVerificationWindow(t *testing.T) {
	path := sockPath(t)
	opened := false
	stop, _ := ServeControlWith(path, "", func() (string, time.Time, error) { opened = true; return "T", time.Now(), nil },
		func() ([]byte, error) { return []byte(`{}`), nil })
	defer stop()
	if _, err := RequestStatus(path); err != nil {
		t.Fatal(err)
	}
	if opened {
		t.Fatal("asking for the status must never open a verification window")
	}
}

func TestStatusWithoutAProviderIsAnError(t *testing.T) {
	path := sockPath(t)
	stop, _ := ServeControl(path, "", func() (string, time.Time, error) { return "T", time.Now(), nil })
	defer stop()
	if _, err := RequestStatus(path); err == nil {
		t.Fatal("a server that cannot report a status must say so")
	}
}

func TestStatusProviderErrorsAreReported(t *testing.T) {
	path := sockPath(t)
	stop, _ := ServeControlWith(path, "", nil, func() ([]byte, error) { return nil, errTest })
	defer stop()
	if _, err := RequestStatus(path); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("err = %v", err)
	}
}

func TestOpenStillWorksAlongsideStatus(t *testing.T) {
	path := sockPath(t)
	exp := time.Now().Add(time.Minute)
	stop, _ := ServeControlWith(path, "https://x.example", func() (string, time.Time, error) { return "TOK", exp, nil },
		func() ([]byte, error) { return []byte(`{}`), nil })
	defer stop()
	link, _, err := RequestLink(path)
	if err != nil || !strings.HasSuffix(link, "TOK") {
		t.Fatalf("link = %q, %v", link, err)
	}
}

func TestStatusUnreachableServerHasAClearError(t *testing.T) {
	if _, err := RequestStatus(sockPath(t)); err == nil || !strings.Contains(err.Error(), "control socket") {
		t.Fatalf("err = %v", err)
	}
}

var errTest = errors.New("boom")
