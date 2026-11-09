// Package oolongtest starts an oolong TEA server (github.com/oolong-project/oolong,
// oolong/oolong-server) for integration tests.
//
// Start uses, in order:
//
//   - OOLONG_BASE_URL: a running server (for example http://127.0.0.1:3005
//     from oolong/docker-compose.tea-interop.yml).
//   - OOLONG_SERVER_DIR: an oolong/oolong-server directory where `npm ci` and
//     `npm run build` have run. The fixtures next to it
//     (../fixtures/tea-1.0.0) are copied into a temporary directory the
//     test owns, and `node dist/main.js` is started on a free port of
//     127.0.0.1 (node from PATH, or OOLONG_NODE).
//
// With neither set the test is skipped, unless TEA_INTEGRATION_REQUIRED=1,
// in which case it fails.
package oolongtest

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// Server is a running oolong server.
type Server struct {
	// URL is the server's origin, e.g. http://127.0.0.1:41234. It is the
	// API root (SERVER_HOST) and the base of /.well-known/tea.
	URL string
}

const readyTimeout = 30 * time.Second

// Start returns a running oolong server for t, or skips t (see the package
// documentation).
func Start(t testing.TB) *Server {
	t.Helper()
	if base := os.Getenv("OOLONG_BASE_URL"); base != "" {
		return &Server{URL: strings.TrimSuffix(base, "/")}
	}
	dir := os.Getenv("OOLONG_SERVER_DIR")
	if dir == "" {
		msg := "integration test needs an oolong server: set OOLONG_BASE_URL to a running one, " +
			"or OOLONG_SERVER_DIR to an oolong/oolong-server directory where `npm ci && npm run build` has run"
		if os.Getenv("TEA_INTEGRATION_REQUIRED") == "1" {
			t.Fatal(msg + " (TEA_INTEGRATION_REQUIRED=1)")
		}
		t.Skip(msg)
	}
	return startNode(t, dir)
}

// lockedBuffer collects the server's output from two goroutines.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func startNode(t testing.TB, dir string) *Server {
	t.Helper()
	dir, err := filepath.Abs(dir)
	if err != nil {
		t.Fatal(err)
	}
	mainJS := filepath.Join(dir, "dist", "main.js")
	if _, err := os.Stat(mainJS); err != nil {
		t.Fatalf("OOLONG_SERVER_DIR: %v (run `npm ci && npm run build` there first)", err)
	}
	node := os.Getenv("OOLONG_NODE")
	if node == "" {
		if node, err = exec.LookPath("node"); err != nil {
			t.Fatalf("node not found on PATH (or set OOLONG_NODE): %v", err)
		}
	}

	content := filepath.Join(t.TempDir(), "content")
	if err := copyTree(filepath.Join(dir, "..", "fixtures", "tea-1.0.0"), content); err != nil {
		t.Fatalf("copying fixtures: %v", err)
	}
	port, err := freePort()
	if err != nil {
		t.Fatal(err)
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	url := "http://127.0.0.1:" + port

	cmd := exec.Command(node, mainJS)
	cmd.Dir = dir
	cmd.Env = []string{
		"PORT=" + port,
		"SERVER_HOST=" + url,
		"CONTENT_DIR=" + content,
		"NODE_ENV=production",
		"API_VERSION=1.0.0",
		"PAGE_TOKEN_SECRET=" + hex.EncodeToString(secret),
	}
	out := &lockedBuffer{}
	cmd.Stdout, cmd.Stderr = out, out
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting %s: %v", mainJS, err)
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		<-exited
		if t.Failed() {
			t.Logf("oolong server output:\n%s", out.String())
		}
	})

	if err := waitReady(url, exited); err != nil {
		t.Fatalf("oolong server at %s: %v\noutput:\n%s", url, err, out.String())
	}
	return &Server{URL: url}
}

// waitReady polls /.well-known/tea until it answers 200 (it is 503 until
// the content is loaded).
func waitReady(url string, exited <-chan error) error {
	ctx, cancel := context.WithTimeout(context.Background(), readyTimeout)
	defer cancel()
	client := &http.Client{Timeout: 2 * time.Second}
	last := "no answer"
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url+"/.well-known/tea", nil)
		if err != nil {
			return err
		}
		if resp, err := client.Do(req); err == nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
			last = resp.Status
		} else {
			last = err.Error()
		}
		select {
		case err := <-exited:
			return fmt.Errorf("process exited before it was ready: %v", err)
		case <-ctx.Done():
			return fmt.Errorf("not ready after %v (last: %s)", readyTimeout, last)
		case <-time.After(200 * time.Millisecond):
		}
	}
}

func freePort() (string, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	defer l.Close()
	_, port, err := net.SplitHostPort(l.Addr().String())
	return port, err
}

// copyTree copies a directory of regular files; anything else is refused.
func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		switch {
		case d.IsDir():
			return os.MkdirAll(target, 0o755)
		case d.Type().IsRegular():
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			return os.WriteFile(target, b, 0o644)
		default:
			return fmt.Errorf("%s is not a regular file or directory", path)
		}
	})
}
