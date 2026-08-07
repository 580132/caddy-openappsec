//go:build e2e

// Package e2e is the cross-process end-to-end test harness for the
// caddy-openappsec module. It builds the mock engine (cmd/mockengine) and a
// Caddy server with the module compiled in (cmd/caddy) once, then spawns them
// as REAL subprocesses talking over the TCP socket transport, and drives real
// HTTP requests through the resulting stack. There are no in-process seams:
// the app, handler, mock engine, and transport all run inside their own
// processes.
//
// Run with:  go test -tags e2e ./internal/e2e/ -v -count=1
package e2e

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	// buildTimeout bounds each `go build` invocation made from inside the
	// test process. The first cold caddy build can take a while on Windows.
	buildTimeout = 10 * time.Minute
	// processBootTimeout bounds waiting for a subprocess to report readiness
	// (the mock engine's "listening on %q" line, or a caddy TCP listener).
	processBootTimeout = 10 * time.Second
)

// Binary build state, populated once in TestMain via buildBinaries.
var (
	binOnce      sync.Once
	binariesOK   error
	mockBinPath  string
	caddyBinPath string
	buildDirPath string
)

// repoRoot returns the module root, the parent of internal/e2e.
func repoRoot() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("getwd: %w", err)
	}
	root := filepath.Dir(filepath.Dir(wd))
	if fi, err := os.Stat(filepath.Join(root, "go.mod")); err != nil || fi.IsDir() {
		return "", fmt.Errorf("module root %q has no go.mod", root)
	}
	return root, nil
}

// goExe resolves the go toolchain. The scoop shim directory is on PATH on
// this box; fall back to the known shim path so the harness also works when
// PATH does not carry it.
func goExe() string {
	if p, err := exec.LookPath("go"); err == nil {
		return p
	}
	const scoopShim = `C:\Users\MSI-NB\scoop\shims\go.exe`
	if _, err := os.Stat(scoopShim); err == nil {
		return scoopShim
	}
	return "go"
}

// buildBinaries compiles cmd/mockengine and cmd/caddy exactly once into a
// shared temp dir and verifies the resulting caddy binary registers the
// openappsec modules. It is invoked from TestMain; a failure aborts the
// whole suite.
func buildBinaries() error {
	binOnce.Do(func() {
		root, err := repoRoot()
		if err != nil {
			binariesOK = err
			return
		}
		dir, err := os.MkdirTemp("", "caddy-openappsec-e2e-*")
		if err != nil {
			binariesOK = fmt.Errorf("mkdirtemp: %w", err)
			return
		}
		buildDirPath = dir
		mockBinPath = filepath.Join(dir, "mockengine.exe")
		caddyBinPath = filepath.Join(dir, "caddy.exe")

		for _, job := range []struct{ pkg, out string }{
			{"./cmd/mockengine", mockBinPath},
			{"./cmd/caddy", caddyBinPath},
		} {
			ctx, cancel := context.WithTimeout(context.Background(), buildTimeout)
			cmd := exec.CommandContext(ctx, goExe(), "build", "-o", job.out, job.pkg)
			cmd.Dir = root
			out, err := cmd.CombinedOutput()
			cancel()
			if err != nil {
				binariesOK = fmt.Errorf("go build %s: %w\n%s", job.pkg, err, out)
				return
			}
		}

		// The whole point of building ./cmd/caddy is that the openappsec
		// module is registered in the binary. Verify it before running any
		// scenario so a regression here fails loudly and once.
		out, err := exec.Command(caddyBinPath, "list-modules").CombinedOutput()
		if err != nil {
			binariesOK = fmt.Errorf("caddy list-modules: %w", err)
			return
		}
		if !bytes.Contains(out, []byte("http.openappsec")) ||
			!bytes.Contains(out, []byte("http.handlers.openappsec")) {
			binariesOK = fmt.Errorf("caddy binary missing openappsec modules; modules:\n%s", out)
		}
	})
	return binariesOK
}

// binaries returns the built binary paths, failing the test if TestMain did
// not build them.
func binaries(t *testing.T) (mockBin, cadBin string) {
	t.Helper()
	if binariesOK != nil {
		t.Fatalf("e2e binaries were not built: %v", binariesOK)
	}
	if mockBinPath == "" || caddyBinPath == "" {
		t.Fatal("e2e binaries not built (TestMain did not run?)")
	}
	return mockBinPath, caddyBinPath
}

// lockedBuffer is a mutex-guarded bytes.Buffer fed by a subprocess's
// combined output pipe.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// proc is a running subprocess with its combined stdout+stderr captured into
// a lockedBuffer. stop kills it reliably and waits for the drain so no
// goroutine is left behind; t.Cleanup registers the stop.
type proc struct {
	cmd  *exec.Cmd
	out  lockedBuffer
	done chan struct{} // closed once the process has exited and output drained
}

// startProcess spawns cmd with stdout+stderr piped to a shared buffer, and
// registers a cleanup that kills it. The pipe is drained in a goroutine so a
// chatty process can never deadlock the harness.
func startProcess(t *testing.T, name string, cmd *exec.Cmd) *proc {
	t.Helper()
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatalf("%s: pipe: %v", name, err)
	}
	cmd.Stdout = pw
	cmd.Stderr = pw
	if err := cmd.Start(); err != nil {
		_ = pw.Close()
		_ = pr.Close()
		t.Fatalf("%s: start: %v", name, err)
	}
	_ = pw.Close()
	p := &proc{cmd: cmd, done: make(chan struct{})}
	go func() {
		_, _ = io.Copy(&p.out, pr)
		_ = pr.Close()
		_ = cmd.Wait()
		close(p.done)
	}()
	t.Cleanup(func() { p.stop() })
	return p
}

// stop kills the process (idempotent) and waits for the drain goroutine so
// the harness never leaks output readers or child processes.
func (p *proc) stop() {
	if p.cmd.Process != nil {
		_ = p.cmd.Process.Kill()
	}
	select {
	case <-p.done:
	case <-time.After(10 * time.Second):
	}
}

// output returns the combined output captured so far.
func (p *proc) output() string { return p.out.String() }

// exited reports whether the process has exited and been waited on.
func (p *proc) exited() bool {
	select {
	case <-p.done:
		return true
	default:
		return false
	}
}

// engineProc is a running mock engine with its canonical tcp:// listener
// address parsed from the "listening on %q" readiness line.
type engineProc struct {
	p        *proc
	addr     string // canonical "tcp://host:port"
	scenario string
}

// output returns the mock engine's captured combined output.
func (e *engineProc) output() string { return e.p.output() }

// caddyProc is a running caddy server bound to a unique loopback port.
type caddyProc struct {
	p    *proc
	port int
}

// URL returns the site URL for the running caddy server.
func (c *caddyProc) URL() string {
	return urlForPort(c.port)
}

// output returns the caddy server's captured combined output.
func (c *caddyProc) output() string { return c.p.output() }

// startMockEngine spawns the mock engine in socket mode on an ephemeral port
// and waits for its "listening on %q" line to learn the bound tcp:// address.
func startMockEngine(t *testing.T, scenario string, requests int) *engineProc {
	t.Helper()
	mockBin, _ := binaries(t)
	cmd := exec.Command(mockBin,
		"-transport", "socket",
		"-addr", "127.0.0.1:0",
		"-scenario", scenario,
		"-requests", strconv.Itoa(requests),
	)
	p := startProcess(t, "mockengine["+scenario+"]", cmd)

	// The mock engine logs `mock engine listening on %q (transport ...)`
	// with the canonical bound address; that is the engine discovery contract.
	re := regexp.MustCompile(`listening on "([^"]+)"`)
	addr := waitForMatch(t, p, re, processBootTimeout)
	t.Logf("mock engine [%s] listening at %s", scenario, addr)
	return &engineProc{p: p, addr: addr, scenario: scenario}
}

// startCaddy writes a Caddyfile that fronts the given engine over the socket
// transport, spawns `caddy run` on a freshly probed loopback port, and waits
// until the port accepts connections. origin is the handler text that follows
// the openappsec directive inside the route block (e.g. `respond "hello"`).
// extraEngine are additional engine-block subdirectives such as fail-open
// timeouts. The port is retried on collision.
func startCaddy(t *testing.T, engineAddr, origin string, extraEngine ...string) *caddyProc {
	t.Helper()
	_, cadBin := binaries(t)

	var (
		p        *proc
		sitePort int
	)
	for attempt := 0; attempt < 3; attempt++ {
		sitePort = freePort(t)
		cf := writeCaddyfile(t, sitePort, engineAddr, origin, extraEngine)
		cmd := exec.Command(cadBin, "run", "--config", cf, "--adapter", "caddyfile")
		p = startProcess(t, "caddy", cmd)
		if waitForTCP(t, sitePort, processBootTimeout) {
			t.Logf("caddy ready at %s", urlForPort(sitePort))
			return &caddyProc{p: p, port: sitePort}
		}
		if p.exited() {
			// A bind failure is a port race worth retrying; any other early
			// exit is a configuration error that will not fix itself.
			if strings.Contains(p.output(), "bind") ||
				strings.Contains(p.output(), "in use") ||
				strings.Contains(p.output(), "permitted") {
				t.Logf("caddy port %d collision; retrying", sitePort)
				continue
			}
			t.Fatalf("caddy exited during startup; output:\n%s", p.output())
		}
		p.stop() // wedged without accepting connections; clean up before retry
		t.Logf("caddy did not accept connections on port %d within %v; retrying (attempt %d)",
			sitePort, processBootTimeout, attempt+1)
	}
	t.Fatalf("caddy failed to become ready after 3 attempts; last output:\n%s", p.output())
	return nil
}

// writeCaddyfile renders the site block for the harness: a route that runs
// the openappsec handler FIRST (directive order inside `route` is preserved,
// so the engine verdict gates the origin), then the given origin handler.
// The site is explicitly http:// so Caddy never engages auto-HTTPS or the
// admin endpoint during the test.
func writeCaddyfile(t *testing.T, sitePort int, engineAddr, origin string, extraEngine []string) string {
	t.Helper()
	var sb strings.Builder
	sb.WriteString("{\n\tadmin off\n}\n\n")
	fmt.Fprintf(&sb, "http://127.0.0.1:%d {\n", sitePort)
	sb.WriteString("\troute {\n")
	sb.WriteString("\t\topenappsec {\n")
	sb.WriteString("\t\t\tengine {\n")
	sb.WriteString("\t\t\t\ttransport socket\n")
	fmt.Fprintf(&sb, "\t\t\t\tregistration_socket %s\n", engineAddr)
	fmt.Fprintf(&sb, "\t\t\t\tkeep_alive_path %s\n", engineAddr)
	sb.WriteString("\t\t\t\tfamily_name e2e\n")
	for _, e := range extraEngine {
		sb.WriteString("\t\t\t\t" + e + "\n")
	}
	sb.WriteString("\t\t\t}\n")
	sb.WriteString("\t\t}\n")
	sb.WriteString("\t\t" + origin + "\n")
	sb.WriteString("\t}\n")
	sb.WriteString("}\n")

	f, err := os.CreateTemp("", "caddy-e2e-*.Caddyfile")
	if err != nil {
		t.Fatalf("create temp Caddyfile: %v", err)
	}
	if _, err := io.WriteString(f, sb.String()); err != nil {
		_ = f.Close()
		t.Fatalf("write Caddyfile: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close Caddyfile: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(f.Name()) })
	t.Logf("Caddyfile:\n%s", sb.String())
	return f.Name()
}

// freePort probes a free loopback port by binding :0 and closing it. The
// caller must handle the (rare) race where the port is taken before use.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("free port probe: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return port
}

// waitForTCP polls addr until a TCP connection succeeds or timeout elapses.
func waitForTCP(t *testing.T, port int, timeout time.Duration) bool {
	t.Helper()
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

func urlForPort(port int) string {
	return fmt.Sprintf("http://127.0.0.1:%d/", port)
}

// waitForMatch polls p's output until it matches re (bounded by timeout) and
// returns the first capture group. It fails the test with the captured output
// so a hung or misbehaving subprocess is diagnosed, not silently retried.
func waitForMatch(t *testing.T, p *proc, re *regexp.Regexp, timeout time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if m := re.FindStringSubmatch(p.output()); m != nil {
			return m[1]
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out after %v waiting for %s in process output (exited=%v):\n%s",
		timeout, re, p.exited(), p.output())
	return ""
}

// waitForOutputSubstr polls p's output until it contains substr (bounded by
// timeout), failing the test otherwise.
func waitForOutputSubstr(t *testing.T, p *proc, substr string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if strings.Contains(p.output(), substr) {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out after %v waiting for %q in process output; output:\n%s",
		timeout, substr, p.output())
}

// getOnce issues one GET with a per-request timeout, reading the whole body.
func getOnce(url string, timeout time.Duration) (*http.Response, []byte, error) {
	client := &http.Client{Timeout: timeout}
	resp, err := client.Get(url)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	return resp, body, err
}

// getWithRetry issues GET to url until it succeeds at the connection level
// within window. It returns the final response and body, or fails the test.
// Every request carries a hard per-request timeout, so a hung subprocess
// fails the test instead of hanging the suite.
func getWithRetry(t *testing.T, url string, window time.Duration) (*http.Response, []byte) {
	t.Helper()
	deadline := time.Now().Add(window)
	var lastErr error
	for time.Now().Before(deadline) {
		resp, body, err := getOnce(url, 30*time.Second)
		if err == nil {
			return resp, body
		}
		lastErr = err
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("GET %s did not succeed within %v; last error: %v", url, window, lastErr)
	return nil, nil
}
