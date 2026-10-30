package edge

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

const csConfig = "/data/crowdsec/config.yaml"

func Generate(c Config, check bool) error {
	for _, p := range []string{"/data/logs", "/data/crowdsec", "/data/caddy"} {
		if e := os.MkdirAll(p, 0700); e != nil {
			return e
		}
	}
	logFile, err := os.OpenFile("/data/logs/access.json", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if err = logFile.Close(); err != nil {
		return err
	}
	text, e := Render(c)
	if e != nil {
		return e
	}
	if check {
		text = strings.ReplaceAll(text, "  enable_hard_fails\n", "")
	}
	if e = AtomicWrite("/data/Caddyfile", []byte(text), 0600); e != nil {
		return e
	}
	return nil
}

func Check(c Config) error {
	if e := Generate(c, true); e != nil {
		return e
	}
	cmd := exec.Command("/usr/bin/caddy", "validate", "--config", "/data/Caddyfile", "--adapter", "caddyfile")
	cmd.Env = append(os.Environ(), "CROWDSEC_API_KEY=config-validation-only")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func secret(path string, n int) error {
	if _, e := os.Stat(path); e == nil {
		return nil
	} else if !os.IsNotExist(e) {
		return e
	}
	b := make([]byte, n)
	if _, e := rand.Read(b); e != nil {
		return e
	}
	return AtomicWrite(path, []byte(hex.EncodeToString(b)), 0600)
}

func cs(args ...string) error {
	cmd := exec.Command("/usr/local/bin/cscli", append([]string{"-c", csConfig}, args...)...)
	out, e := cmd.CombinedOutput()
	if e != nil {
		return fmt.Errorf("cscli %s: %w: %s", args[0], e, out)
	}
	return nil
}

func prepareCrowdSec() error {
	b, e := os.ReadFile("/opt/web-edge/crowdsec.yaml")
	if e != nil {
		return e
	}
	if e = AtomicWrite(csConfig, b, 0600); e != nil {
		return e
	}
	if _, e = os.Stat("/data/crowdsec/credentials.yaml"); os.IsNotExist(e) {
		if e = cs("machines", "add", "web-edge", "--auto", "--force", "--url", "http://127.0.0.1:8081", "--file", "/data/crowdsec/credentials.yaml"); e != nil {
			return e
		}
	}
	if _, e = os.Stat("/data/crowdsec/bouncer.key"); os.IsNotExist(e) {
		// A fresh name makes recovery safe if the database survived but the key did not.
		id := make([]byte, 8)
		if _, e = rand.Read(id); e != nil {
			return e
		}
		cmd := exec.Command("/usr/local/bin/cscli", "-c", csConfig, "bouncers", "add", "web-edge-"+hex.EncodeToString(id), "-o", "raw")
		var errbuf strings.Builder
		cmd.Stderr = &errbuf
		key, e := cmd.Output()
		if e != nil {
			return fmt.Errorf("initialize bouncer: %w: %s", e, errbuf.String())
		}
		if e = AtomicWrite("/data/crowdsec/bouncer.key", []byte(strings.TrimSpace(string(key))), 0600); e != nil {
			return e
		}
	}
	return nil
}

type LogRecord struct {
	Timestamp string `json:"timestamp"`
	Node      string `json:"node"`
	HostIP    string `json:"host_ip,omitempty"`
	Container string `json:"container"`
	Service   string `json:"service"`
	Message   string `json:"message"`
}

func Record(id Identity, service, line string) LogRecord {
	return LogRecord{time.Now().UTC().Format(time.RFC3339Nano), id.Node, id.HostIP, id.Container, service, line}
}

func Serve(c Config) error {
	if e := Generate(c, false); e != nil {
		return e
	}
	if e := secret("/data/anubis.key", 32); e != nil {
		return e
	}
	if e := prepareCrowdSec(); e != nil {
		return e
	}
	key, e := os.ReadFile("/data/crowdsec/bouncer.key")
	if e != nil {
		return e
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	var children []*exec.Cmd
	defer func() {
		for _, p := range children {
			_ = p.Process.Signal(syscall.SIGTERM)
		}
		time.Sleep(500 * time.Millisecond)
		for _, p := range children {
			_ = p.Process.Kill()
		}
	}()
	failures := make(chan error, 3)
	var logLock sync.Mutex
	start := func(name, bin string, args, extraEnv []string) error {
		cmd := exec.Command(bin, args...)
		cmd.Env = append(os.Environ(), extraEnv...)
		r, w, e := os.Pipe()
		if e != nil {
			return e
		}
		cmd.Stdout = w
		cmd.Stderr = w
		if e = cmd.Start(); e != nil {
			r.Close()
			w.Close()
			return e
		}
		w.Close()
		children = append(children, cmd)
		go func() {
			defer r.Close()
			sc := bufio.NewScanner(r)
			sc.Buffer(make([]byte, 64*1024), 1024*1024)
			for sc.Scan() {
				logLock.Lock()
				_ = json.NewEncoder(os.Stdout).Encode(Record(c.Identity, name, sc.Text()))
				logLock.Unlock()
			}
		}()
		go func() { e := cmd.Wait(); failures <- fmt.Errorf("%s stopped: %v", name, e) }()
		return nil
	}
	if e = start("crowdsec", "/usr/local/bin/crowdsec", []string{"-c", csConfig}, nil); e != nil {
		return e
	}
	if e = waitPort(ctx, "127.0.0.1:8081", failures); e != nil {
		return e
	}
	if e = start("anubis", "/usr/bin/anubis", nil, AnubisEnv(c)); e != nil {
		return e
	}
	if e = waitPort(ctx, "127.0.0.1:8923", failures); e != nil {
		return e
	}
	if e = start("caddy", "/usr/bin/caddy", []string{"run", "--config", "/data/Caddyfile", "--adapter", "caddyfile"}, []string{"CROWDSEC_API_KEY=" + string(key)}); e != nil {
		return e
	}
	select {
	case <-ctx.Done():
		return nil
	case e := <-failures:
		return e
	}
}

func waitPort(ctx context.Context, addr string, failures <-chan error) error {
	for i := 0; i < 100; i++ {
		c, e := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if e == nil {
			c.Close()
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case e := <-failures:
			return e
		case <-time.After(200 * time.Millisecond):
		}
	}
	return fmt.Errorf("service at %s did not start", addr)
}

func Health() error {
	for _, p := range []string{"2019", "8081", "8923"} {
		c, e := net.DialTimeout("tcp", "127.0.0.1:"+p, time.Second)
		if e != nil {
			return e
		}
		c.Close()
	}
	return nil
}

// Export a persisted log/CA without exposing other state or private keys.
func Export(name string, w io.Writer) error {
	paths := map[string]string{"access": "/data/logs/access.json", "ca": "/data/caddy/caddy/pki/authorities/local/root.crt"}
	p, ok := paths[name]
	if !ok {
		return errors.New("export: expected access or ca")
	}
	f, e := os.Open(filepath.Clean(p))
	if e != nil {
		return e
	}
	defer f.Close()
	_, e = io.Copy(w, f)
	return e
}
