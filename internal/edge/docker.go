package edge

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

func Docker(args ...string) error {
	c := exec.Command("docker", args...)
	c.Stdin = os.Stdin
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	return c.Run()
}

func dockerOutput(args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, "docker", args...).CombinedOutput()
}

func ensureImage(image string) error {
	if !ValidImage(image) {
		return errors.New("invalid image reference")
	}
	if _, e := dockerOutput("info", "--format", "{{.OSType}}"); e != nil {
		return fmt.Errorf("Docker недоступен: %w; установите Docker Engine и запустите CLI через sudo", e)
	}
	if _, e := dockerOutput("image", "inspect", image); e != nil {
		if image == DefaultImage {
			return loadReleaseImage(image)
		}
		return Docker("pull", image)
	}
	return nil
}

// The official image is distributed as a public GitHub release asset. No
// registry account is needed. A checksum is verified before docker load.
func loadReleaseImage(image string) error {
	version := strings.TrimPrefix(image, "web-edge:")
	if version == image || !imageValue.MatchString(version) {
		return errors.New("invalid release image version")
	}
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		return errors.New("supported architectures: amd64, arm64")
	}
	base := "https://github.com/k1dory/web-edge/releases/download/v" + version + "/"
	name := "web-edge-image-linux-" + runtime.GOARCH + ".tar.gz"
	client := http.Client{Timeout: 10 * time.Minute}
	fetch := func(path string) (*http.Response, error) {
		r, e := client.Get(base + path)
		if e != nil {
			return nil, e
		}
		if r.StatusCode != 200 {
			r.Body.Close()
			return nil, fmt.Errorf("release download %s: HTTP %d", path, r.StatusCode)
		}
		return r, nil
	}
	r, e := fetch("SHA256SUMS")
	if e != nil {
		return e
	}
	manifest, e := io.ReadAll(io.LimitReader(r.Body, 64*1024))
	r.Body.Close()
	if e != nil {
		return e
	}
	want := ""
	for _, line := range strings.Split(string(manifest), "\n") {
		parts := strings.Fields(line)
		if len(parts) == 2 && strings.TrimPrefix(parts[1], "*") == name {
			want = parts[0]
		}
	}
	if b, e := hex.DecodeString(want); e != nil || len(b) != 32 {
		return errors.New("image checksum missing from release manifest")
	}
	d, e := os.MkdirTemp("", "web-edge-image-")
	if e != nil {
		return e
	}
	defer os.RemoveAll(d)
	p := filepath.Join(d, name)
	f, e := os.Create(p)
	if e != nil {
		return e
	}
	fmt.Println("Скачиваю проверяемый образ из GitHub Releases:", name)
	r, e = fetch(name)
	if e != nil {
		f.Close()
		return e
	}
	h := sha256.New()
	n, copyErr := io.Copy(io.MultiWriter(f, h), io.LimitReader(r.Body, 1024*1024*1024+1))
	r.Body.Close()
	closeErr := f.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	if n > 1024*1024*1024 {
		return errors.New("image exceeds 1 GiB download limit")
	}
	if hex.EncodeToString(h.Sum(nil)) != strings.ToLower(want) {
		return errors.New("image SHA-256 mismatch; not loading")
	}
	if e = Docker("load", "-i", p); e != nil {
		return e
	}
	if _, e = dockerOutput("image", "inspect", image); e != nil {
		return errors.New("release archive did not contain expected image")
	}
	return nil
}

func ExistingImage() (string, error) {
	i, e := inspect()
	if e != nil {
		return "", e
	}
	if i != nil {
		return i.Config.Image, nil
	}
	return DefaultImage, nil
}

type containerInfo struct {
	Config struct {
		Image  string
		Labels map[string]string
	}
	State struct {
		Running bool
		Health  struct{ Status string }
	}
}

func inspect() (*containerInfo, error) {
	b, e := dockerOutput("inspect", Container)
	if e != nil {
		if strings.Contains(string(b), "No such") {
			return nil, nil
		}
		return nil, fmt.Errorf("docker inspect: %s", b)
	}
	var list []containerInfo
	if e = json.Unmarshal(b, &list); e != nil || len(list) != 1 {
		return nil, errors.New("invalid docker inspect response")
	}
	if list[0].Config.Labels["io.web-edge.managed"] != "true" {
		return nil, errors.New("container named web-edge is not managed by this CLI; refusing to replace it")
	}
	return &list[0], nil
}

func runContainer(path, image string) error {
	return Docker("run", "-d", "--name", Container, "--label", "io.web-edge.managed=true",
		"--restart", "unless-stopped", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
		"--pids-limit", "256", "--memory", "2g", "--cpus", "2", "--stop-timeout", "20",
		"--tmpfs", "/tmp:rw,nosuid,nodev,size=128m,uid=10001,gid=10001",
		"--mount", "type=volume,src=web-edge-data,dst=/data",
		"--mount", "type=bind,src="+path+",dst=/config/config.json,readonly",
		"-p", "80:8080/tcp", "-p", "443:8443/tcp",
		"--log-driver", "json-file", "--log-opt", "max-size=10m", "--log-opt", "max-file=3", image)
}

// Validate a candidate before replacing a running container. It has no network,
// state volume, Docker socket or credentials from the running instance.
func ValidateImage(c Config, image string) error {
	if e := ensureImage(image); e != nil {
		return e
	}
	d, e := os.MkdirTemp("", "web-edge-check-")
	if e != nil {
		return e
	}
	defer os.RemoveAll(d)
	if e = os.Chmod(d, 0755); e != nil {
		return e
	}
	p := filepath.Join(d, "config.json")
	if e = Save(p, c); e != nil {
		return e
	}
	return Docker("run", "--rm", "--network=none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
		"--pids-limit", "128", "--memory", "1g", "--cpus", "2",
		"--tmpfs", "/data:rw,nosuid,nodev,size=64m,uid=10001,gid=10001",
		"--tmpfs", "/tmp:rw,nosuid,nodev,size=128m,uid=10001,gid=10001",
		"--mount", "type=bind,src="+p+",dst=/config/config.json,readonly", image, "check-config")
}

func Apply(c Config, path, image string, start bool) error {
	if err := c.Validate(); err != nil {
		return err
	}
	path, e := filepath.Abs(path)
	if e != nil {
		return e
	}
	if strings.ContainsAny(path, ",\r\n") {
		return errors.New("config path cannot contain comma/newline")
	}
	if !start {
		return Save(path, c)
	}
	if e = ValidateImage(c, image); e != nil {
		return fmt.Errorf("candidate rejected; running service unchanged: %w", e)
	}
	old, e := inspect()
	if e != nil {
		return e
	}
	previous, readErr := os.ReadFile(path)
	if old != nil && readErr != nil {
		return errors.New("cannot back up existing config; refusing to replace running container")
	}
	if e = Save(path, c); e != nil {
		return e
	}
	if old != nil {
		if e = Docker("rm", "-f", Container); e != nil {
			_ = AtomicWrite(path, previous, 0644)
			return e
		}
	}
	e = runContainer(path, image)
	if e == nil {
		for i := 0; i < 60; i++ {
			info, err := inspect()
			if err != nil {
				e = err
				break
			}
			if info != nil && info.State.Running && info.State.Health.Status == "healthy" {
				return nil
			}
			time.Sleep(time.Second)
		}
		if e == nil {
			e = errors.New("container did not become healthy in 60 seconds; inspect web-edge logs")
		}
	}
	if old != nil {
		fmt.Fprintln(os.Stderr, "Запуск не удался; восстанавливаю предыдущую конфигурацию и образ.")
		_ = Docker("rm", "-f", Container)
		if err := AtomicWrite(path, previous, 0644); err != nil {
			return fmt.Errorf("%v; rollback config: %w", e, err)
		}
		if err := runContainer(path, old.Config.Image); err != nil {
			return fmt.Errorf("%v; rollback start: %w", e, err)
		}
	}
	return e
}

func Stop() error {
	i, e := inspect()
	if e != nil {
		return e
	}
	if i == nil {
		return errors.New("web-edge container not found")
	}
	return Docker("stop", Container)
}
