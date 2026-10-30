package edge

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/mail"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

var DefaultImage = "web-edge:0.1.0"

const Container = "web-edge"
const State = "/data"

type Identity struct {
	Node      string `json:"node"`
	HostIP    string `json:"host_ip"`
	Container string `json:"container"`
}

type Config struct {
	Schema   int      `json:"schema"`
	Zone     string   `json:"zone"`
	Email    string   `json:"email"`
	TLS      string   `json:"tls"`
	Identity Identity `json:"identity"`
	Sites    []Site   `json:"sites"`
}

type Site struct {
	Name              string   `json:"name"`
	Upstream          string   `json:"upstream"`
	Profile           string   `json:"profile"`
	BotCheck          bool     `json:"bot_check"`
	ShareOnly         bool     `json:"share_only"`
	WAF               string   `json:"waf"`
	InsecureTLS       bool     `json:"insecure_upstream_tls"`
	MaxBodyMiB        int      `json:"max_body_mib"`
	RatePerMinute     int      `json:"rate_per_minute"`
	LoginPaths        []string `json:"login_paths,omitempty"`
	LoginPerMinute    int      `json:"login_per_minute"`
	LoginPer15Minutes int      `json:"login_per_15_minutes"`
}

var label = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
var identityValue = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,252}$`)
var safePath = regexp.MustCompile(`^/[a-zA-Z0-9/_.-]+\*?$`)
var imageValue = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_./:@-]*$`)

func Domain(s string) bool {
	if len(s) > 253 || !strings.Contains(s, ".") {
		return false
	}
	for _, p := range strings.Split(s, ".") {
		if !label.MatchString(p) {
			return false
		}
	}
	return net.ParseIP(s) == nil
}

func DefaultSite() Site {
	return Site{Profile: "web", BotCheck: true, WAF: "block", MaxBodyMiB: 64, RatePerMinute: 600, LoginPerMinute: 20, LoginPer15Minutes: 100}
}

func (s *Site) ApplyProfile() {
	s.ShareOnly = s.Profile == "qnap-share"
	s.MaxBodyMiB = 64
	s.LoginPaths = nil
	if s.Profile == "qnap" || s.Profile == "qnap-share" {
		s.MaxBodyMiB = 1024
		s.LoginPaths = []string{"/cgi-bin/authLogin.cgi", "/cgi-bin/authLogin.cgi/*"}
	}
}

func (c Config) Validate() error {
	if c.Schema != 1 {
		return errors.New("unsupported config schema (expected 1)")
	}
	if !Domain(c.Zone) {
		return errors.New("zone must be a DNS domain, e.g. gw.example.com (ASCII/punycode, no wildcard)")
	}
	a, err := mail.ParseAddress(c.Email)
	if err != nil || a.Address != c.Email || strings.ContainsAny(c.Email, "\r\n\t \"`{}\\") {
		return errors.New("invalid ACME email")
	}
	if c.TLS != "acme" && c.TLS != "internal" {
		return errors.New("tls must be acme or internal")
	}
	if !identityValue.MatchString(c.Identity.Node) || !identityValue.MatchString(c.Identity.Container) {
		return errors.New("invalid log identity: node/container")
	}
	if c.Identity.HostIP != "" && net.ParseIP(c.Identity.HostIP) == nil {
		return errors.New("identity.host_ip must be an IP address")
	}
	if len(c.Sites) == 0 || len(c.Sites) > 200 {
		return errors.New("configure between 1 and 200 sites")
	}
	seen := map[string]bool{}
	for _, s := range c.Sites {
		if !label.MatchString(s.Name) || s.Name == "botcheck" || seen[s.Name] {
			return fmt.Errorf("invalid, reserved or duplicate subdomain %q", s.Name)
		}
		seen[s.Name] = true
		if !Domain(s.Name + "." + c.Zone) {
			return errors.New("site hostname too long")
		}
		u, e := url.Parse(s.Upstream)
		if e != nil || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.Hostname() == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || u.ForceQuery || strings.ContainsAny(s.Upstream, "\r\n\t \"`{}\\") {
			return fmt.Errorf("invalid upstream for %s: use http(s)://host:port without credentials or a subpath", s.Name)
		}
		if net.ParseIP(u.Hostname()) == nil && !Domain(u.Hostname()) && !label.MatchString(u.Hostname()) {
			return fmt.Errorf("invalid upstream host for %s", s.Name)
		}
		if u.Port() != "" {
			n, e := strconv.Atoi(u.Port())
			if e != nil || n < 1 || n > 65535 {
				return errors.New("invalid upstream port")
			}
		}
		if strings.EqualFold(u.Hostname(), s.Name+"."+c.Zone) || strings.EqualFold(u.Hostname(), "botcheck."+c.Zone) {
			return errors.New("upstream points back to its public proxy hostname")
		}
		if s.Profile != "web" && s.Profile != "qnap" && s.Profile != "qnap-share" {
			return errors.New("profile must be web, qnap or qnap-share")
		}
		if s.WAF != "block" && s.WAF != "detect" && s.WAF != "off" {
			return errors.New("waf must be block, detect or off")
		}
		if s.InsecureTLS && u.Scheme != "https" {
			return errors.New("insecure_upstream_tls only applies to HTTPS")
		}
		if s.MaxBodyMiB < 1 || s.MaxBodyMiB > 1024 || s.RatePerMinute < 1 || s.RatePerMinute > 100000 || s.LoginPerMinute < 1 || s.LoginPer15Minutes < 1 {
			return errors.New("invalid request limits")
		}
		for _, p := range s.LoginPaths {
			if !safePath.MatchString(p) {
				return fmt.Errorf("invalid login path %q", p)
			}
		}
	}
	return nil
}

func Load(path string) (Config, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return Config{}, e
	}
	var c Config
	d := json.NewDecoder(strings.NewReader(string(b)))
	d.DisallowUnknownFields()
	if e = d.Decode(&c); e != nil {
		return c, e
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return c, errors.New("trailing data after configuration")
	}
	return c, c.Validate()
}

func Save(path string, c Config) error {
	if err := c.Validate(); err != nil {
		return err
	}
	b, e := json.MarshalIndent(c, "", "  ")
	if e != nil {
		return e
	}
	return AtomicWrite(path, append(b, '\n'), 0644)
}

func AtomicWrite(path string, b []byte, mode os.FileMode) error {
	if e := os.MkdirAll(filepath.Dir(path), 0755); e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".web-edge-*")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	if e = f.Chmod(mode); e != nil {
		f.Close()
		return e
	}
	if _, e = f.Write(b); e != nil {
		f.Close()
		return e
	}
	if e = f.Sync(); e != nil {
		f.Close()
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	return os.Rename(f.Name(), path)
}

func ValidImage(s string) bool { return imageValue.MatchString(s) }
