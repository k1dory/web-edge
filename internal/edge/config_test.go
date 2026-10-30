package edge

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fixture() Config {
	s := DefaultSite()
	s.Name = "nas"
	s.Upstream = "https://10.20.0.10:443"
	s.Profile = "qnap"
	s.ApplyProfile()
	return Config{Schema: 1, Zone: "gw.example.com", Email: "ops@example.com", TLS: "internal", Identity: Identity{"edge01", "10.20.0.5", "web-edge"}, Sites: []Site{s}}
}

func TestRejectConfigInjection(t *testing.T) {
	for name, change := range map[string]func(*Config){
		"zone":     func(c *Config) { c.Zone = "example.com { respond pwned }" },
		"name":     func(c *Config) { c.Sites[0].Name = "../evil" },
		"reserved": func(c *Config) { c.Sites[0].Name = "botcheck" },
		"email":    func(c *Config) { c.Email = "ops@example.com\nadmin :2019" },
		"upstream": func(c *Config) { c.Sites[0].Upstream = "http://127.0.0.1 { header_up X x }" },
		"userinfo": func(c *Config) { c.Sites[0].Upstream = "https://user:secret@example.com" },
		"subpath":  func(c *Config) { c.Sites[0].Upstream = "https://example.com/admin" },
		"port":     func(c *Config) { c.Sites[0].Upstream = "https://example.com:99999" },
		"loop":     func(c *Config) { c.Sites[0].Upstream = "https://nas.gw.example.com" },
		"login":    func(c *Config) { c.Sites[0].LoginPaths = []string{"/login\nrespond 200"} },
		"body":     func(c *Config) { c.Sites[0].MaxBodyMiB = 1025 },
		"ip":       func(c *Config) { c.Identity.HostIP = "container-name" },
		"node":     func(c *Config) { c.Identity.Node = "host\nforged" },
	} {
		t.Run(name, func(t *testing.T) {
			c := fixture()
			change(&c)
			if c.Validate() == nil {
				t.Fatal("accepted unsafe config")
			}
		})
	}
}

func TestRenderSecurityOrderAndProfile(t *testing.T) {
	c := fixture()
	s, e := Render(c)
	if e != nil {
		t.Fatal(e)
	}
	start := strings.Index(s, "nas.gw.example.com {")
	site := s[start:]
	last := -1
	for _, marker := range []string{"crowdsec", "rate_limit", "import botcheck", "coraza_waf", "reverse_proxy https://10.20.0.10:443"} {
		i := strings.Index(site, marker)
		if i <= last {
			t.Fatalf("handler order: %s", marker)
		}
		last = i
	}
	for _, want := range []string{"SecRuleEngine On", "SecRequestBodyLimit 1073741824", "header_up X-Forwarded-For {client_ip}", "header_up X-Real-IP {client_ip}", "header_up -Forwarded", "@streq GET", "language_trigger.svg?${URL_RANDOM_NUM;}", "window 15m"} {
		if !strings.Contains(site, want) {
			t.Errorf("missing %s", want)
		}
	}
	if strings.Contains(site, "tls_insecure_skip_verify") {
		t.Error("TLS verification disabled by default")
	}
	c.Sites[0].Profile = "web"
	s, e = Render(c)
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(s, "ruleRemoveById") {
		t.Fatal("QNAP exception leaked into generic profile")
	}
}

func TestAnubisIdentityNotClientControlled(t *testing.T) {
	c := fixture()
	env := strings.Join(AnubisEnv(c), "\n")
	for _, want := range []string{"JWT_RESTRICTION_HEADER=X-Real-IP", "COOKIE_HTTP_ONLY=true", "COOKIE_SECURE=true", "COOKIE_EXPIRATION_TIME=24h", "nas.gw.example.com"} {
		if !strings.Contains(env, want) {
			t.Error(want)
		}
	}
	rec := Record(c.Identity, "caddy", `[hostname "172.19.0.4"]`)
	if rec.Node != "edge01" || rec.HostIP != "10.20.0.5" || rec.Container != "web-edge" {
		t.Fatal("log identity overwritten by payload")
	}
}

func TestConfigPersistence(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.json")
	c := fixture()
	if e := Save(p, c); e != nil {
		t.Fatal(e)
	}
	if _, e := Load(p); e != nil {
		t.Fatal(e)
	}
	b, _ := json.Marshal(c)
	if e := os.WriteFile(p, append(b, []byte(" garbage")...), 0644); e != nil {
		t.Fatal(e)
	}
	if _, e := Load(p); e == nil {
		t.Fatal("trailing input accepted")
	}
	if e := os.WriteFile(p, []byte(`{"unexpected":true}`), 0644); e != nil {
		t.Fatal(e)
	}
	if _, e := Load(p); e == nil {
		t.Fatal("unknown property accepted")
	}
}
