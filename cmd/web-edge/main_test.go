package main

import (
	"path/filepath"
	"testing"

	"github.com/k1dory/web-edge/internal/edge"
)

func TestSetupAndAddWithoutDocker(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.json")
	t.Setenv("WEB_EDGE_CONFIG", p)
	if e := run([]string{"setup", "--zone", "gw.example.com", "--email", "ops@example.com", "--node", "host01", "--host-ip", "10.20.0.5", "--name", "nas", "--upstream", "https://10.20.0.10:443", "--profile", "qnap", "--no-start"}); e != nil {
		t.Fatal(e)
	}
	c, e := edge.Load(p)
	if e != nil {
		t.Fatal(e)
	}
	if c.Sites[0].InsecureTLS || !c.Sites[0].BotCheck || c.Sites[0].MaxBodyMiB != 1024 {
		t.Fatal("wrong defaults")
	}
	if e = run([]string{"add", "--name", "app", "--upstream", "http://10.20.0.11:8080", "--no-start"}); e != nil {
		t.Fatal(e)
	}
	if e = run([]string{"edit", "app", "--waf", "detect", "--bot-check=false", "--no-start"}); e != nil {
		t.Fatal(e)
	}
	c, e = edge.Load(p)
	if e != nil {
		t.Fatal(e)
	}
	if len(c.Sites) != 2 || c.Sites[1].WAF != "detect" || c.Sites[1].BotCheck {
		t.Fatal("edit not persisted")
	}
	if e = run([]string{"remove", "nas", "--no-start"}); e != nil {
		t.Fatal(e)
	}
	if e = run([]string{"add", "--name", "botcheck", "--upstream", "http://10.20.0.12", "--no-start"}); e == nil {
		t.Fatal("reserved domain accepted")
	}
	c, e = edge.Load(p)
	if e != nil {
		t.Fatal(e)
	}
	if len(c.Sites) != 1 {
		t.Fatal("invalid edit mutated config")
	}
	if e = run([]string{"edit", "app", "--profile", "qnap-share", "--no-start"}); e != nil {
		t.Fatal(e)
	}
	c, e = edge.Load(p)
	if e != nil || !c.Sites[0].ShareOnly || c.Sites[0].MaxBodyMiB != 1024 {
		t.Fatal("share profile not applied", e)
	}
	if e = run([]string{"edit", "app", "--profile", "web", "--no-start"}); e != nil {
		t.Fatal(e)
	}
	c, e = edge.Load(p)
	if e != nil || c.Sites[0].ShareOnly || len(c.Sites[0].LoginPaths) != 0 || c.Sites[0].MaxBodyMiB != 64 {
		t.Fatal("old profile restrictions retained", e)
	}
}
