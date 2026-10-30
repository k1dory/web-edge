package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/k1dory/web-edge/internal/edge"
)

var version = "0.1.0"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "web-edge:", err)
		os.Exit(1)
	}
}

func help() {
	fmt.Print(`web-edge — Caddy + Coraza WAF + Anubis + CrowdSec в одном контейнере

  sudo web-edge setup                 мастер первой публикации
  sudo web-edge add                   добавить ещё один сайт
  sudo web-edge edit NAME [флаги]      изменить публикацию
  sudo web-edge remove NAME           удалить публикацию
  sudo web-edge up                    проверить конфиг и запустить/применить
  sudo web-edge down                  остановить; данные сохраняются
  web-edge list                      список публикаций
  web-edge doctor                    DNS и доступность upstream
  sudo web-edge status               состояние контейнера
  sudo web-edge logs                 журналы с полями node/host_ip/container
  sudo web-edge block IP [DURATION]   бан IP (по умолчанию 4h)
  sudo web-edge unblock IP            снять бан
  sudo web-edge decisions             текущие блокировки
  web-edge render                    показать Caddyfile без секретов

Флаги setup/add/edit:
  --name nas --upstream https://10.20.0.10:443 --profile qnap-share
  --bot-check=true --waf block|detect|off --insecure-upstream=false
  --max-body-mib 64 --rate 600 --login-path /login (один путь)
  --login-minute 20 --login-15-minutes 100 --no-start
Флаги setup: --zone gw.example.com --email ops@example.com
  --tls acme|internal --node HOSTNAME --host-ip LAN_IP
Общие флаги: --config /etc/web-edge/config.json --image IMAGE

Docker Engine должен быть установлен. CLI не меняет DNS и настройки роутера.
`)
}

type prompts struct{ reader *bufio.Reader }

func (p prompts) ask(label, def string) (string, error) {
	fmt.Printf("%s", label)
	if def != "" {
		fmt.Printf(" [%s]", def)
	}
	fmt.Print(": ")
	s, e := p.reader.ReadString('\n')
	if e != nil {
		return "", fmt.Errorf("нужен ответ для %s; для автоматизации используйте флаги: %w", label, e)
	}
	s = strings.TrimSpace(s)
	if s == "" {
		s = def
	}
	return s, nil
}

func hostIP() string {
	c, e := net.Dial("udp4", "192.0.2.1:9")
	if e != nil {
		return ""
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).IP.String()
}

func run(args []string) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" {
		help()
		return nil
	}
	action := args[0]
	if action == "version" || action == "--version" {
		fmt.Println(version)
		return nil
	}
	if action == "health" {
		return edge.Health()
	}
	if action == "export" && len(args) == 2 {
		return edge.Export(args[1], os.Stdout)
	}
	f := flag.NewFlagSet(action, flag.ContinueOnError)
	defaultConfig := os.Getenv("WEB_EDGE_CONFIG")
	if defaultConfig == "" {
		defaultConfig = "/etc/web-edge/config.json"
	}
	if action == "serve" || action == "check-config" {
		defaultConfig = "/config/config.json"
	}
	path := f.String("config", defaultConfig, "configuration file")
	image := f.String("image", edge.DefaultImage, "container image")
	zone := f.String("zone", "", "publication domain")
	email := f.String("email", "", "ACME email")
	tlsMode := f.String("tls", "acme", "acme or internal")
	node, _ := os.Hostname()
	nodeFlag := f.String("node", node, "host name for logs")
	ip := f.String("host-ip", hostIP(), "host IP for logs")
	name := f.String("name", "", "subdomain")
	upstream := f.String("upstream", "", "upstream http(s)://host:port")
	profile := f.String("profile", "web", "web, qnap or qnap-share")
	shareOnly := f.Bool("share-only", false, "only QNAP public sharing routes")
	bot := f.Bool("bot-check", true, "Anubis browser challenge")
	waf := f.String("waf", "block", "block/detect/off")
	insecure := f.Bool("insecure-upstream", false, "skip upstream TLS verification")
	maxBody := f.Int("max-body-mib", 64, "maximum request body MiB")
	rate := f.Int("rate", 600, "requests per minute per IP")
	login := f.String("login-path", "", "login route to limit")
	loginMinute := f.Int("login-minute", 20, "login requests per minute per IP")
	loginLong := f.Int("login-15-minutes", 100, "login requests per 15 minutes per IP")
	noStart := f.Bool("no-start", false, "save configuration without starting")
	// Positional names precede flags for edit/remove; block uses positional IP/duration.
	var target string
	rest := args[1:]
	if (action == "edit" || action == "remove") && len(rest) > 0 && !strings.HasPrefix(rest[0], "-") {
		target = rest[0]
		rest = rest[1:]
	}
	if e := f.Parse(rest); e != nil {
		return e
	}
	visited := map[string]bool{}
	f.Visit(func(v *flag.Flag) { visited[v.Name] = true })
	if action == "logs" {
		return edge.Docker("logs", "--tail", "100", "--follow", edge.Container)
	}
	if action == "status" {
		return edge.Docker("inspect", "--format", "{{.State.Status}} / {{if .State.Health}}{{.State.Health.Status}}{{end}}", edge.Container)
	}
	if action == "down" {
		return edge.Stop()
	}
	if action == "block" || action == "unblock" || action == "decisions" {
		csargs := []string{"exec", edge.Container, "/usr/local/bin/cscli", "-c", "/data/crowdsec/config.yaml", "decisions"}
		if action == "decisions" {
			return edge.Docker(append(csargs, "list")...)
		}
		if len(f.Args()) < 1 || net.ParseIP(f.Args()[0]) == nil {
			return errors.New("укажите IPv4 или IPv6")
		}
		if action == "unblock" {
			return edge.Docker(append(csargs, "delete", "--ip", f.Args()[0])...)
		}
		duration := "4h"
		if len(f.Args()) > 1 {
			duration = f.Args()[1]
		}
		d, e := time.ParseDuration(duration)
		if e != nil || d <= 0 || d > 30*24*time.Hour {
			return errors.New("duration must be between 1ns and 720h")
		}
		return edge.Docker(append(csargs, "add", "--ip", f.Args()[0], "--duration", duration, "--reason", "web-edge-cli")...)
	}
	var c edge.Config
	if action == "setup" {
		if _, e := os.Stat(*path); e == nil {
			return errors.New("конфиг уже существует; используйте add/edit")
		}
		c = edge.Config{Schema: 1, Zone: *zone, Email: *email, TLS: *tlsMode, Identity: edge.Identity{Node: *nodeFlag, HostIP: *ip, Container: edge.Container}}
	} else {
		var e error
		c, e = edge.Load(*path)
		if e != nil {
			return e
		}
	}
	switch action {
	case "serve":
		return edge.Serve(c)
	case "check-config":
		return edge.Check(c)
	case "render":
		s, e := edge.Render(c)
		if e == nil {
			fmt.Print(s)
		}
		return e
	case "list":
		fmt.Print(edge.DNSInstructions(c))
		return nil
	case "doctor":
		return doctor(c)
	case "up":
		if !visited["image"] {
			var e error
			*image, e = edge.ExistingImage()
			if e != nil {
				return e
			}
		}
		return edge.Apply(c, *path, *image, true)
	case "setup", "add", "edit":
		p := prompts{bufio.NewReader(os.Stdin)}
		var e error
		interactive := *name == "" && action != "edit"
		if action == "setup" {
			if c.Zone == "" {
				c.Zone, e = p.ask("Домен публикаций (например gw.example.com)", "")
				if e != nil {
					return e
				}
			}
			if c.Email == "" {
				c.Email, e = p.ask("Email для сертификатов", "")
				if e != nil {
					return e
				}
			}
			if interactive {
				c.Identity.Node, e = p.ask("Hostname сервера для журналов", c.Identity.Node)
				if e != nil {
					return e
				}
				c.Identity.HostIP, e = p.ask("Внутренний IP сервера для журналов", c.Identity.HostIP)
				if e != nil {
					return e
				}
			}
		}
		s := edge.DefaultSite()
		idx := -1
		if action == "edit" {
			for i, old := range c.Sites {
				if old.Name == target {
					s = old
					idx = i
					break
				}
			}
			if idx < 0 {
				return errors.New("site not found")
			}
		}
		if action != "edit" {
			if *name == "" {
				*name, e = p.ask("Поддомен (например nas)", "")
				if e != nil {
					return e
				}
			}
			if *upstream == "" {
				*upstream, e = p.ask("Адрес сервиса (http:// или https://, с портом)", "")
				if e != nil {
					return e
				}
			}
			if interactive {
				*profile, e = p.ask("Профиль: web / qnap / qnap-share", *profile)
				if e != nil {
					return e
				}
				if strings.HasPrefix(*upstream, "https://") {
					answer, e := p.ask("Разрешить самоподписанный сертификат upstream? да/нет", "нет")
					if e != nil {
						return e
					}
					*insecure = answer == "да" || answer == "yes"
				}
			}
			s.Name = *name
			s.Upstream = *upstream
			s.Profile = *profile
			s.ApplyProfile()
		}
		if visited["upstream"] {
			s.Upstream = *upstream
		}
		if visited["profile"] {
			s.Profile = *profile
			s.ApplyProfile()
		}
		if action != "edit" || visited["bot-check"] {
			s.BotCheck = *bot
		}
		if visited["share-only"] {
			s.ShareOnly = *shareOnly
		}
		if action != "edit" || visited["waf"] {
			s.WAF = *waf
		}
		if action != "edit" || visited["insecure-upstream"] {
			s.InsecureTLS = *insecure
		}
		if visited["max-body-mib"] {
			s.MaxBodyMiB = *maxBody
		}
		if visited["rate"] {
			s.RatePerMinute = *rate
		}
		if visited["login-path"] {
			s.LoginPaths = []string{*login}
		}
		if visited["login-minute"] {
			s.LoginPerMinute = *loginMinute
		}
		if visited["login-15-minutes"] {
			s.LoginPer15Minutes = *loginLong
		}
		if idx >= 0 {
			c.Sites[idx] = s
		} else {
			c.Sites = append(c.Sites, s)
		}
		if e = c.Validate(); e != nil {
			return e
		}
		fmt.Print(edge.DNSInstructions(c))
		if interactive && !*noStart {
			answer, e := p.ask("Запустить/применить сейчас? да/нет", "да")
			if e != nil {
				return e
			}
			*noStart = answer != "да" && answer != "yes"
		}
		if !*noStart && action != "setup" && !visited["image"] {
			var e error
			*image, e = edge.ExistingImage()
			if e != nil {
				return e
			}
		}
		return edge.Apply(c, *path, *image, !*noStart)
	case "remove":
		out := c.Sites[:0]
		found := false
		for _, s := range c.Sites {
			if s.Name == target {
				found = true
			} else {
				out = append(out, s)
			}
		}
		if !found {
			return errors.New("site not found")
		}
		c.Sites = out
		if len(out) == 0 {
			return errors.New("последний сайт: используйте web-edge down для остановки")
		}
		if !*noStart && !visited["image"] {
			var e error
			*image, e = edge.ExistingImage()
			if e != nil {
				return e
			}
		}
		return edge.Apply(c, *path, *image, !*noStart)
	default:
		return fmt.Errorf("unknown command %q; use web-edge help", action)
	}
}

func doctor(c edge.Config) error {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	failed := false
	names := []string{"botcheck." + c.Zone}
	for _, s := range c.Sites {
		names = append(names, s.Name+"."+c.Zone)
	}
	for _, n := range names {
		ips, e := net.DefaultResolver.LookupHost(ctx, n)
		fmt.Printf("DNS %-40s %v %v\n", n, ips, e)
		if e != nil {
			failed = true
		}
	}
	for _, s := range c.Sites {
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: s.InsecureTLS} // explicitly configured by operator
		client := http.Client{Timeout: 5 * time.Second, Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		req, _ := http.NewRequestWithContext(ctx, "GET", s.Upstream, nil)
		resp, e := client.Do(req)
		if e != nil {
			fmt.Printf("UPSTREAM %s: %v\n", s.Name, e)
			failed = true
		} else {
			resp.Body.Close()
			fmt.Printf("UPSTREAM %s: HTTP %d (сеть доступна)\n", s.Name, resp.StatusCode)
		}
		tr.CloseIdleConnections()
	}
	if _, e := exec.LookPath("docker"); e != nil {
		fmt.Println("Docker CLI не найден")
		failed = true
	}
	if failed {
		return errors.New("есть ошибки; см. вывод выше")
	}
	return nil
}
