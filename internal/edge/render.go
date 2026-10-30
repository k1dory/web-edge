package edge

import (
	"fmt"
	"strconv"
	"strings"
)

// User-supplied values must pass Config.Validate before reaching this renderer.
func Render(c Config) (string, error) {
	if err := c.Validate(); err != nil {
		return "", err
	}
	var b strings.Builder
	f := func(s string, a ...any) { fmt.Fprintf(&b, s, a...) }
	f("{\n admin 127.0.0.1:2019\n http_port 8080\n https_port 8443\n servers {\n  protocols h1 h2\n }\n email %s\n persist_config off\n skip_install_trust\n", c.Email)
	if c.TLS == "internal" {
		f(" local_certs\n")
	}
	f(" crowdsec {\n  api_url http://127.0.0.1:8081\n  api_key {$CROWDSEC_API_KEY}\n  ticker_interval 5s\n  enable_hard_fails\n }\n}\n")
	f("(access_log) {\n log {\n  output file /data/logs/access.json {\n   roll_size 20MiB\n   roll_keep 5\n   mode 0600\n  }\n  format json\n }\n}\n")
	f("(botcheck) {\n encode /.within.website/* zstd gzip\n reverse_proxy /.within.website/* 127.0.0.1:8923 {\n  header_up X-Real-IP {remote_host}\n }\n forward_auth 127.0.0.1:8923 {\n  uri /.within.website/x/cmd/anubis/api/check\n  header_up X-Real-IP {remote_host}\n }\n}\n")
	f("botcheck.%s {\n import access_log\n route {\n crowdsec\n encode zstd gzip\n rate_limit {\n  zone botcheck_ip {\n   key {client_ip}\n   events 600\n   window 1m\n  }\n }\n reverse_proxy 127.0.0.1:8923 {\n  header_up X-Real-IP {remote_host}\n }\n }\n}\n", c.Zone)
	for _, s := range c.Sites {
		id := strings.ReplaceAll(s.Name, "-", "_")
		f("%s.%s {\n import access_log\n", s.Name, c.Zone)
		if s.ShareOnly {
			f(" @share_denied expression `%s`\n", ShareDenied(s.BotCheck))
		}
		f(" route {\n  crowdsec\n  rate_limit {\n   zone %s_ip {\n    key {client_ip}\n    events %d\n    window 1m\n   }\n", id, s.RatePerMinute)
		if len(s.LoginPaths) > 0 {
			for _, limit := range []struct {
				name, window string
				n            int
			}{{"short", "1m", s.LoginPerMinute}, {"long", "15m", s.LoginPer15Minutes}} {
				f("   zone %s_login_%s {\n    match {\n     path %s\n    }\n    key {client_ip}\n    events %d\n    window %s\n   }\n", id, limit.name, strings.Join(s.LoginPaths, " "), limit.n, limit.window)
			}
		}
		f("  }\n")
		if s.ShareOnly {
			f("  respond @share_denied \"Not found\" 404\n")
		}
		if s.BotCheck {
			f("  import botcheck\n")
		}
		if s.WAF != "off" {
			mode := "On"
			if s.WAF == "detect" {
				mode = "DetectionOnly"
			}
			f("  coraza_waf {\n   load_owasp_crs\n   directives `\n    Include @coraza.conf-recommended\n    Include @crs-setup.conf.example\n")
			if s.Profile == "qnap" || s.Profile == "qnap-share" {
				f("    SecRule REQUEST_METHOD \"@streq GET\" \"id:100100,phase:1,pass,nolog,chain\"\n    SecRule REQUEST_URI \"@streq /cgi-bin/images/toolbar/language_trigger.svg?${URL_RANDOM_NUM;}\" \"t:none,t:urlDecodeUni,ctl:ruleRemoveById=932130,ctl:ruleRemoveById=933135\"\n")
			}
			f("    Include @owasp_crs/*.conf\n    SecRuleEngine %s\n    SecRequestBodyAccess On\n    SecRequestBodyLimit %d\n    SecRequestBodyLimitAction Reject\n    SecResponseBodyAccess Off\n    SecAuditEngine Off\n   `\n  }\n", mode, int64(s.MaxBodyMiB)*1024*1024)
		}
		f("  reverse_proxy %s {\n   header_up X-Real-IP {client_ip}\n   header_up X-Forwarded-For {client_ip}\n   header_up -Forwarded\n", strings.TrimSuffix(s.Upstream, "/"))
		if s.InsecureTLS {
			f("   transport http {\n    tls\n    tls_insecure_skip_verify\n   }\n")
		}
		f("  }\n }\n}\n")
	}
	f("http:// {\n respond \"Unknown site\" 404\n}\nhttps:// {\n respond \"Unknown site\" 404\n}\n")
	return b.String(), nil
}

func ShareDenied(botcheck bool) string {
	allowed := `({http.request.uri.path} == "/share.cgi" && {http.request.uri.query} != "") || (({http.request.method} == "GET" || {http.request.method} == "HEAD") && {http.request.uri.path}.matches("^/(?:libs/extjs-3[.]3[.]3/|shareLink/|cgi-bin/filemanager/shareLink/|cgi-bin/apps/fileManager/langs/|v3_menu/|cgi-bin/images/)[A-Za-z0-9_./-]+[.](?:js|css|png|gif|svg|ico|woff2?|ttf|eot|jpg|jpeg)$")) || (({http.request.method} == "GET" || {http.request.method} == "HEAD") && {http.request.uri.path} in ["/libs/qnap-lib.js", "/cgi-bin/apps/fileManager/js/shlkPlugin.js", "/cgi-bin/apps/fileManager/ShareLkJWP.html"])`
	if botcheck {
		allowed += ` || {http.request.uri.path}.startsWith("/.within.website/")`
	}
	return "!(" + allowed + ")"
}

func AnubisEnv(c Config) []string {
	domains := []string{"botcheck." + c.Zone}
	for _, s := range c.Sites {
		if s.BotCheck {
			domains = append(domains, s.Name+"."+c.Zone)
		}
	}
	return []string{"BIND=127.0.0.1:8923", "METRICS_BIND=127.0.0.1:9091", "TARGET= ", "PUBLIC_URL=https://botcheck." + c.Zone, "COOKIE_DOMAIN=" + c.Zone, "COOKIE_EXPIRATION_TIME=24h", "COOKIE_SECURE=true", "COOKIE_HTTP_ONLY=true", "COOKIE_SAME_SITE=Lax", "JWT_RESTRICTION_HEADER=X-Real-IP", "DIFFICULTY=4", "POLICY_FNAME=/opt/web-edge/anubis.yaml", "ED25519_PRIVATE_KEY_HEX_FILE=/data/anubis.key", "SERVE_ROBOTS_TXT=false", "REDIRECT_DOMAINS=" + strings.Join(domains, ",")}
}

func DNSInstructions(c Config) string {
	var b strings.Builder
	fmt.Fprintf(&b, "DNS: A/AAAA для botcheck.%s", c.Zone)
	for _, s := range c.Sites {
		fmt.Fprintf(&b, ", %s.%s", s.Name, c.Zone)
	}
	fmt.Fprintln(&b, " → публичный IP сервера. Можно использовать wildcard *."+c.Zone+".")
	fmt.Fprintln(&b, "Для публичных сертификатов входящие TCP 80/443 должны вести на этот сервер.")
	for _, s := range c.Sites {
		fmt.Fprintf(&b, "https://%s.%s → %s (WAF: %s, Anubis: %s)\n", s.Name, c.Zone, s.Upstream, s.WAF, strconv.FormatBool(s.BotCheck))
	}
	return b.String()
}
