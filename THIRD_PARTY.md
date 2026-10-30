# Third-party components

The wrapper, configuration generator and CLI are MIT licensed. They do not
change the licenses, ownership or warranties of the bundled software.

| Component | Version | Upstream / license |
|---|---|---|
| Caddy | 2.11.7 | [caddyserver/caddy](https://github.com/caddyserver/caddy), Apache-2.0 |
| Coraza Caddy module | 2.6.2 | [corazawaf/coraza-caddy](https://github.com/corazawaf/coraza-caddy), Apache-2.0 |
| Coraza / OWASP CRS | pinned in caddy/go.sum | [Coraza](https://github.com/corazawaf/coraza), [CRS](https://github.com/coreruleset/coreruleset), Apache-2.0 |
| CrowdSec bouncer | 0.14.1 | [hslatman/caddy-crowdsec-bouncer](https://github.com/hslatman/caddy-crowdsec-bouncer), Apache-2.0 |
| Rate limiter | 0.1.0 | [mholt/caddy-ratelimit](https://github.com/mholt/caddy-ratelimit), Apache-2.0 |
| Anubis | 1.28.2 | [TecharoHQ/anubis](https://github.com/TecharoHQ/anubis), [license](third_party/anubis.LICENSE) |
| CrowdSec engine | 1.8.2 | [crowdsecurity/crowdsec](https://github.com/crowdsecurity/crowdsec), [license](third_party/crowdsec.LICENSE) |

Official Anubis and CrowdSec base images are pinned by digest in the Dockerfile.
CrowdSec's bundled Hub index determines rule versions; auxiliary Hub datasets are
downloaded at image-build time, never in the isolated runtime tests. The resulting
image archive is checksummed per release. Go module versions and checksums are in
`caddy/go.mod` and `caddy/go.sum`. Dependency license/notice files available in the
Go modules are copied into `/usr/share/licenses/web-edge/go` during image build.
Anubis artwork and assets retain their upstream attribution.
