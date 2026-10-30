# syntax=docker/dockerfile:1
FROM golang:1.26.6-alpine AS build
WORKDIR /src/caddy
COPY caddy/go.mod caddy/go.sum ./
RUN go mod download
COPY caddy/main.go ./
COPY scripts/licenses.go /src/scripts/licenses.go
RUN CGO_ENABLED=0 go build -trimpath -tags nobadger,nomysql,nopgx -ldflags='-s -w' -o /out/caddy .
RUN go run /src/scripts/licenses.go /out/licenses && cp /usr/local/go/LICENSE /out/licenses/Go.LICENSE
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/web-edge ./cmd/web-edge

FROM ghcr.io/techarohq/anubis:v1.28.2@sha256:5fcbce70ee6168be5b226d19bec90111d0acd0daf13028fa06b044cf3ebbbd5f AS anubis
FROM crowdsecurity/crowdsec:v1.8.2@sha256:65b74942f7e7ed5c60fde4ac15fc4ba715904c398c8b16dd451f4907d90347d4
USER root
RUN apk add --no-cache ca-certificates \
    && cp -a /staging/etc/crowdsec /etc/crowdsec \
    && cp -a /staging/var/lib/crowdsec/. /var/lib/crowdsec/ \
    && cscli collections install crowdsecurity/caddy crowdsecurity/http-cve \
    && rm -f /etc/crowdsec/parsers/s02-enrich/whitelists.yaml \
    && addgroup -g 10001 edge && adduser -D -u 10001 -G edge edge \
    && mkdir -p /data /config /opt/web-edge \
    && chown 10001:10001 /data \
    && chmod -R a+rX /etc/crowdsec /var/lib/crowdsec
COPY --from=anubis /ko-app/anubis /usr/bin/anubis
COPY --from=anubis /var/run/ko /var/run/ko
COPY --from=build /out/caddy /usr/bin/caddy
COPY --from=build /out/web-edge /usr/bin/web-edge
COPY --from=build /out/licenses /usr/share/licenses/web-edge/go
COPY LICENSE THIRD_PARTY.md third_party/ /usr/share/licenses/web-edge/
COPY anubis.yaml crowdsec.yaml acquis.yaml /opt/web-edge/
LABEL org.opencontainers.image.source="https://github.com/k1dory/web-edge" \
      org.opencontainers.image.description="Caddy, Coraza WAF, Anubis and CrowdSec with a setup CLI" \
      org.opencontainers.image.licenses="MIT"
ENV HOME=/data XDG_DATA_HOME=/data/caddy XDG_CONFIG_HOME=/data/config KO_DATA_PATH=/var/run/ko
USER 10001:10001
EXPOSE 8080/tcp 8443/tcp
HEALTHCHECK --interval=5s --timeout=3s --start-period=30s --retries=3 CMD ["/usr/bin/web-edge", "health"]
ENTRYPOINT ["/usr/bin/web-edge"]
CMD ["serve"]
