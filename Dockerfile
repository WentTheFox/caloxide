# Hardened caloxide image: static binary on scratch, non-root, no shell.
# Base image is pinned by digest; Dependabot proposes digest bumps.

# Cross-compile on the build platform so multi-arch builds need no emulation.
FROM --platform=$BUILDPLATFORM golang:1.27.3-alpine@sha256:d200d2dd76b03a99b52651fd1325aff7dcd35422c35c01bac56571b0507f3deb AS build
ARG TARGETOS
ARG TARGETARCH
ENV CGO_ENABLED=0 GOFLAGS=-mod=readonly GOTOOLCHAIN=local
WORKDIR /src

# go.mod has a `replace` into third_party/, so it must be present before download.
COPY go.mod go.sum ./
COPY third_party ./third_party
RUN go mod download && go mod verify

COPY . .
RUN GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w" -o /out/caloxide ./cmd/caloxide
# scratch has no mkdir/chown: prepare the data dir here.
RUN mkdir /out/data && chown 65532:65532 /out/data && chmod 0700 /out/data

FROM scratch
# TLS roots, needed to reach the Proton API.
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/caloxide /caloxide
COPY --from=build --chown=65532:65532 /out/data /data

USER 65532:65532
# auth.json (encrypted session) and the decrypted calendar cache live under
# /data/caloxide/. Mount a volume here; it must be owned by 65532:65532.
VOLUME ["/data"]
# CalDAV over plain HTTP with Basic auth: publish this port on 127.0.0.1 only
# and put a TLS reverse proxy in front. Never expose it directly.
EXPOSE 8081

ENTRYPOINT ["/caloxide", "-config-home", "/data", "-caldav-host", "0.0.0.0"]
CMD ["caldav"]
