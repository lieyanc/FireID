# syntax=docker/dockerfile:1

# The builder stages run on the build host and cross-compile, so a multi-arch
# build needs no emulation: only the final stage, which copies files, is per
# architecture.

FROM --platform=$BUILDPLATFORM node:22-alpine AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_TIME=unknown
ENV CGO_ENABLED=0 GOTOOLCHAIN=local
WORKDIR /src
# The main module replaces github.com/lieyanc/FireID/client with ./client.
COPY go.mod go.sum ./
COPY client/go.mod client/
RUN go mod download
COPY . .
COPY --from=web /src/web/dist web/dist
RUN GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath \
      -ldflags "-s -w \
        -X github.com/lieyanc/FireID/internal/version.Version=${VERSION} \
        -X github.com/lieyanc/FireID/internal/version.Commit=${COMMIT} \
        -X github.com/lieyanc/FireID/internal/version.BuildTime=${BUILD_TIME}" \
      -o /out/fireid ./cmd/fireid \
 && mkdir -p /out/data

# distroless/static: no shell, no package manager; the binary is static.
FROM gcr.io/distroless/static-debian12:nonroot
LABEL org.opencontainers.image.title="Fire ID" \
      org.opencontainers.image.description="Self-hosted OpenID Connect identity provider" \
      org.opencontainers.image.source="https://github.com/lieyanc/FireID" \
      org.opencontainers.image.licenses="MIT"
COPY --from=build /out/fireid /usr/local/bin/fireid
# /data holds config.json, the SQLite database and master.key. It is the only
# path the process writes, so the root filesystem can be mounted read-only.
COPY --from=build --chown=65532:65532 /out/data /data
USER 65532:65532
WORKDIR /data
VOLUME ["/data"]
EXPOSE 8099
ENTRYPOINT ["/usr/local/bin/fireid"]
CMD ["-c", "/data/config.json"]
