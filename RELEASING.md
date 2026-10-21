# Releasing Fire ID

A release is a commit on `main` plus a `v*` tag. Pushing the tag runs
[`.github/workflows/release.yml`](.github/workflows/release.yml); nothing is
uploaded by hand.

## Versions and tags

- Tags are `vMAJOR.MINOR.PATCH`, for example `v0.1.0`. A suffix such as
  `v0.2.0-rc.1` marks a pre-release. Any other `v*` tag fails the workflow before
  anything is built.
- The binary reports the tag as its version (`fireid -v` prints
  `Fire ID v0.1.0 (commit 1a2b3c4, built 2026-10-21T08:00:00Z)`); archives and
  image tags drop the leading `v`.

## Cutting a release

1. On an up-to-date `main`, run `make check` (gofmt, go vet, race tests for both
   modules, eslint and tsc) and `make release-local` to see the archives build.
2. In `CHANGELOG.md`, move the entries under `[Unreleased]` into a new
   `## [X.Y.Z] - YYYY-MM-DD` section and update the compare links at the bottom.
   The workflow uses that section as the release notes and fails if it is
   missing.
3. Commit, then tag and push:

   ```sh
   git tag -a v0.1.0 -m "Fire ID v0.1.0"
   git push origin main v0.1.0
   ```

4. Watch the *Release* workflow. When it is green, check the release page and
   `docker pull ghcr.io/lieyanc/fireid:0.1.0`.

## What the workflow does

| Job | Result |
|---|---|
| Version | Validates the tag; decides whether it is a pre-release. |
| CI | The whole of [`ci.yml`](.github/workflows/ci.yml): gofmt, go vet, race tests for both modules, UI lint/typecheck/build, a static build. Nothing is published unless it passes. |
| Archives and GitHub release | `make release-local` with the tag as `VERSION`: the UI is built, then `CGO_ENABLED=0` binaries for linux and darwin on amd64 and arm64 are packed as `fireid_<version>_<os>_<arch>.tar.gz` (binary, `LICENSE`, `README.md`, `CHANGELOG.md`) next to a `SHA256SUMS` file. `gh release create` publishes them with the changelog section as notes, using the workflow's own `GITHUB_TOKEN`. |
| Container image | `docker buildx` builds the [Dockerfile](Dockerfile) for `linux/amd64` and `linux/arm64` and pushes it to `ghcr.io/<owner>/fireid`. |

Image tags: `<version>` (for example `0.1.0`) always, and `latest` for releases
that are not pre-releases.

Re-running a failed workflow is safe: an existing release has its assets
replaced, and the image tags are overwritten.

The first image push creates the `fireid` package on ghcr.io as private. Make it
public once under the package's settings, and link it to the repository if GitHub
has not done so from the image's `org.opencontainers.image.source` label.

## Verifying a download

```sh
VERSION=0.1.0
base=https://github.com/lieyanc/FireID/releases/download/v$VERSION
curl -fLO "$base/fireid_${VERSION}_linux_amd64.tar.gz"
curl -fLO "$base/SHA256SUMS"
sha256sum --check --ignore-missing SHA256SUMS      # Linux
shasum -a 256 --check --ignore-missing SHA256SUMS  # macOS
```

Each line of `SHA256SUMS` is `<sha256>  <archive name>`. For the image, compare
the digest that `docker buildx imagetools inspect ghcr.io/lieyanc/fireid:$VERSION`
prints with the one in the workflow log.

## The container image

- Base `gcr.io/distroless/static-debian12:nonroot`: no shell, runs as UID/GID
  `65532`, the binary is `/usr/local/bin/fireid`.
- The default command is `-c /data/config.json`. `/data` is a volume and the only
  path the process writes (configuration, SQLite database with its WAL files,
  `master.key`), so the container runs with `--read-only`; add `--tmpfs /tmp` for
  SQLite's occasional temporary files.
- The listener port is `8099` (`server.port`). The configuration must set
  `server.host` to `0.0.0.0` inside a container and `dataDir` to `/data`; see the
  README's *Install* section for a complete example.

## Building locally

```sh
make release-local              # dist/*.tar.gz and dist/SHA256SUMS
make docker                     # fireid:<git describe> for the local architecture (needs Docker)
make release-local VERSION=v0.1.0-test PLATFORMS="linux/arm64"
```
