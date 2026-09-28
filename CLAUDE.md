# dind-authz-docker

Scoped guidance for anyone (human or agent) working in this repo. A
Docker-in-Docker image with an optional authorization-plugin layer that
denies privileged/host-escalation container creation - not actually tied to
code-docker specifically (hence this repo's name, not `code-dind`), it's a
generic "run a locked-down nested Docker daemon" component.

Consumed by [code-docker](https://github.com/qwreey/code-docker) as a
**remote-git build context pinned to a release tag**
(`https://github.com/qwreey/dind-authz-docker.git#<tag>`, `DIND_REF` in its
`.env`; `DIND_CONTEXT` points it at a local clone, conventionally
code-docker's `dev/dind-authz-docker`). It used to be a git submodule at
`code-dind/` (history preserved via `git subtree split` when it was extracted
from there), so a change here reaches code-docker only through a new tag.
It's the build source for code-docker's `code-docker-dind` service -
the privileged daemon code-docker talks to via `DOCKER_HOST=tcp://dind:2375`
to run `docker`/`docker compose`/`docker buildx` from inside code-docker. See
code-docker's own root `CLAUDE.md`'s "docker-compose topology" section for
how this fits into the wider network/trust model. Unlike `router/`, this repo
has no compose file of its own - it's Dockerfile-only, meant to be built as a
stage inside a consumer's own compose topology, not run standalone.
`.claude/dind-authz-plan.md` has the full design history/rationale behind
the authz plugin and userns-remap layering below - don't re-derive decisions
already recorded there.

## What's here

- `Dockerfile` - three build-target stages layered on top of stock
  `docker:dind`: `dind` (no protection), `dind-authz` (default - denies
  privileged/dangerous-cap/host-namespace/out-of-`/code`-mount container
  creation, plus the swarm and v2-plugin endpoint families wholesale, via a
  hand-written Go authz plugin), `dind-authz-remap`
  (`dind-authz` + Docker userns-remap, opt-in). `docker-compose.yml`'s
  `DIND_TARGET` env var picks which stage `code-docker-dind` actually
  builds/runs - a build-stage choice rather than a runtime toggle so an
  unwanted stage's code/config isn't even present in the image.
- `script/dind-entrypoint.sh` - the custom entrypoint (replaces
  `docker:dind`'s own) that binds the daemon to `code-docker-internal` only
  (never `0.0.0.0`), self-detects which of the stages above it's running on
  (starts the authz plugin / passes `--userns-remap` only if that stage's
  artifacts are present), and applies the same default-route-enforcement +
  nameserver-writing `netinit/` uses for code-docker's routing (code-docker's
  own DNS resolution moved to a local dnsmasq under `config/dns-local/`
  instead - see code-docker's own root `CLAUDE.md`'s
  `.claude/archive/dns-local-servfail-fix-done.md` for why dind still uses the
  plain `apply_nameserver` approach this paragraph describes), against
  dind's own netns instead (dind already has
  `NET_ADMIN` via
  `privileged: true`, so it doesn't need a separate sidecar the way
  code-docker does) - via `apply_default_route`/`apply_nameserver`, applied
  once synchronously before `dockerd` starts (so nested containers get
  correct DNS baked in from their very first `docker run`, not just once
  the background loop's first tick lands) and then kept current by a
  background loop, same shape as before.
- `netshare` functions (`apply_default_route`/`apply_nameserver`) come from
  [qwreey/router-docker-client](https://github.com/qwreey/router-docker-client)'s
  `netshare/` subdirectory, fetched by the Dockerfile's own `FROM scratch AS
  netshare` stage (`ADD ...router-docker-client.git#main:netshare /`, floating
  `#main` ref - see that repo's own `CLAUDE.md` for why). A BuildKit named
  context called `netshare` replaces that stage, which is how code-docker's
  compose builds against a local checkout (`ROUTER_CLIENT_SOURCE`).
- `dind-authz/` - the authz plugin's Go source (own `go.mod`, standalone
  module, `go test ./...` runs directly from here). Every request goes
  through `policy.go`'s `decide()`, which does two things: refuse a denied
  *endpoint family* outright (`deniedEndpointFamilies` - swarm/services/
  tasks/nodes/secrets/configs and plugins, all methods), then body-inspect
  the two endpoints that can smuggle host access through an otherwise
  ordinary call (`containers/create`, `volumes/create`). The family list is
  not "endpoints we don't use" tidiness - each one *routes around* the body
  checks: a swarm task's container is built by the daemon's own swarmkit
  executor and never reaches an authz plugin at all, and a v2 plugin's
  `config.json` declares its own caps/devices/host mounts/host namespaces
  and gets run as a runc container with exactly that. `/build` and
  `/session` are deliberately *not* in that list (BuildKit's escalation
  knobs are daemon-side entitlements, off by default, so denying them would
  break every `docker build` for nothing) - see the comment on
  `deniedEndpointFamilies` before adding or removing an entry. Both
  body-inspecting checks fail **closed** on a body they can't parse: a body
  this plugin's narrow structs can't decode is a body it can't check, and
  the daemon's own decoder is more permissive than they are.
- `config/dind-authz/*.default.json` - baked-in allow-list defaults for the
  authz plugin, merged at container-start with the live, host-editable
  `DIND_AUTHZ_VOLUME` mount (`/etc/dind-authz.d`) - deliberately never
  mounted into code-docker itself by any path, see `.claude/dind-authz-plan.md`'s
  "볼륨 격리" section for why.

## Naming

This repo is `dind-authz-docker`, not `code-dind` or `dind`, because it isn't
actually code-docker-specific - it's the generic dind+authz component,
consumed by code-docker (and could be consumed the same way by any other
project). Inside code-docker it used to be checked out as a submodule at
`code-dind/`, not `dind/`, originally so it couldn't
collide with code-docker's own repo-root runtime data directories - before
this repo was split out as its own subtree, the *source* for the authz
plugin lived at code-docker's repo-root `./dind-authz/`, the exact same path
the runtime volume defaulted to, a real collision. Every runtime data
directory in code-docker has since moved under a single repo-root `data/`
folder (`DIND_VOLUME`/`DIND_AUTHZ_VOLUME` now default to
`./data/dind`/`./data/dind-authz`, see code-docker's own `docker-compose.yml`
and root `CLAUDE.md`'s "docker-compose topology") specifically so source
subtrees/submodules and runtime data never share a naming namespace at all -
the original collision this section describes can't recur regardless of
what this repo was checked out as, but the names stuck.

## Ground rules

- Follow code-docker's own root `CLAUDE.md`'s override pattern and code
  style (minimal comments, no premature abstraction) for anything touching
  code-docker's side of the integration (docker-compose.yml, etc) - this
  repo itself has no override system of its own.
- This container is meaningfully more trusted than code-docker (it's
  `privileged: true` and can create host-kernel-equivalent containers) -
  changes here should be held to that higher trust bar, same framing
  `router/CLAUDE.md` uses for router.
- Before running `docker compose build`/`up`/`restart` against a live
  consumer container, confirm it's actually safe - someone else may be
  iterating on it.
