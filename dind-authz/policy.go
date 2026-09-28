package main

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// config is the merged conf.d policy data: what's explicitly allowed.
// Anything not listed here is denied by default (undefined == false).
type config struct {
	AllowedCaps       map[string]bool `json:"allowed_caps"`
	BindAllowPrefixes []string        `json:"bind_allow_prefixes"`
}

func mergeConfig(dst, src *config) {
	if dst.AllowedCaps == nil {
		dst.AllowedCaps = map[string]bool{}
	}
	for k, v := range src.AllowedCaps {
		if v {
			dst.AllowedCaps[k] = true
		}
	}
	for _, p := range src.BindAllowPrefixes {
		exists := false
		for _, have := range dst.BindAllowPrefixes {
			if have == p {
				exists = true
				break
			}
		}
		if !exists {
			dst.BindAllowPrefixes = append(dst.BindAllowPrefixes, p)
		}
	}
}

// createBody is the subset of a POST .../containers/create request body
// this plugin inspects. Every other field passes through untouched.
type createBody struct {
	HostConfig struct {
		Privileged        bool              `json:"Privileged"`
		CapAdd            []string          `json:"CapAdd"`
		SecurityOpt       []string          `json:"SecurityOpt"`
		PidMode           string            `json:"PidMode"`
		NetworkMode       string            `json:"NetworkMode"`
		IpcMode           string            `json:"IpcMode"`
		CgroupnsMode      string            `json:"CgroupnsMode"`
		Devices           []json.RawMessage `json:"Devices"`
		DeviceCgroupRules []string          `json:"DeviceCgroupRules"`
		Binds             []string          `json:"Binds"`
		Mounts            []struct {
			Type          string `json:"Type"`
			Source        string `json:"Source"`
			VolumeOptions *struct {
				DriverConfig *struct {
					Name    string            `json:"Name"`
					Options map[string]string `json:"Options"`
				} `json:"DriverConfig"`
			} `json:"VolumeOptions"`
		} `json:"Mounts"`
	} `json:"HostConfig"`
}

// volumeCreateBody is the subset of a POST .../volumes/create request body
// this plugin inspects — the "local" driver options here use the same
// bind-passthrough mechanism as a Mounts[].VolumeOptions.DriverConfig entry
// above, just under the top-level Driver/DriverOpts field names Docker uses
// for this endpoint instead.
type volumeCreateBody struct {
	Driver     string            `json:"Driver"`
	DriverOpts map[string]string `json:"DriverOpts"`
}

// deniedEndpointFamilies maps an endpoint family (the first path segment
// after the optional /v1.NN/ API-version prefix) to the reason it's refused.
// These are whole families this environment has no use for, each of which
// hands out host-level privilege by a route the container-create checks
// below never see:
//
//   - swarm/services/tasks/nodes: a swarm task's container is created by the
//     daemon's own swarmkit executor, not by an API call, so it never reaches
//     this plugin at all — `docker service create --cap-add ALL --mount
//     type=bind,source=/,...` would sail straight past every check in
//     evaluate(). Nothing short of refusing swarm itself closes that.
//   - secrets/configs: swarm-only endpoints, meaningless without swarm and
//     part of the same surface.
//   - plugins: a v2 plugin's config.json declares its own capabilities,
//     allowAllDevices, host bind mounts and host network/pid namespaces, and
//     the daemon then runs it as a runc container with exactly that. `docker
//     plugin create` builds one from a local rootfs tar — no registry needed.
//
// Denied for every method, not just the mutating ones: the GETs (listing
// services, inspecting nodes) are harmless on their own, but a family-wide
// rule is one line to read and leaves no "is this one a reader?" judgement
// for the next person touching it. Nothing in `docker`/`docker compose`/
// `docker buildx`'s normal, non-swarm workflow calls any of these.
//
// Two neighbours deliberately *not* listed: /build and /session. BuildKit's
// escalation knobs are gated daemon-side rather than in the request —
// `RUN --security=insecure` needs the daemon's builder.entitlements.
// security-insecure (false unless someone turns it on in dind's own
// daemon.json), and `RUN --mount=type=bind` binds build context/stages, not
// host paths — so denying them would break every `docker build` for no gain.
var deniedEndpointFamilies = map[string]string{
	"swarm":    "swarm mode is not allowed",
	"services": "swarm services are not allowed",
	"tasks":    "swarm tasks are not allowed",
	"nodes":    "swarm nodes are not allowed",
	"secrets":  "swarm secrets are not allowed",
	"configs":  "swarm configs are not allowed",
	"plugins":  "docker plugins are not allowed",
}

// decide is the whole policy for one authorization request: a denied
// endpoint family first, then the body-inspecting checks for the two
// endpoints that can smuggle host access through an otherwise ordinary
// call. Everything else is allowed — inverting that default (allow-list the
// endpoints `docker compose` needs) was considered and rejected as a
// regression risk out of proportion to the gain, see the family list above.
func decide(method, uri string, body []byte, cfg *config) (allow bool, reason string) {
	if reason, denied := deniedEndpointFamilies[apiRoot(uri)]; denied {
		return false, reason
	}
	switch {
	case isContainersCreate(method, uri):
		return evaluate(body, cfg)
	case isVolumesCreate(method, uri):
		return evaluateVolumeCreate(body, cfg)
	}
	return true, ""
}

// apiRoot returns a request URI's first path segment with the /v1.NN/
// API-version prefix and any query string removed — "/v1.45/swarm/init" and
// "/plugins/foo/enable?x=1" both reduce to the family name the deny list is
// keyed on. Same prefix/query handling isContainersCreate does, just applied
// from the front of the path instead of the back.
func apiRoot(uri string) string {
	u := uri
	if i := strings.IndexByte(u, '?'); i >= 0 {
		u = u[:i]
	}
	u = strings.TrimPrefix(u, "/")
	first, rest, _ := strings.Cut(u, "/")
	if len(first) > 1 && first[0] == 'v' && first[1] >= '0' && first[1] <= '9' {
		first, _, _ = strings.Cut(rest, "/")
	}
	return first
}

// isContainersCreate reports whether a request is a "create a container"
// call, independent of the /v1.NN/ API-version prefix Docker clients send.
func isContainersCreate(method, uri string) bool {
	if method != "POST" {
		return false
	}
	u := uri
	if i := strings.IndexByte(u, '?'); i >= 0 {
		u = u[:i]
	}
	return path.Base(u) == "create" && strings.HasSuffix(path.Dir(u), "/containers")
}

// isVolumesCreate reports whether a request is a "create a volume" call —
// gated the same way as isContainersCreate, since a malicious named volume
// created here (with bind-passthrough driver options) could otherwise be
// pre-created unevaluated and referenced by name in a later container
// create's Mounts/Binds.
func isVolumesCreate(method, uri string) bool {
	if method != "POST" {
		return false
	}
	u := uri
	if i := strings.IndexByte(u, '?'); i >= 0 {
		u = u[:i]
	}
	return path.Base(u) == "create" && strings.HasSuffix(path.Dir(u), "/volumes")
}

// evaluate decides whether a container-create request is allowed under cfg.
// docker update cannot change Privileged/CapAdd/SecurityOpt/*Mode/Devices on
// an existing container (the Engine API itself rejects that), so gating
// only the create call is sufficient for the fields checked here.
func evaluate(body []byte, cfg *config) (allow bool, reason string) {
	var req createBody
	if err := json.Unmarshal(body, &req); err != nil {
		// A body we can't parse is a body we can't check. The daemon's
		// own decoder is more permissive than this narrow struct, so
		// "let the daemon reject it" was a guess, not a guarantee —
		// and the only fail-open direction left in an otherwise
		// fail-closed plugin.
		return false, "malformed request body"
	}
	hc := req.HostConfig

	if hc.Privileged {
		return false, "privileged containers are not allowed"
	}
	for _, capName := range hc.CapAdd {
		normalized := strings.ToUpper(strings.TrimPrefix(capName, "CAP_"))
		if !cfg.AllowedCaps[normalized] {
			return false, "capability not in allow-list: " + capName
		}
	}
	for _, opt := range hc.SecurityOpt {
		lower := strings.ToLower(opt)
		if strings.Contains(lower, "seccomp=unconfined") ||
			strings.Contains(lower, "seccomp:unconfined") ||
			strings.Contains(lower, "apparmor=unconfined") ||
			strings.Contains(lower, "apparmor:unconfined") ||
			strings.Contains(lower, "label=disable") ||
			strings.Contains(lower, "label:disable") {
			return false, "disabling seccomp/apparmor/labeling is not allowed: " + opt
		}
	}
	if hc.PidMode == "host" {
		return false, "pid=host is not allowed"
	}
	if hc.NetworkMode == "host" {
		return false, "network=host is not allowed"
	}
	if hc.IpcMode == "host" {
		return false, "ipc=host is not allowed"
	}
	if hc.CgroupnsMode == "host" {
		return false, "cgroupns=host is not allowed"
	}
	if len(hc.Devices) > 0 {
		return false, "device passthrough is not allowed"
	}
	if len(hc.DeviceCgroupRules) > 0 {
		return false, "device cgroup rules are not allowed"
	}
	for _, b := range hc.Binds {
		src := b
		if i := strings.IndexByte(b, ':'); i >= 0 {
			src = b[:i]
		}
		if !bindSourceAllowed(src, cfg.BindAllowPrefixes) {
			return false, "bind mount source not allowed: " + src
		}
	}
	for _, m := range hc.Mounts {
		switch m.Type {
		case "bind":
			if !bindSourceAllowed(m.Source, cfg.BindAllowPrefixes) {
				return false, "bind mount source not allowed: " + m.Source
			}
		case "volume":
			var driverName string
			var opts map[string]string
			if m.VolumeOptions != nil && m.VolumeOptions.DriverConfig != nil {
				driverName = m.VolumeOptions.DriverConfig.Name
				opts = m.VolumeOptions.DriverConfig.Options
			}
			if !driverOptsAllowed(driverName, opts, cfg.BindAllowPrefixes) {
				return false, "volume mount driver options not allowed (bind-mount passthrough): " + m.Source
			}
		}
	}

	return true, ""
}

// evaluateVolumeCreate decides whether a POST .../volumes/create request is
// allowed under cfg — the "local" driver's type=none/o=bind/device=<path>
// options perform an arbitrary host bind mount despite the request being
// nominally a "volume", so this closes the same hole evaluate()'s Mounts
// handling does, for a volume created ahead of time and referenced by name
// in a later container-create call instead of inlined directly.
func evaluateVolumeCreate(body []byte, cfg *config) (allow bool, reason string) {
	var req volumeCreateBody
	if err := json.Unmarshal(body, &req); err != nil {
		return false, "malformed request body"
	}
	if !driverOptsAllowed(req.Driver, req.DriverOpts, cfg.BindAllowPrefixes) {
		return false, "volume driver options not allowed (bind-mount passthrough)"
	}
	return true, ""
}

// driverOptsAllowed reports whether a volume's driver+options are safe: a
// plain named/anonymous volume with the default (or no) driver and no
// options lives entirely inside dind's own storage and is always safe. Any
// driver options at all are only allowed if they don't request a host bind
// passthrough — recognized here by the presence of a "device" option, the
// "local" driver's trigger for treating the volume as a bind mount of that
// host path (typically paired with "o=bind"/"type=none", but the device key
// alone is treated as the meaningful signal so this fails closed rather than
// pattern-matching every way to spell "bind"). An unrecognized (non-empty,
// non-"local") driver name can't be reasoned about at all, so it's only
// allowed with zero options.
func driverOptsAllowed(driverName string, opts map[string]string, allowRoots []string) bool {
	if driverName != "" && driverName != "local" {
		return len(opts) == 0
	}
	if len(opts) == 0 {
		return true
	}
	device, hasDevice := opts["device"]
	if !hasDevice {
		return true
	}
	return bindSourceAllowed(device, allowRoots)
}

// bindSourceAllowed reports whether src is safe as a bind-mount source.
// Named volumes (a source that isn't an absolute path) are always allowed
// — they live inside dind's own storage, not the host filesystem. Absolute
// paths must equal, or fall under, one of the configured allow-list roots
// (each entry may be given with or without a trailing slash — "/code" and
// "/code/" mean the same root), and must do so twice over:
//
//   - lexically, after path.Clean, so "/code/../etc" is refused;
//   - after following symlinks on disk, because that is what the daemon
//     does when it mounts the source. Everything under /code is writable by
//     the code-docker container that talks to this daemon, so without this
//     a symlink /code/x -> / made the whole of dind's own filesystem
//     (privileged, so including its /dev) mountable while the request text
//     said "/code/x".
//
// This plugin runs inside the dind container, so it sees the same
// filesystem the daemon resolves against. What it cannot close is the race
// between this check and the daemon's mount: a caller that swaps a checked
// directory for a symlink in between still wins. The dind-authz-remap
// target (userns-remap) is the layer that bounds what that race can reach.
func bindSourceAllowed(src string, allowRoots []string) bool {
	if !strings.HasPrefix(src, "/") {
		return true
	}
	cleanSrc := path.Clean(src)
	resolvedSrc, err := resolveOnDisk(cleanSrc)
	if err != nil {
		return false
	}
	for _, root := range allowRoots {
		cleanRoot := path.Clean(root)
		if !underRoot(cleanSrc, cleanRoot) {
			continue
		}
		resolvedRoot, err := resolveOnDisk(cleanRoot)
		if err != nil {
			continue
		}
		if underRoot(resolvedSrc, resolvedRoot) {
			return true
		}
	}
	return false
}

func underRoot(p, root string) bool {
	return p == root || root == "/" || strings.HasPrefix(p, root+"/")
}

// resolveOnDisk returns p with every symlink resolved. A bind source that
// doesn't exist yet is legal — the daemon creates a missing `-v` source
// directory — so the deepest existing ancestor is resolved and the missing
// tail re-appended; that tail can't contain symlinks, since it doesn't
// exist. A component that exists only as a dangling symlink is an error
// rather than "missing": the daemon would follow it when creating the
// directory, and where it points is exactly what this check can't see.
func resolveOnDisk(p string) (string, error) {
	missing := ""
	cur := p
	for {
		resolved, err := filepath.EvalSymlinks(cur)
		if err == nil {
			return path.Join(resolved, missing), nil
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return "", err
		}
		if _, lerr := os.Lstat(cur); lerr == nil {
			return "", errors.New("dangling symlink in bind source: " + cur)
		}
		parent := path.Dir(cur)
		if parent == cur {
			return "", err
		}
		missing = path.Join(path.Base(cur), missing)
		cur = parent
	}
}
