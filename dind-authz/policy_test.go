package main

import "testing"

func testConfig() *config {
	return &config{
		AllowedCaps:       map[string]bool{"NET_BIND_SERVICE": true},
		BindAllowPrefixes: []string{"/code/"},
	}
}

func TestEvaluate(t *testing.T) {
	cases := []struct {
		name  string
		body  string
		allow bool
	}{
		{"plain container, no HostConfig fields", `{}`, true},
		{"privileged denied", `{"HostConfig":{"Privileged":true}}`, false},
		{"allowed cap passes", `{"HostConfig":{"CapAdd":["NET_BIND_SERVICE"]}}`, true},
		{"allowed cap with CAP_ prefix passes", `{"HostConfig":{"CapAdd":["CAP_NET_BIND_SERVICE"]}}`, true},
		{"disallowed cap denied", `{"HostConfig":{"CapAdd":["SYS_ADMIN"]}}`, false},
		{"CapAdd ALL denied (not in allow-list)", `{"HostConfig":{"CapAdd":["ALL"]}}`, false},
		{"seccomp unconfined denied", `{"HostConfig":{"SecurityOpt":["seccomp=unconfined"]}}`, false},
		{"apparmor unconfined denied", `{"HostConfig":{"SecurityOpt":["apparmor=unconfined"]}}`, false},
		{"unrelated security-opt passes", `{"HostConfig":{"SecurityOpt":["no-new-privileges"]}}`, true},
		{"pid host denied", `{"HostConfig":{"PidMode":"host"}}`, false},
		{"network host denied", `{"HostConfig":{"NetworkMode":"host"}}`, false},
		{"network bridge passes", `{"HostConfig":{"NetworkMode":"bridge"}}`, true},
		{"ipc host denied", `{"HostConfig":{"IpcMode":"host"}}`, false},
		{"cgroupns host denied", `{"HostConfig":{"CgroupnsMode":"host"}}`, false},
		{"device passthrough denied", `{"HostConfig":{"Devices":[{"PathOnHost":"/dev/mem"}]}}`, false},
		{"device cgroup rule denied", `{"HostConfig":{"DeviceCgroupRules":["a *:* rwm"]}}`, false},
		{"bind under /code allowed", `{"HostConfig":{"Binds":["/code/myproject/pgdata:/var/lib/postgresql/data"]}}`, true},
		{"bind of /code root itself allowed", `{"HostConfig":{"Binds":["/code:/mnt"]}}`, true},
		{"bind outside /code denied", `{"HostConfig":{"Binds":["/etc:/mnt/etc"]}}`, false},
		{"bind of sibling-prefixed dir denied", `{"HostConfig":{"Binds":["/codesecrets:/mnt"]}}`, false},
		{"bind of docker.sock denied", `{"HostConfig":{"Binds":["/var/run/docker.sock:/var/run/docker.sock"]}}`, false},
		{"bind of authz config dir denied", `{"HostConfig":{"Binds":["/etc/dind-authz.d:/foo"]}}`, false},
		{"named volume allowed", `{"HostConfig":{"Binds":["mydata:/var/lib/postgresql/data"]}}`, true},
		{"mount type bind under /code allowed", `{"HostConfig":{"Mounts":[{"Type":"bind","Source":"/code/x"}]}}`, true},
		{"mount type bind outside /code denied", `{"HostConfig":{"Mounts":[{"Type":"bind","Source":"/root"}]}}`, false},
		{"mount type volume ignored by bind check", `{"HostConfig":{"Mounts":[{"Type":"volume","Source":"mydata"}]}}`, true},
		{"bind with .. traversal escaping /code denied", `{"HostConfig":{"Binds":["/code/../../etc:/mnt/etc"]}}`, false},
		{"mount type bind with .. traversal escaping /code denied", `{"HostConfig":{"Mounts":[{"Type":"bind","Source":"/code/../etc/dind-authz.d"}]}}`, false},
		{"mount type volume with local bind-passthrough device outside /code denied",
			`{"HostConfig":{"Mounts":[{"Type":"volume","VolumeOptions":{"DriverConfig":{"Name":"local","Options":{"type":"none","o":"bind","device":"/"}}}}]}}`, false},
		{"mount type volume with local bind-passthrough device under /code allowed",
			`{"HostConfig":{"Mounts":[{"Type":"volume","VolumeOptions":{"DriverConfig":{"Name":"local","Options":{"type":"none","o":"bind","device":"/code/x"}}}}]}}`, true},
		{"mount type volume with unrecognized driver and no options allowed",
			`{"HostConfig":{"Mounts":[{"Type":"volume","VolumeOptions":{"DriverConfig":{"Name":"nfs","Options":{}}}}]}}`, true},
		{"mount type volume with unrecognized driver and options denied",
			`{"HostConfig":{"Mounts":[{"Type":"volume","VolumeOptions":{"DriverConfig":{"Name":"nfs","Options":{"share":"host:/export"}}}}]}}`, false},
		{"malformed json fails closed", `not json`, false},
		{"truncated json fails closed", `{"HostConfig":{"Privileged"`, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			allow, reason := evaluate([]byte(tc.body), testConfig())
			if allow != tc.allow {
				t.Errorf("evaluate(%s) = allow=%v reason=%q, want allow=%v", tc.body, allow, reason, tc.allow)
			}
			if !allow && reason == "" {
				t.Errorf("evaluate(%s) denied with no reason", tc.body)
			}
		})
	}
}

func TestIsContainersCreate(t *testing.T) {
	cases := []struct {
		method, uri string
		want        bool
	}{
		{"POST", "/v1.43/containers/create", true},
		{"POST", "/v1.43/containers/create?name=foo", true},
		{"POST", "/containers/create", true},
		{"GET", "/v1.43/containers/create", false},
		{"POST", "/v1.43/containers/abc123/start", false},
		{"POST", "/v1.43/containers/abc123/exec", false},
		{"POST", "/v1.43/images/create", false},
	}
	for _, tc := range cases {
		if got := isContainersCreate(tc.method, tc.uri); got != tc.want {
			t.Errorf("isContainersCreate(%q, %q) = %v, want %v", tc.method, tc.uri, got, tc.want)
		}
	}
}

func TestEvaluateVolumeCreate(t *testing.T) {
	cases := []struct {
		name  string
		body  string
		allow bool
	}{
		{"plain named volume, no driver opts", `{"Name":"mydata"}`, true},
		{"local driver, no opts", `{"Name":"mydata","Driver":"local"}`, true},
		{"local driver bind-passthrough outside /code denied", `{"Name":"evil","Driver":"local","DriverOpts":{"type":"none","o":"bind","device":"/"}}`, false},
		{"local driver bind-passthrough under /code allowed", `{"Name":"ok","Driver":"local","DriverOpts":{"type":"none","o":"bind","device":"/code/x"}}`, true},
		{"unrecognized driver with opts denied", `{"Name":"evil","Driver":"nfs","DriverOpts":{"share":"host:/export"}}`, false},
		{"malformed json fails closed", `not json`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			allow, reason := evaluateVolumeCreate([]byte(tc.body), testConfig())
			if allow != tc.allow {
				t.Errorf("evaluateVolumeCreate(%s) = allow=%v reason=%q, want allow=%v", tc.body, allow, reason, tc.allow)
			}
		})
	}
}

func TestIsVolumesCreate(t *testing.T) {
	cases := []struct {
		method, uri string
		want        bool
	}{
		{"POST", "/v1.43/volumes/create", true},
		{"POST", "/volumes/create", true},
		{"GET", "/v1.43/volumes/create", false},
		{"POST", "/v1.43/volumes/myvol", false},
		{"POST", "/v1.43/containers/create", false},
	}
	for _, tc := range cases {
		if got := isVolumesCreate(tc.method, tc.uri); got != tc.want {
			t.Errorf("isVolumesCreate(%q, %q) = %v, want %v", tc.method, tc.uri, got, tc.want)
		}
	}
}

func TestMergeConfig(t *testing.T) {
	dst := &config{AllowedCaps: map[string]bool{"NET_BIND_SERVICE": true}, BindAllowPrefixes: []string{"/code/"}}
	src := &config{AllowedCaps: map[string]bool{"SYS_PTRACE": true}, BindAllowPrefixes: []string{"/code/", "/tmp/scratch/"}}
	mergeConfig(dst, src)

	if !dst.AllowedCaps["NET_BIND_SERVICE"] || !dst.AllowedCaps["SYS_PTRACE"] {
		t.Errorf("merged caps = %v, want both NET_BIND_SERVICE and SYS_PTRACE", dst.AllowedCaps)
	}
	if len(dst.BindAllowPrefixes) != 2 {
		t.Errorf("merged bind prefixes = %v, want exactly 2 (dedup /code/)", dst.BindAllowPrefixes)
	}
}

func TestAPIRoot(t *testing.T) {
	cases := []struct{ uri, want string }{
		{"/v1.45/swarm/init", "swarm"},
		{"/swarm/init", "swarm"},
		{"/v1.51/plugins/foo/enable?timeout=0", "plugins"},
		{"/v1.45/containers/create?name=x", "containers"},
		{"/_ping", "_ping"},
		{"/", ""},
		{"/volumes", "volumes"},
	}
	for _, tc := range cases {
		if got := apiRoot(tc.uri); got != tc.want {
			t.Errorf("apiRoot(%q) = %q, want %q", tc.uri, got, tc.want)
		}
	}
}

// TestDecide covers the dispatch itself: the endpoint families denied
// outright, and that denying them didn't cost the ordinary calls
// `docker`/`docker compose`/`docker buildx` make all day.
func TestDecide(t *testing.T) {
	cases := []struct {
		name        string
		method, uri string
		body        string
		allow       bool
	}{
		{"swarm init denied", "POST", "/v1.45/swarm/init", `{}`, false},
		{"swarm join denied", "POST", "/v1.45/swarm/join", `{}`, false},
		{"swarm inspect denied too", "GET", "/v1.45/swarm", ``, false},
		{"services create denied", "POST", "/services/create", `{}`, false},
		{"services list denied", "GET", "/v1.45/services", ``, false},
		{"tasks list denied", "GET", "/v1.45/tasks", ``, false},
		{"nodes list denied", "GET", "/v1.45/nodes", ``, false},
		{"secrets create denied", "POST", "/v1.45/secrets/create", `{}`, false},
		{"configs create denied", "POST", "/v1.45/configs/create", `{}`, false},
		{"plugins create denied", "POST", "/v1.45/plugins/create?name=x", ``, false},
		{"plugins enable denied", "POST", "/v1.45/plugins/foo/enable", ``, false},
		{"plugins list denied", "GET", "/v1.45/plugins", ``, false},
		{"malformed container create denied", "POST", "/v1.45/containers/create", `not json`, false},
		{"privileged container create still denied", "POST", "/v1.45/containers/create", `{"HostConfig":{"Privileged":true}}`, false},
		{"malformed volume create denied", "POST", "/v1.45/volumes/create", `not json`, false},
		{"normal container create allowed", "POST", "/v1.45/containers/create?name=web", `{"Image":"alpine","HostConfig":{"Binds":["/code/x:/x"]}}`, true},
		{"container list allowed", "GET", "/v1.45/containers/json", ``, true},
		{"container start allowed", "POST", "/v1.45/containers/abc/start", ``, true},
		{"image pull allowed", "POST", "/v1.45/images/create?fromImage=alpine", ``, true},
		{"build allowed", "POST", "/v1.45/build?t=x", ``, true},
		{"buildkit session allowed", "POST", "/v1.45/session", ``, true},
		{"ping allowed", "GET", "/_ping", ``, true},
		{"normal volume create allowed", "POST", "/v1.45/volumes/create", `{"Name":"mydata"}`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			allow, reason := decide(tc.method, tc.uri, []byte(tc.body), testConfig())
			if allow != tc.allow {
				t.Errorf("decide(%s %s, %s) = allow=%v reason=%q, want allow=%v", tc.method, tc.uri, tc.body, allow, reason, tc.allow)
			}
			if !allow && reason == "" {
				t.Errorf("decide(%s %s) denied with no reason", tc.method, tc.uri)
			}
		})
	}
}
