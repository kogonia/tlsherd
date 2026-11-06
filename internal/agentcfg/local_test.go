package agentcfg

import (
	"strings"
	"testing"
)

func TestServicesCatalog(t *testing.T) {
	ids := map[string]bool{}
	for _, s := range Services() {
		ids[s.ID] = true
		if s.ID != ServiceCustom && len(s.VerifyCommand) == 0 {
			t.Fatalf("%s: expected verify_command", s.ID)
		}
		if s.ID != ServiceCustom && s.DefaultName == "" {
			t.Fatalf("%s: expected default_name", s.ID)
		}
		if s.ID != ServiceCustom && len(s.Verify.Command) == 0 {
			t.Fatalf("%s: expected systemd verify preset", s.ID)
		}
		if s.ID != ServiceCustom && s.Restart.Name == "" {
			t.Fatalf("%s: expected systemd restart name", s.ID)
		}
	}
	for _, want := range []string{ServiceNginx, ServiceHAProxy, ServiceApache2, ServiceHTTPD, ServiceCustom} {
		if !ids[want] {
			t.Fatalf("missing service %s", want)
		}
	}
}

func TestPresetDockerNginx(t *testing.T) {
	info, ok := ServiceByID(ServiceNginx)
	if !ok {
		t.Fatal("nginx missing")
	}
	v, r := info.Preset(DeployDocker, "web")
	wantVerify := []string{"docker", "exec", "web", "nginx", "-t"}
	if strings.Join(v.Command, " ") != strings.Join(wantVerify, " ") {
		t.Fatalf("verify = %#v", v.Command)
	}
	if r.Type != DeployDocker || r.Name != "web" || !r.ReloadOnly {
		t.Fatalf("restart = %#v", r)
	}
	if strings.Join(r.Command, " ") != "nginx -s reload" {
		t.Fatalf("reload cmd = %#v", r.Command)
	}
}

func TestWrapVerifyArgv(t *testing.T) {
	got := WrapVerifyArgv([]string{"nginx", "-t"}, Restart{Type: DeployDocker, Name: "web"})
	if strings.Join(got, " ") != "docker exec web nginx -t" {
		t.Fatalf("got %#v", got)
	}
	already := []string{"docker", "exec", "web", "nginx", "-t"}
	if strings.Join(WrapVerifyArgv(already, Restart{Type: DeployDocker, Name: "web"}), " ") != strings.Join(already, " ") {
		t.Fatal("should not double-wrap")
	}
}

func TestLocalFromServiceAndHash(t *testing.T) {
	lc, err := LocalFromService(ServiceNginx)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateLocal(lc); err != nil {
		t.Fatal(err)
	}
	h1, err := HashLocal(lc)
	if err != nil || h1 == "" {
		t.Fatalf("hash: %v %q", err, h1)
	}
	lc.Restart.Name = "nginx-custom"
	h2, err := HashLocal(lc)
	if err != nil || h2 == h1 {
		t.Fatalf("hash should change: %v %q %q", err, h1, h2)
	}
}

func TestApplyLocalToConfigWins(t *testing.T) {
	cfg := Default()
	cfg.Verify.Command = []string{"old", "verify"}
	cfg.Restart = Restart{Type: "systemd", Name: "old"}
	lc, err := LocalFromService(ServiceNginx)
	if err != nil {
		t.Fatal(err)
	}
	out := ApplyLocalToConfig(cfg, lc)
	if len(out.Verify.Command) != 2 || out.Verify.Command[0] != "nginx" {
		t.Fatalf("verify = %#v", out.Verify.Command)
	}
	if out.Restart.Name != "nginx" || !out.Restart.ReloadOnly {
		t.Fatalf("restart = %#v", out.Restart)
	}
}

func TestParseLocalEmpty(t *testing.T) {
	lc, err := ParseLocal(nil)
	if err != nil {
		t.Fatal(err)
	}
	if lc.Service != ServiceCustom {
		t.Fatalf("service = %q", lc.Service)
	}
}
