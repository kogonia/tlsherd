package agentcfg

import (
	"testing"
)

func TestServicesCatalog(t *testing.T) {
	ids := map[string]bool{}
	for _, s := range Services() {
		ids[s.ID] = true
		if s.ID != ServiceCustom && len(s.Verify.Command) == 0 {
			t.Fatalf("%s: expected default verify command", s.ID)
		}
		if s.ID != ServiceCustom && s.Restart.Name == "" {
			t.Fatalf("%s: expected default restart name", s.ID)
		}
	}
	for _, want := range []string{ServiceNginx, ServiceHAProxy, ServiceApache2, ServiceHTTPD, ServiceCustom} {
		if !ids[want] {
			t.Fatalf("missing service %s", want)
		}
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
