package agent

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/kogonia/tlsherd/internal/agentcfg"
	"github.com/kogonia/tlsherd/internal/config"
)

func TestLocalConfigWriteKeepsPrev(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.local.cfg")
	a, err := New(Options{
		Bootstrap: config.AgentBootstrap{
			ServerURL: "https://example.test", CertRoot: dir, StateDir: dir, LocalConfigPath: path,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	first, err := agentcfg.LocalFromService(agentcfg.ServiceNginx)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.writeLocalConfig(first); err != nil {
		t.Fatal(err)
	}
	second, err := agentcfg.LocalFromService(agentcfg.ServiceHAProxy)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.writeLocalConfig(second); err != nil {
		t.Fatal(err)
	}
	prev, err := os.ReadFile(path + ".prev")
	if err != nil {
		t.Fatal(err)
	}
	gotPrev, err := agentcfg.ParseLocal(prev)
	if err != nil {
		t.Fatal(err)
	}
	if gotPrev.Service != agentcfg.ServiceNginx {
		t.Fatalf("prev service = %q", gotPrev.Service)
	}
	cur, err := agentcfg.ParseLocal(mustRead(t, path))
	if err != nil {
		t.Fatal(err)
	}
	if cur.Service != agentcfg.ServiceHAProxy {
		t.Fatalf("cur service = %q", cur.Service)
	}
}

func TestLocalConfigUpdateConflict(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.local.cfg")
	a, err := New(Options{
		Bootstrap: config.AgentBootstrap{
			ServerURL: "https://example.test", CertRoot: dir, StateDir: dir, LocalConfigPath: path,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	lc, _ := agentcfg.LocalFromService(agentcfg.ServiceNginx)
	if err := a.writeLocalConfig(lc); err != nil {
		t.Fatal(err)
	}
	other, _ := agentcfg.LocalFromService(agentcfg.ServiceHTTPD)
	applied, err := a.acceptLocalConfigUpdate(&LocalConfigUpdate{Config: other, BaseHash: "deadbeef"})
	if err != nil {
		t.Fatal(err)
	}
	if applied || !a.localConfigConflict {
		t.Fatalf("applied=%v conflict=%v", applied, a.localConfigConflict)
	}
	if a.local.Service != agentcfg.ServiceNginx {
		t.Fatalf("service changed on conflict: %q", a.local.Service)
	}
}

func TestRuntimeCFGLocalWins(t *testing.T) {
	a := &Agent{cfg: agentcfg.Default(), local: agentcfg.DefaultLocal()}
	a.cfg.Verify.Command = []string{"server-side"}
	a.cfg.Restart.Name = "from-server"
	lc, _ := agentcfg.LocalFromService(agentcfg.ServiceNginx)
	a.local = lc
	rt := a.runtimeCFG()
	if rt.Verify.Command[0] != "nginx" || rt.Restart.Name != "nginx" {
		t.Fatalf("runtime = verify=%v restart=%#v", rt.Verify.Command, rt.Restart)
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
