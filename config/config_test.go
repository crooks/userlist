package config

import (
	"os"
	"path"
	"testing"
)

func TestConfig(t *testing.T) {
	testFile, err := os.CreateTemp("", "testcfg")
	if err != nil {
		t.Fatalf("Unable to create TempFile: %v", err)
	}
	defer os.Remove(testFile.Name())
	fakeCfg := new(Config)
	fakeKey := path.Join(expandTilde("~"), ".ssh/ed25519")
	fakeCfg.PrivateKeys = []string{fakeKey}
	fakeCfg.Sources.Servers = append(fakeCfg.Sources.Servers, "dummyServer")
	fakeCfg.SSHUser = "dummy"
	fakeCfg.WriteConfig(testFile.Name())
	cfg, err := ParseConfig(testFile.Name())
	if err != nil {
		t.Fatalf("Unable to parse config: %v", err)
	}
	if cfg.Sources.Servers[0] != "dummyServer" {
		t.Errorf("Expect source of %s.  Got %s", fakeCfg.Sources.Servers[0], cfg.Sources.Servers[0])
	}
	if len(cfg.PrivateKeys) != 1 {
		t.Errorf("Expected a single default private key. Got %d.", len(cfg.PrivateKeys))
	}
	if cfg.PrivateKeys[0] != fakeCfg.PrivateKeys[0] {
		t.Errorf("Unexpected private key file: Expected=\"%s\", Got=\"%s\"", fakeCfg.PrivateKeys[0], cfg.PrivateKeys[0])
	}
	if cfg.LogLevel != "info" {
		t.Errorf("Unexpected loglevel: Expected=info, Got=\"%s\"", cfg.LogLevel)
	}
}

func TestFlags(t *testing.T) {
	f := ParseFlags()
	expectingConfig := "userlist.yml"
	if f.Config != expectingConfig {
		t.Fatalf("Unexpected config flag: Expected=%s, Got=%s", expectingConfig, f.Config)
	}
}
