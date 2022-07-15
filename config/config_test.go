package config

import (
	"io/ioutil"
	"os"
	"path"
	"testing"
)

func TestConfig(t *testing.T) {
	testFile, err := ioutil.TempFile("/tmp", "testcfg")
	if err != nil {
		t.Fatalf("Unable to create TempFile: %v", err)
	}
	defer os.Remove(testFile.Name())
	fakeCfg := new(Config)
	fakeKey := path.Join(expandTilde("~"), ".ssh/ed25519")
	fakeCfg.PrivateKeys = []string{fakeKey}
	fakeCfg.ServerList = "dummy"
	fakeCfg.SSHUser = "dummy"
	fakeCfg.WriteConfig(testFile.Name())
	cfg, err := ParseConfig(testFile.Name())
	if err != nil {
		t.Fatalf("Unable to parse config: %v", err)
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
