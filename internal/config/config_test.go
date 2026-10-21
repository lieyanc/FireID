package config

import (
	"os"
	"path/filepath"
	"testing"
)

// The configuration may hold the SMTP password and master.key unlocks every
// sealed secret: an existing copy that others can read is tightened on start.
func TestSecretFilesAreOwnerOnly(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	dataDir := filepath.Join(dir, "data")
	if err := os.WriteFile(cfgPath, []byte(`{"server":{"port":8099,"publicUrl":"https://id.example"},"dataDir":"`+dataDir+`"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(cfgPath, 0o644); err != nil {
		t.Fatal(err)
	}
	st, _, err := Open(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	first, err := st.MasterKey()
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dataDir, "master.key")
	if err := os.Chmod(keyPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Open(cfgPath); err != nil {
		t.Fatal(err)
	}
	again, err := st.MasterKey()
	if err != nil {
		t.Fatal(err)
	}
	if string(again) != string(first) {
		t.Fatal("the master key changed between reads")
	}
	for _, p := range []string{cfgPath, keyPath} {
		info, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if mode := info.Mode().Perm(); mode&0o077 != 0 {
			t.Errorf("%s has mode %o, want owner-only", filepath.Base(p), mode)
		}
	}
}
