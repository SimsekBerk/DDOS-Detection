package app

import (
	"os"
	"path/filepath"
	"testing"
)

// A single-file bind mount (or a read-only directory) cannot be replaced by
// rename; the file must then be rewritten in place.
func TestWriteConfigFileFallsBackToInPlace(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0o700)
	if err := writeConfigFile(path, []byte("new")); err != nil {
		t.Fatalf("in-place fallback failed: %v", err)
	}
	if b, _ := os.ReadFile(path); string(b) != "new" {
		t.Fatalf("content = %q", b)
	}
	a := &App{Path: path}
	if !a.ConfigWritable() {
		t.Fatal("writable file reported read-only")
	}
	_ = os.Chmod(path, 0o400)
	if a.ConfigWritable() {
		t.Fatal("read-only file reported writable")
	}
}
