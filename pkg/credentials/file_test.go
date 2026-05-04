package credentials_test

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/fastly/cli/pkg/credentials"
)

func TestFileStore(t *testing.T) {
	t.Parallel()
	runStoreSuite(t, "file", func(t *testing.T) credentials.Store {
		dir := t.TempDir()
		return credentials.NewFileStore(filepath.Join(dir, "credentials.toml"))
	})
}

func TestFileStore_MissingFileBehavesAsEmpty(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "credentials.toml")

	s := credentials.NewFileStore(path)

	names, err := s.Names()
	if err != nil {
		t.Fatalf("Names on missing file: %v", err)
	}
	if len(names) != 0 {
		t.Fatalf("expected empty Names on missing file, got %v", names)
	}
	if _, err := s.DefaultName(); !errors.Is(err, credentials.ErrNoDefault) {
		t.Fatalf("DefaultName on missing file: expected ErrNoDefault, got %v", err)
	}
	if _, err := s.Get("anything"); !errors.Is(err, credentials.ErrNotFound) {
		t.Fatalf("Get on missing file: expected ErrNotFound, got %v", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("read should not have created the file, stat err = %v", err)
	}
}

func TestFileStore_WritesFileWithStrictPerms(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission semantics")
	}
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "credentials.toml")

	s := credentials.NewFileStore(path)
	if err := s.Set("a", staticToken()); err != nil {
		t.Fatalf("Set: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Fatalf("file mode = %#o, want 0600", mode)
	}
}

func TestFileStore_RefusesWidePermsOnRead(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission semantics")
	}
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "credentials.toml")

	// #nosec G306 -- test deliberately writes wider-than-0600 perms to verify FileStore rejects them
	if err := os.WriteFile(path, []byte("default = \"\"\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	s := credentials.NewFileStore(path)
	_, err := s.Names()
	if !errors.Is(err, credentials.ErrCorrupt) {
		t.Fatalf("Names on wide-perm file: expected ErrCorrupt, got %v", err)
	}
}

func TestFileStore_CorruptFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "credentials.toml")

	if err := os.WriteFile(path, []byte("this is { not valid toml"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	s := credentials.NewFileStore(path)
	if _, err := s.Names(); !errors.Is(err, credentials.ErrCorrupt) {
		t.Fatalf("Names: expected ErrCorrupt, got %v", err)
	}
	if _, err := s.Get("a"); !errors.Is(err, credentials.ErrCorrupt) {
		t.Fatalf("Get: expected ErrCorrupt, got %v", err)
	}
	if err := s.Set("a", staticToken()); !errors.Is(err, credentials.ErrCorrupt) {
		t.Fatalf("Set: expected ErrCorrupt, got %v", err)
	}
}

func TestFileStore_PersistsAcrossInstances(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "credentials.toml")

	s1 := credentials.NewFileStore(path)
	if err := s1.Set("work", ssoToken()); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := s1.SetDefault("work"); err != nil {
		t.Fatalf("SetDefault: %v", err)
	}

	s2 := credentials.NewFileStore(path)
	got, err := s2.Get("work")
	if err != nil {
		t.Fatalf("Get from second instance: %v", err)
	}
	if got.AccessToken != "access_xyz" {
		t.Fatalf("AccessToken = %q, want %q", got.AccessToken, "access_xyz")
	}
	def, err := s2.DefaultName()
	if err != nil {
		t.Fatalf("DefaultName from second instance: %v", err)
	}
	if def != "work" {
		t.Fatalf("DefaultName = %q, want %q", def, "work")
	}
}

func TestFileStore_AtomicWriteLeavesNoTempOnSuccess(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "credentials.toml")

	s := credentials.NewFileStore(path)
	if err := s.Set("a", staticToken()); err != nil {
		t.Fatalf("Set: %v", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		switch e.Name() {
		case "credentials.toml", "credentials.toml.lock":
			continue
		}
		t.Errorf("unexpected leftover file in dir: %s", e.Name())
	}
}

func TestFileStore_CreatesParentDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission semantics")
	}
	t.Parallel()

	root := t.TempDir()
	dir := filepath.Join(root, "fastly")
	path := filepath.Join(dir, "credentials.toml")

	s := credentials.NewFileStore(path)
	if err := s.Set("a", staticToken()); err != nil {
		t.Fatalf("Set: %v", err)
	}

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	if !info.IsDir() {
		t.Fatalf("expected directory, got %v", info.Mode())
	}
	if mode := info.Mode().Perm(); mode != 0o700 {
		t.Fatalf("dir mode = %#o, want 0700", mode)
	}
}
