package credentials_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/fastly/cli/pkg/credentials"
)

func envFunc(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

// withSelectionPath swaps the package-level BackendSelectionPath to a
// temp path for the duration of the test, then restores it. Tests
// run in parallel only when they do not depend on this swap (i.e.
// not calls that read the selection file).
func withSelectionPath(t *testing.T, path string) {
	t.Helper()
	old := credentials.BackendSelectionPath
	credentials.BackendSelectionPath = path
	t.Cleanup(func() {
		credentials.BackendSelectionPath = old
	})
}

func TestSelectBackendEnvOverridesSidecar(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "credentials.backend")
	withSelectionPath(t, path)
	if err := credentials.WriteBackendSelection(credentials.BackendKeychain); err != nil {
		t.Fatalf("WriteBackendSelection: %v", err)
	}
	got := credentials.SelectBackend(envFunc(map[string]string{
		credentials.EnvCredentialsBackend: "file",
	}))
	if got != credentials.BackendFile {
		t.Fatalf("env should win: got %q, want %q", got, credentials.BackendFile)
	}
}

func TestSelectBackendSidecarWinsWhenEnvEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "credentials.backend")
	withSelectionPath(t, path)
	if err := credentials.WriteBackendSelection(credentials.BackendKeychain); err != nil {
		t.Fatalf("WriteBackendSelection: %v", err)
	}
	got := credentials.SelectBackend(envFunc(nil))
	if got != credentials.BackendKeychain {
		t.Fatalf("sidecar should win: got %q, want %q", got, credentials.BackendKeychain)
	}
}

func TestSelectBackendCIHeuristic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "credentials.backend")
	withSelectionPath(t, path)
	cases := []map[string]string{
		{"CI": "true"},
		{"CI": "1"},
		{"NON_INTERACTIVE": "1"},
	}
	for _, env := range cases {
		got := credentials.SelectBackend(envFunc(env))
		if got != credentials.BackendFile {
			t.Errorf("CI env %v: got %q, want %q", env, got, credentials.BackendFile)
		}
	}
}

func TestSelectBackendDefault(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "credentials.backend")
	withSelectionPath(t, path)
	got := credentials.SelectBackend(envFunc(nil))
	if got != credentials.BackendFile {
		t.Fatalf("default: got %q, want %q", got, credentials.BackendFile)
	}
}

func TestSelectBackendMalformedSidecarFallsThrough(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "credentials.backend")
	withSelectionPath(t, path)
	if err := writeFile(path, "garbage\n"); err != nil {
		t.Fatalf("seed sidecar: %v", err)
	}
	got := credentials.SelectBackend(envFunc(nil))
	if got != credentials.BackendFile {
		t.Fatalf("malformed sidecar should fall through to default: got %q", got)
	}
}

func TestSelectBackendAutoFallsThrough(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "credentials.backend")
	withSelectionPath(t, path)
	if err := writeFile(path, "auto\n"); err != nil {
		t.Fatalf("seed sidecar: %v", err)
	}
	got := credentials.SelectBackend(envFunc(map[string]string{
		credentials.EnvCredentialsBackend: "auto",
	}))
	if got != credentials.BackendFile {
		t.Fatalf("auto everywhere should resolve to file: got %q", got)
	}
}

func TestReadBackendSelectionMalformed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "credentials.backend")
	withSelectionPath(t, path)
	if err := writeFile(path, "wat\n"); err != nil {
		t.Fatalf("seed sidecar: %v", err)
	}
	b, raw, err := credentials.ReadBackendSelection()
	if err != nil {
		t.Fatalf("ReadBackendSelection: %v", err)
	}
	if b != credentials.BackendAuto {
		t.Errorf("Backend = %q, want %q", b, credentials.BackendAuto)
	}
	if raw != "wat" {
		t.Errorf("raw = %q, want %q", raw, "wat")
	}
}

func TestWriteBackendSelectionRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "credentials.backend")
	withSelectionPath(t, path)
	if err := credentials.WriteBackendSelection(credentials.BackendKeychain); err != nil {
		t.Fatalf("WriteBackendSelection: %v", err)
	}
	b, raw, err := credentials.ReadBackendSelection()
	if err != nil {
		t.Fatalf("ReadBackendSelection: %v", err)
	}
	if b != credentials.BackendKeychain || raw != "keychain" {
		t.Fatalf("round-trip: got (%q, %q), want (%q, %q)", b, raw, credentials.BackendKeychain, "keychain")
	}
}

func writeFile(path, contents string) error {
	return os.WriteFile(path, []byte(contents), 0o644)
}
