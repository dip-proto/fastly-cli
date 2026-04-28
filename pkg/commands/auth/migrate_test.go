package auth_test

import (
	"path/filepath"
	"testing"

	"github.com/fastly/cli/pkg/credentials"
)

// withCredentialPaths redirects the package-level credential paths to
// dir for the test, so file backend and keychain sidecar both live in
// a controllable location.
func withCredentialPaths(t *testing.T, dir string) {
	t.Helper()
	oldFile := credentials.FilePath
	oldKey := credentials.KeychainSidecarPath
	oldSel := credentials.BackendSelectionPath
	credentials.FilePath = filepath.Join(dir, "credentials.toml")
	credentials.KeychainSidecarPath = filepath.Join(dir, "credentials.keychain.toml")
	credentials.BackendSelectionPath = filepath.Join(dir, "credentials.backend")
	t.Cleanup(func() {
		credentials.FilePath = oldFile
		credentials.KeychainSidecarPath = oldKey
		credentials.BackendSelectionPath = oldSel
	})
}

func TestAuthBackendSelectionRoundTrip(t *testing.T) {
	dir := t.TempDir()
	withCredentialPaths(t, dir)

	if err := credentials.WriteBackendSelection(credentials.BackendKeychain); err != nil {
		t.Fatalf("WriteBackendSelection: %v", err)
	}

	got, _, err := credentials.ReadBackendSelection()
	if err != nil {
		t.Fatalf("ReadBackendSelection: %v", err)
	}
	if got != credentials.BackendKeychain {
		t.Fatalf("ReadBackendSelection = %q, want %q", got, credentials.BackendKeychain)
	}
}

func TestAuthBackendSetMalformedRejected(t *testing.T) {
	dir := t.TempDir()
	withCredentialPaths(t, dir)

	if err := credentials.WriteBackendSelection(credentials.Backend("garbage")); err == nil {
		t.Fatal("expected WriteBackendSelection to reject unknown backend")
	}
}
