package credentials

import (
	"strings"
)

// Backend identifies a credential storage implementation.
type Backend string

const (
	// BackendFile selects the FileStore (TOML file at credentials.toml).
	BackendFile Backend = "file"
	// BackendKeychain selects the OS keychain backend with sidecar.
	BackendKeychain Backend = "keychain"
	// BackendAuto resolves to a concrete backend at startup.
	BackendAuto Backend = "auto"
)

// EnvCredentialsBackend is the environment variable that overrides
// backend selection.
const EnvCredentialsBackend = "FASTLY_CREDENTIALS_BACKEND"

// SelectBackend resolves the credentials backend. It reads only the
// env lookup and the selection file, parses no TOML, and never logs.
// Use `auth backend show` to surface warnings about a malformed
// selection file.
//
// Order of precedence:
//
//  1. FASTLY_CREDENTIALS_BACKEND env var.
//  2. The credentials.backend selection file.
//  3. CI heuristic (CI=true or NON_INTERACTIVE=*) → file.
//  4. The release default → file.
//
// Unrecognised values fall through rather than failing; a typo in the
// selection file shouldn't block commands that don't read credentials.
func SelectBackend(getenv func(string) string) Backend {
	if b, ok := parseBackend(getenv(EnvCredentialsBackend)); ok && b != BackendAuto {
		return b
	}
	if b, _, err := ReadBackendSelection(); err == nil && b != "" && b != BackendAuto {
		return b
	}
	if isCIEnv(getenv) {
		return BackendFile
	}
	return BackendFile
}

// parseBackend normalises s to a Backend. Returns ok=false for empty
// or unrecognised values. BackendAuto is recognised but callers treat
// it as "fall through to the next source".
func parseBackend(s string) (Backend, bool) {
	switch strings.TrimSpace(strings.ToLower(s)) {
	case "":
		return "", false
	case string(BackendFile):
		return BackendFile, true
	case string(BackendKeychain):
		return BackendKeychain, true
	case string(BackendAuto):
		return BackendAuto, true
	}
	return "", false
}

func isCIEnv(getenv func(string) string) bool {
	if v := strings.TrimSpace(strings.ToLower(getenv("CI"))); v != "" && v != "false" && v != "0" {
		return true
	}
	if v := strings.TrimSpace(getenv("NON_INTERACTIVE")); v != "" && v != "0" && strings.ToLower(v) != "false" {
		return true
	}
	return false
}
