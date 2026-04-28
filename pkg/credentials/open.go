package credentials

import "fmt"

// Open returns the Store and user-facing path for backend. File-bearing
// backends return the file users would inspect (credentials.toml for
// FileStore, the sidecar for the keychain backend).
func Open(backend Backend) (Store, string, error) {
	switch backend {
	case BackendFile, "":
		return NewFileStore(FilePath), FilePath, nil
	case BackendKeychain:
		s := NewKeychainStore(KeychainSidecarPath)
		return s, KeychainSidecarPath, nil
	case BackendAuto:
		return nil, "", fmt.Errorf("credentials: SelectBackend must resolve %q before Open is called", backend)
	}
	return nil, "", fmt.Errorf("credentials: unknown backend %q", backend)
}
