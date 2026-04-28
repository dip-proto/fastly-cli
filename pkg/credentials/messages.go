package credentials

import "fmt"

// SavedMessage returns the user-facing "token saved" message for
// backend. Centralised so every save site uses the same wording.
func SavedMessage(backend Backend, path string) string {
	switch backend {
	case BackendKeychain:
		return fmt.Sprintf("Token saved to system keychain (metadata at %s)", path)
	case BackendFile, BackendAuto, "":
		return fmt.Sprintf("Token saved to %s", path)
	}
	return fmt.Sprintf("Token saved to %s", path)
}
