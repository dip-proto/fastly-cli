package credentials

// KeyringClient is the test-only re-export of the keyringClient
// interface so out-of-package tests can supply an in-memory fake.
type KeyringClient = keyringClient

// NewKeychainStoreForTest returns a KeychainStore wired to the
// supplied client. Test-only.
func NewKeychainStoreForTest(path string, client KeyringClient) *KeychainStore {
	return newKeychainStoreWithClient(path, client)
}

// KeychainAccountForTest returns the account string a KeychainStore
// would use for the given (name, field) pair. Test-only.
func KeychainAccountForTest(name, field string) string {
	return keychainAccount(name, field)
}

// KeychainServiceForTest exposes the keychain "service" constant for
// tests that need to seed the fake.
const KeychainServiceForTest = keychainService

const (
	KeychainFieldTokenForTest        = keychainFieldToken
	KeychainFieldAccessTokenForTest  = keychainFieldAccessToken
	KeychainFieldRefreshTokenForTest = keychainFieldRefreshToken
)
