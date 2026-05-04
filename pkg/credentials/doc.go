// Package credentials defines the storage abstraction for Fastly CLI
// credentials and provides file- and memory-backed implementations.
//
// A Store holds named Tokens and tracks which one is the current default.
// Callers that need only token names or non-secret metadata should prefer
// Names and Metadata over Get; backends such as the OS keychain may unlock
// only when Get is called.
package credentials
