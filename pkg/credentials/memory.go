package credentials

import (
	"fmt"
	"sort"
)

// MemoryStore is an in-process Store backed by a map, intended for tests
// and as a reference implementation. Not safe across processes.
type MemoryStore struct {
	tokens map[string]*Token
	deflt  string
}

// NewMemoryStore returns an empty MemoryStore.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{tokens: make(map[string]*Token)}
}

// Names returns the credential names in deterministic order.
func (s *MemoryStore) Names() ([]string, error) {
	names := make([]string, 0, len(s.tokens))
	for n := range s.tokens {
		names = append(names, n)
	}
	sort.Strings(names)
	return names, nil
}

// Metadata returns the non-secret view of name.
func (s *MemoryStore) Metadata(name string) (*Metadata, error) {
	t, ok := s.tokens[name]
	if !ok {
		return nil, ErrNotFound
	}
	return t.Metadata(), nil
}

// Get returns a copy of the named credential.
func (s *MemoryStore) Get(name string) (*Token, error) {
	t, ok := s.tokens[name]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *t
	return &cp, nil
}

// Set stores a copy of t under name. Does not change the default.
func (s *MemoryStore) Set(name string, t *Token) error {
	if t == nil {
		return fmt.Errorf("credentials: Set requires a non-nil token")
	}
	cp := *t
	s.tokens[name] = &cp
	return nil
}

// Delete removes name. If name was the default, the default is cleared;
// the next DefaultName returns ErrNoDefault.
func (s *MemoryStore) Delete(name string) error {
	if _, ok := s.tokens[name]; !ok {
		return ErrNotFound
	}
	delete(s.tokens, name)
	if s.deflt == name {
		s.deflt = ""
	}
	return nil
}

// DefaultName returns the current default name.
func (s *MemoryStore) DefaultName() (string, error) {
	if s.deflt == "" {
		return "", ErrNoDefault
	}
	return s.deflt, nil
}

// SetDefault sets the default to name.
func (s *MemoryStore) SetDefault(name string) error {
	if _, ok := s.tokens[name]; !ok {
		return ErrNotFound
	}
	s.deflt = name
	return nil
}
