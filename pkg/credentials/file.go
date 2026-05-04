package credentials

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync"

	toml "github.com/pelletier/go-toml"
)

// FileStore persists credentials in a TOML file at a fixed path.
//
// Writes are atomic: marshal, write to a same-directory temp file opened
// with O_EXCL and mode 0600, fsync, rename, then best-effort fsync the
// parent directory. On read, Unix files with permissions wider than 0600
// are rejected as ErrCorrupt (Windows ACLs are not checked).
//
// A sync.Mutex serializes calls within the process. Read-modify-write
// operations (Set, Delete, SetDefault) also take an OS advisory lock on
// "<path>.lock" so concurrent CLI invocations cannot race; reads rely on
// atomic rename to never observe a partial file. The advisory lock uses
// flock(2) on Unix and LockFileEx on Windows; elsewhere it degrades to a
// no-op and concurrent writers may lose updates.
type FileStore struct {
	path string
	mu   sync.Mutex
}

// NewFileStore returns a FileStore that reads and writes path.
func NewFileStore(path string) *FileStore {
	return &FileStore{path: path}
}

// Path returns the on-disk path. Useful for user-facing messages.
func (s *FileStore) Path() string {
	return s.path
}

type fileFormat struct {
	Default string            `toml:"default"`
	Tokens  map[string]*Token `toml:"tokens"`
}

func (s *FileStore) load() (*fileFormat, error) {
	info, err := os.Stat(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &fileFormat{Tokens: map[string]*Token{}}, nil
		}
		return nil, fmt.Errorf("%w: stat %s: %v", ErrUnavailable, s.path, err)
	}

	if runtime.GOOS != "windows" {
		if mode := info.Mode().Perm(); mode&^FilePermissions != 0 {
			return nil, fmt.Errorf("%w: %s has permissions %#o, expected 0600 or stricter",
				ErrCorrupt, s.path, mode)
		}
	}

	data, err := os.ReadFile(s.path)
	if err != nil {
		return nil, fmt.Errorf("%w: read %s: %v", ErrUnavailable, s.path, err)
	}

	f := &fileFormat{}
	if err := toml.Unmarshal(data, f); err != nil {
		return nil, fmt.Errorf("%w: parse %s: %v", ErrCorrupt, s.path, err)
	}
	if f.Tokens == nil {
		f.Tokens = map[string]*Token{}
	}
	return f, nil
}

func (s *FileStore) save(f *fileFormat) error {
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, DirectoryPermissions); err != nil {
		return fmt.Errorf("%w: mkdir %s: %v", ErrUnavailable, dir, err)
	}

	data, err := toml.Marshal(f)
	if err != nil {
		return fmt.Errorf("%w: encode: %v", ErrUnavailable, err)
	}

	tmp := fmt.Sprintf("%s.tmp.%d", s.path, os.Getpid())
	fp, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, FilePermissions)
	if err != nil {
		return fmt.Errorf("%w: create %s: %v", ErrUnavailable, tmp, err)
	}
	cleanup := func() { _ = os.Remove(tmp) }

	if _, err := fp.Write(data); err != nil {
		_ = fp.Close()
		cleanup()
		return fmt.Errorf("%w: write %s: %v", ErrUnavailable, tmp, err)
	}
	if err := fp.Sync(); err != nil {
		_ = fp.Close()
		cleanup()
		return fmt.Errorf("%w: fsync %s: %v", ErrUnavailable, tmp, err)
	}
	if err := fp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("%w: close %s: %v", ErrUnavailable, tmp, err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		cleanup()
		return fmt.Errorf("%w: rename %s -> %s: %v", ErrUnavailable, tmp, s.path, err)
	}

	syncDir(dir)
	return nil
}

// Names returns all credential names in deterministic order.
func (s *FileStore) Names() ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	f, err := s.load()
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(f.Tokens))
	for n := range f.Tokens {
		names = append(names, n)
	}
	sort.Strings(names)
	return names, nil
}

// Metadata returns the non-secret view of name.
func (s *FileStore) Metadata(name string) (*Metadata, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	f, err := s.load()
	if err != nil {
		return nil, err
	}
	t, ok := f.Tokens[name]
	if !ok {
		return nil, ErrNotFound
	}
	return t.Metadata(), nil
}

// Get returns a copy of the named credential.
func (s *FileStore) Get(name string) (*Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	f, err := s.load()
	if err != nil {
		return nil, err
	}
	t, ok := f.Tokens[name]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *t
	return &cp, nil
}

// Set stores a copy of t under name. Does not change the default.
func (s *FileStore) Set(name string, t *Token) error {
	if t == nil {
		return fmt.Errorf("credentials: Set requires a non-nil token")
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	lock, err := s.acquireLock()
	if err != nil {
		return fmt.Errorf("%w: acquire lock: %v", ErrUnavailable, err)
	}
	defer lock.Release()

	f, err := s.load()
	if err != nil {
		return err
	}
	cp := *t
	f.Tokens[name] = &cp
	return s.save(f)
}

// Delete removes name. If name was the default, the default is cleared;
// the next DefaultName returns ErrNoDefault.
func (s *FileStore) Delete(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	lock, err := s.acquireLock()
	if err != nil {
		return fmt.Errorf("%w: acquire lock: %v", ErrUnavailable, err)
	}
	defer lock.Release()

	f, err := s.load()
	if err != nil {
		return err
	}
	if _, ok := f.Tokens[name]; !ok {
		return ErrNotFound
	}
	delete(f.Tokens, name)
	if f.Default == name {
		f.Default = ""
	}
	return s.save(f)
}

// DefaultName returns the current default credential name.
func (s *FileStore) DefaultName() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	f, err := s.load()
	if err != nil {
		return "", err
	}
	if f.Default == "" {
		return "", ErrNoDefault
	}
	return f.Default, nil
}

// SetDefault sets the default to name.
func (s *FileStore) SetDefault(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	lock, err := s.acquireLock()
	if err != nil {
		return fmt.Errorf("%w: acquire lock: %v", ErrUnavailable, err)
	}
	defer lock.Release()

	f, err := s.load()
	if err != nil {
		return err
	}
	if _, ok := f.Tokens[name]; !ok {
		return ErrNotFound
	}
	f.Default = name
	return s.save(f)
}
