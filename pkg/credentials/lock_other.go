//go:build !unix && !windows

package credentials

// acquireLock is a no-op on platforms without flock(2) or
// LockFileEx. The CLI does not target plan9 or wasm in practice;
// concurrent writers on these platforms may lose updates.
func (s *FileStore) acquireLock() (*fileLock, error) {
	f, err := s.openLockFile()
	if err != nil {
		return nil, err
	}
	return &fileLock{f: f}, nil
}

func (l *fileLock) Release() {
	_ = l.f.Close()
}
