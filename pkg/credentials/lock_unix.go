//go:build unix

package credentials

import (
	"os"
	"syscall"
)

func acquireLockAt(path string) (*fileLock, error) {
	f, err := openLockFileAt(path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(f.Name(), FilePermissions); err != nil {
		_ = f.Close()
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		_ = f.Close()
		return nil, err
	}
	return &fileLock{f: f}, nil
}

func (l *fileLock) Release() {
	_ = syscall.Flock(int(l.f.Fd()), syscall.LOCK_UN)
	_ = l.f.Close()
}
