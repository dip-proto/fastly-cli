//go:build windows

package credentials

import "golang.org/x/sys/windows"

func acquireLockAt(path string) (*fileLock, error) {
	f, err := openLockFileAt(path)
	if err != nil {
		return nil, err
	}
	handle := windows.Handle(f.Fd())
	var ol windows.Overlapped
	if err := windows.LockFileEx(handle, windows.LOCKFILE_EXCLUSIVE_LOCK, 0, ^uint32(0), ^uint32(0), &ol); err != nil {
		_ = f.Close()
		return nil, err
	}
	return &fileLock{f: f}, nil
}

func (l *fileLock) Release() {
	handle := windows.Handle(l.f.Fd())
	var ol windows.Overlapped
	_ = windows.UnlockFileEx(handle, 0, ^uint32(0), ^uint32(0), &ol)
	_ = l.f.Close()
}
