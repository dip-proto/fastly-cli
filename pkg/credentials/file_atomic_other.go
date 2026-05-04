//go:build !unix

package credentials

// syncDir is a no-op on platforms that do not allow fsync on a
// directory handle. The rename itself is still atomic.
func syncDir(path string) {}
