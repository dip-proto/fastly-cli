//go:build unix

package credentials

import "os"

// syncDir best-effort fsyncs the parent directory so a rename is durable
// across crashes. Errors are dropped; there is no caller-side recovery.
func syncDir(path string) {
	d, err := os.Open(path)
	if err != nil {
		return
	}
	_ = d.Sync()
	_ = d.Close()
}
