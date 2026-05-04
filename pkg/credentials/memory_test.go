package credentials_test

import (
	"testing"

	"github.com/fastly/cli/pkg/credentials"
)

func TestMemoryStore(t *testing.T) {
	t.Parallel()
	runStoreSuite(t, "memory", func(_ *testing.T) credentials.Store {
		return credentials.NewMemoryStore()
	})
}
