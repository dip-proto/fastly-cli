package commands_test

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/fastly/kingpin"

	"github.com/fastly/cli/pkg/commands"
	"github.com/fastly/cli/pkg/testutil"
)

func TestDefineDisableAuthCommand(t *testing.T) {
	newApp := func(stdout *bytes.Buffer) *kingpin.Application {
		app := kingpin.New("fastly", "test")
		app.Writers(stdout, io.Discard)
		app.Terminate(nil)
		return app
	}

	t.Run("auth commands present by default", func(t *testing.T) {
		var stdout bytes.Buffer
		data := testutil.MockGlobalData([]string{"fastly"}, &stdout)
		cmds := commands.Define(newApp(&stdout), data)

		found := false
		for _, cmd := range cmds {
			if cmd.Name() == "auth" {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected auth command to be present when FASTLY_DISABLE_AUTH_COMMAND is not set")
		}
	})

	t.Run("auth commands excluded when FASTLY_DISABLE_AUTH_COMMAND is set", func(t *testing.T) {
		t.Setenv("FASTLY_DISABLE_AUTH_COMMAND", "1")

		var stdout bytes.Buffer
		data := testutil.MockGlobalData([]string{"fastly"}, &stdout)
		cmds := commands.Define(newApp(&stdout), data)

		for _, cmd := range cmds {
			if cmd.Name() == "auth" || strings.HasPrefix(cmd.Name(), "auth ") {
				t.Errorf("expected no auth commands, but found %q", cmd.Name())
			}
		}

		// Non-auth commands still exist.
		found := false
		for _, cmd := range cmds {
			if cmd.Name() == "compute" {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected compute command to still be present")
		}
	})
}
