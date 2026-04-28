package auth

import (
	"fmt"
	"io"

	"github.com/fastly/cli/pkg/argparser"
	"github.com/fastly/cli/pkg/credentials"
	"github.com/fastly/cli/pkg/global"
	"github.com/fastly/cli/pkg/text"
)

// BackendCommand groups the `fastly auth backend` subcommands.
type BackendCommand struct {
	argparser.Base
}

// NewBackendCommand registers the `auth backend` parent command.
func NewBackendCommand(parent argparser.Registerer, g *global.Data) *BackendCommand {
	var c BackendCommand
	c.Globals = g
	c.CmdClause = parent.Command("backend", "Show or set which credentials backend the CLI uses (file or keychain)")
	return &c
}

// Exec is unreachable; subcommands handle execution.
func (c *BackendCommand) Exec(_ io.Reader, _ io.Writer) error {
	return fmt.Errorf("specify a subcommand: show, set")
}

// BackendShowCommand prints the active backend and selection.
type BackendShowCommand struct {
	argparser.Base
}

func NewBackendShowCommand(parent argparser.Registerer, g *global.Data) *BackendShowCommand {
	var c BackendShowCommand
	c.Globals = g
	c.CmdClause = parent.Command("show", "Show the active credentials backend and selection")
	return &c
}

func (c *BackendShowCommand) Exec(_ io.Reader, out io.Writer) error {
	active := c.Globals.CredentialsBackend
	if active == "" {
		active = string(credentials.BackendFile)
	}
	text.Output(out, "Active backend: %s\n", active)
	text.Output(out, "Credentials path: %s\n", c.Globals.CredentialsPath)

	stored, raw, err := credentials.ReadBackendSelection()
	if err != nil {
		return fmt.Errorf("reading backend selection file: %w", err)
	}
	switch {
	case stored == "":
		text.Output(out, "Selection file: not set (%s)\n", credentials.BackendSelectionPath)
	case stored == credentials.BackendAuto && raw != string(credentials.BackendAuto):
		text.Output(out, "Selection file: %s (contains %q which is not a recognised backend; falling through to default)\n", credentials.BackendSelectionPath, raw)
	default:
		text.Output(out, "Selection file: %s = %s\n", credentials.BackendSelectionPath, stored)
	}
	return nil
}

// BackendSetCommand writes the selection file. Changes take effect on
// the next CLI invocation; the running process is not re-opened.
type BackendSetCommand struct {
	argparser.Base
	backend string
}

func NewBackendSetCommand(parent argparser.Registerer, g *global.Data) *BackendSetCommand {
	var c BackendSetCommand
	c.Globals = g
	c.CmdClause = parent.Command("set", "Choose which credentials backend the CLI uses")
	c.CmdClause.Arg("backend", "One of: file, keychain, auto").Required().StringVar(&c.backend)
	return &c
}

func (c *BackendSetCommand) Exec(_ io.Reader, out io.Writer) error {
	b, ok := backendFromString(c.backend)
	if !ok {
		return fmt.Errorf("unknown backend %q (expected one of: file, keychain, auto)", c.backend)
	}
	if err := credentials.WriteBackendSelection(b); err != nil {
		return fmt.Errorf("writing backend selection: %w", err)
	}
	text.Success(out, "Backend selection set to %q.", b)
	if b == credentials.BackendKeychain {
		text.Info(out, "The keychain currently has whatever credentials it had before this command. Run `fastly auth migrate --to keychain` to copy from the file backend, or `fastly auth login` to authenticate fresh.")
	}
	if b == credentials.BackendAuto {
		text.Info(out, "Backend will be resolved automatically at startup based on env, sidecar, and CI heuristics.")
	}
	return nil
}
