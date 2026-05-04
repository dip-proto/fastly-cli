package profile

import (
	"errors"
	"fmt"
	"io"

	"github.com/fastly/cli/pkg/argparser"
	"github.com/fastly/cli/pkg/credentials"
	"github.com/fastly/cli/pkg/global"
	"github.com/fastly/cli/pkg/text"
)

// DeleteCommand represents a Kingpin command.
type DeleteCommand struct {
	argparser.Base

	profile string
}

// NewDeleteCommand returns a usable command registered under the parent.
func NewDeleteCommand(parent argparser.Registerer, g *global.Data) *DeleteCommand {
	var c DeleteCommand
	c.Globals = g
	c.CmdClause = parent.Command("delete", "Delete user profile (deprecated: use 'fastly auth delete' instead)")
	c.CmdClause.Arg("profile", "Profile to delete").Short('x').Required().StringVar(&c.profile)
	return &c
}

// Exec invokes the application logic for the command.
func (c *DeleteCommand) Exec(_ io.Reader, out io.Writer) error {
	if !c.Globals.Flags.Quiet {
		text.Deprecated(out, "This command will be removed in a future release. Use 'fastly auth delete' instead.\n\n")
	}

	if err := c.Globals.Credentials.Delete(c.profile); err != nil {
		if errors.Is(err, credentials.ErrNotFound) {
			return fmt.Errorf("the specified profile does not exist")
		}
		return err
	}

	if c.Globals.Verbose() {
		text.Break(out)
	}
	text.Success(out, "Profile '%s' deleted", c.profile)

	def, err := credentials.DefaultOrEmpty(c.Globals.Credentials)
	if err != nil {
		return fmt.Errorf("resolving default credential: %w", err)
	}
	names, _ := c.Globals.Credentials.Names()
	if def == "" && len(names) > 0 {
		text.Break(out)
		text.Warning(out, "No default profile configured. Run `fastly auth use <name>` to set one.")
	}
	return nil
}
