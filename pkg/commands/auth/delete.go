package auth

import (
	"errors"
	"fmt"
	"io"

	"github.com/fastly/cli/pkg/argparser"
	"github.com/fastly/cli/pkg/credentials"
	"github.com/fastly/cli/pkg/global"
	"github.com/fastly/cli/pkg/text"
)

// DeleteCommand removes a stored token.
type DeleteCommand struct {
	argparser.Base
	name string
}

func NewDeleteCommand(parent argparser.Registerer, g *global.Data) *DeleteCommand {
	var c DeleteCommand
	c.Globals = g
	c.CmdClause = parent.Command("delete", "Delete a stored token")
	// Required.
	c.CmdClause.Arg("name", "Name of the token to remove").Required().StringVar(&c.name)
	return &c
}

func (c *DeleteCommand) Exec(in io.Reader, out io.Writer) error {
	existing, err := credentials.Lookup(c.Globals.Credentials, c.name)
	if err != nil {
		return fmt.Errorf("loading credential %q: %w", c.name, err)
	}
	if existing == nil {
		return fmt.Errorf("token %q not found", c.name)
	}

	defaultName, err := credentials.DefaultOrEmpty(c.Globals.Credentials)
	if err != nil {
		return fmt.Errorf("resolving default credential: %w", err)
	}
	wasDefault := defaultName == c.name

	if wasDefault && !c.Globals.Flags.AutoYes && !c.Globals.Flags.NonInteractive {
		text.Warning(out, "%q is your current default token. Deleting it will affect commands that don't use --token or FASTLY_API_TOKEN.", c.name)
		cont, err := text.AskYesNo(out, "Are you sure? [y/N]: ", in)
		if err != nil {
			return err
		}
		if !cont {
			return nil
		}
	}

	if err := c.Globals.Credentials.Delete(c.name); err != nil {
		if errors.Is(err, credentials.ErrNotFound) {
			return fmt.Errorf("token %q not found", c.name)
		}
		return err
	}

	text.Success(out, "Token %q removed", c.name)
	if wasDefault {
		text.Warning(out, "No default token configured; use 'fastly auth use <name>' to set one")
	}
	return nil
}
