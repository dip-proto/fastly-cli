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

// UseCommand switches the default token.
type UseCommand struct {
	argparser.Base
	name string
}

func NewUseCommand(parent argparser.Registerer, g *global.Data) *UseCommand {
	var c UseCommand
	c.Globals = g
	c.CmdClause = parent.Command("use", "Set the default stored token for CLI commands")
	// Required.
	c.CmdClause.Arg("name", "Name of the token to use as default").Required().StringVar(&c.name)
	return &c
}

func (c *UseCommand) Exec(_ io.Reader, out io.Writer) error {
	if err := c.Globals.Credentials.SetDefault(c.name); err != nil {
		if errors.Is(err, credentials.ErrNotFound) {
			return fmt.Errorf("token %q not found", c.name)
		}
		return err
	}
	text.Success(out, "Default token switched to %q", c.name)
	return nil
}
