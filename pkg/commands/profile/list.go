package profile

import (
	"errors"
	"fmt"
	"io"

	"github.com/fastly/cli/pkg/argparser"
	"github.com/fastly/cli/pkg/credentials"
	fsterr "github.com/fastly/cli/pkg/errors"
	"github.com/fastly/cli/pkg/global"
	"github.com/fastly/cli/pkg/text"
)

// ListCommand represents a Kingpin command.
type ListCommand struct {
	argparser.Base
	argparser.JSONOutput
}

// NewListCommand returns a usable command registered under the parent.
func NewListCommand(parent argparser.Registerer, g *global.Data) *ListCommand {
	var c ListCommand
	c.Globals = g
	c.CmdClause = parent.Command("list", "List user profiles (deprecated: use 'fastly auth list' instead)")
	c.RegisterFlagBool(c.JSONFlag()) // --json
	return &c
}

// Exec invokes the application logic for the command.
func (c *ListCommand) Exec(_ io.Reader, out io.Writer) error {
	if !c.Globals.Flags.Quiet && !c.JSONOutput.Enabled {
		text.Deprecated(out, "This command will be removed in a future release. Use 'fastly auth list' instead.\n\n")
	}

	if c.Globals.Verbose() && c.JSONOutput.Enabled {
		return fsterr.ErrInvalidVerboseJSONCombo
	}

	tokens, err := credentials.AllMetadata(c.Globals.Credentials)
	if err != nil {
		return fmt.Errorf("listing credentials: %w", err)
	}

	if ok, err := c.WriteJSON(out, tokens); ok {
		return err
	}

	if len(tokens) == 0 {
		msg := "no profiles available"
		return fsterr.RemediationError{
			Inner:       errors.New(msg),
			Remediation: fsterr.ProfileRemediation(),
		}
	}

	defaultName, err := credentials.DefaultOrEmpty(c.Globals.Credentials)
	if err != nil {
		return fmt.Errorf("resolving default credential: %w", err)
	}

	if defaultName != "" {
		if md := tokens[defaultName]; md != nil {
			if c.Globals.Verbose() {
				text.Break(out)
			}
			text.Info(out, "Default profile highlighted in red.\n\n")
			display(defaultName, md, true, out, text.BoldRed)
		}
	}

	for name, md := range tokens {
		if name != defaultName {
			text.Break(out)
			display(name, md, false, out, text.Bold)
		}
	}
	return nil
}

func display(name string, md *credentials.Metadata, isDefault bool, out io.Writer, style func(a ...any) string) {
	text.Output(out, style(name))
	text.Break(out)
	text.Output(out, "%s: %t", style("Default"), isDefault)
	text.Output(out, "%s: %s", style("Email"), md.Email)
	isSSO := md.Type == credentials.TypeSSO
	text.Output(out, "%s: %t", style("SSO"), isSSO)
	if isSSO {
		text.Output(out, "%s: %s", style("Account ID"), md.AccountID)
		text.Output(out, "%s: %s", style("Label"), md.Label)
	}
}
