package profile

import (
	"errors"
	"fmt"
	"io"

	"github.com/fastly/cli/pkg/argparser"
	authcmd "github.com/fastly/cli/pkg/commands/auth"
	"github.com/fastly/cli/pkg/credentials"
	fsterr "github.com/fastly/cli/pkg/errors"
	"github.com/fastly/cli/pkg/global"
	"github.com/fastly/cli/pkg/text"
)

// SwitchCommand represents a Kingpin command.
type SwitchCommand struct {
	argparser.Base

	profile string
}

// NewSwitchCommand returns a usable command registered under the parent.
func NewSwitchCommand(parent argparser.Registerer, g *global.Data) *SwitchCommand {
	var c SwitchCommand
	c.Globals = g
	c.CmdClause = parent.Command("switch", "Switch user profile (deprecated: use 'fastly auth use' instead)")
	c.CmdClause.Arg("profile", "Profile to switch to").Short('p').Required().StringVar(&c.profile)
	return &c
}

// Exec invokes the application logic for the command.
func (c *SwitchCommand) Exec(in io.Reader, out io.Writer) error {
	if !c.Globals.Flags.Quiet {
		text.Deprecated(out, "This command will be removed in a future release. Use 'fastly auth use' instead.\n\n")
	}

	at, err := credentials.Lookup(c.Globals.Credentials, c.profile)
	if err != nil {
		return fmt.Errorf("loading credential %q: %w", c.profile, err)
	}
	if at == nil {
		err := fmt.Errorf("the profile '%s' does not exist", c.profile)
		c.Globals.ErrLog.Add(err)
		return fsterr.RemediationError{
			Inner:       err,
			Remediation: fsterr.ProfileRemediation(),
		}
	}

	if at.Type == credentials.TypeSSO {
		if err := authcmd.RunSSOWithTokenName(in, out, c.Globals, false, false, c.profile); err != nil {
			return fmt.Errorf("failed to authenticate: %w", err)
		}
		if err := c.Globals.Credentials.SetDefault(c.profile); err != nil {
			return err
		}
		text.Success(out, "\nProfile switched to '%s'", c.profile)
		return nil
	}

	if err := c.Globals.Credentials.SetDefault(c.profile); err != nil {
		c.Globals.ErrLog.Add(err)
		if errors.Is(err, credentials.ErrNotFound) {
			return fsterr.RemediationError{
				Inner:       fmt.Errorf("the profile '%s' does not exist", c.profile),
				Remediation: fsterr.ProfileRemediation(),
			}
		}
		return fsterr.RemediationError{
			Inner:       err,
			Remediation: fsterr.ProfileRemediation(),
		}
	}

	if c.Globals.Verbose() {
		text.Break(out)
	}
	text.Success(out, "Profile switched to '%s'", c.profile)
	return nil
}
