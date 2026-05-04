package sso

import (
	"fmt"
	"io"

	"github.com/fastly/cli/pkg/argparser"
	authcmd "github.com/fastly/cli/pkg/commands/auth"
	"github.com/fastly/cli/pkg/credentials"
	fsterr "github.com/fastly/cli/pkg/errors"
	"github.com/fastly/cli/pkg/global"
	"github.com/fastly/cli/pkg/text"
)

// ForceReAuth indicates we want to force a re-auth of the user's session.
// This variable is overridden by ../../app/run.go to force a re-auth.
var ForceReAuth = false

// RootCommand is the parent command for all subcommands in this package.
// It should be installed under the primary root command.
type RootCommand struct {
	argparser.Base
	profile string
}

// CommandName is the string to be used to invoke this command.
const CommandName = "sso"

// NewRootCommand returns a new command registered in the parent.
func NewRootCommand(parent argparser.Registerer, g *global.Data) *RootCommand {
	var c RootCommand
	c.Globals = g
	c.CmdClause = parent.Command(CommandName, "Single Sign-On authentication (deprecated: use 'fastly auth login --sso --token <name>' instead)").Hidden()
	c.CmdClause.Arg("profile", "Profile to authenticate (i.e. create/update a token for)").Short('p').StringVar(&c.profile)
	return &c
}

// Exec implements the command interface.
func (c *RootCommand) Exec(in io.Reader, out io.Writer) error {
	if !c.Globals.Flags.Quiet {
		text.Deprecated(out, "This command will be removed in a future release. Use 'fastly auth login --sso --token <name>' instead.\n\n")
	}

	tokenName, isFallback, err := c.resolveTokenName()
	if err != nil {
		return err
	}

	if !isFallback {
		existing, err := credentials.Lookup(c.Globals.Credentials, tokenName)
		if err != nil {
			return fmt.Errorf("loading credential %q: %w", tokenName, err)
		}
		if existing == nil {
			return fsterr.RemediationError{
				Inner:       fmt.Errorf("token %q does not exist", tokenName),
				Remediation: "Run 'fastly auth login --sso --token <name>' to create a new SSO token, or 'fastly auth add' to store an existing token.",
			}
		}
	}

	if err := authcmd.RunSSOWithTokenName(in, out, c.Globals, ForceReAuth, false, tokenName); err != nil {
		return err
	}
	return c.Globals.Credentials.SetDefault(tokenName)
}

func (c *RootCommand) resolveTokenName() (string, bool, error) {
	if c.Globals.Flags.Profile != "" {
		return c.Globals.Flags.Profile, false, nil
	}
	if c.Globals.Manifest != nil && c.Globals.Manifest.File.Profile != "" {
		return c.Globals.Manifest.File.Profile, false, nil
	}
	if c.profile != "" {
		return c.profile, false, nil
	}
	name, err := credentials.DefaultOrEmpty(c.Globals.Credentials)
	if err != nil {
		return "", false, fmt.Errorf("resolving default credential: %w", err)
	}
	if name == "" {
		return "default", true, nil
	}
	return name, false, nil
}
