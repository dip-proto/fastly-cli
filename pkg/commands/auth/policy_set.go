package auth

import (
	"fmt"
	"io"

	"github.com/fastly/cli/pkg/argparser"
	"github.com/fastly/cli/pkg/global"
	"github.com/fastly/cli/pkg/policy"
	"github.com/fastly/cli/pkg/text"
)

// PolicySetCommand sets the policy for a stored token.
type PolicySetCommand struct {
	argparser.Base
	name       string
	useDefault bool
	clear      bool
	allow      []string
}

// NewPolicySetCommand returns a new command registered in the parent.
func NewPolicySetCommand(parent argparser.Registerer, g *global.Data) *PolicySetCommand {
	var c PolicySetCommand
	c.Globals = g
	c.CmdClause = parent.Command("set", "Apply a policy to a stored token")
	c.CmdClause.Flag("name", "Name of the token").StringVar(&c.name)
	c.CmdClause.Flag("default", "Apply to the default token").BoolVar(&c.useDefault)
	c.CmdClause.Flag("policy", "Policy names to allow (run 'fastly auth policy list' to see valid policies)").HintOptions(policy.KnownPolicies()...).StringsVar(&c.allow)
	c.CmdClause.Flag("clear", "Remove all policies (unrestricted access)").BoolVar(&c.clear)
	return &c
}

// Exec implements the command interface.
func (c *PolicySetCommand) Exec(_ io.Reader, out io.Writer) error {
	if c.clear && len(c.allow) > 0 {
		return fmt.Errorf("--clear and --policy are mutually exclusive; use --clear to remove all policies, or --policy to set specific ones")
	}
	if !c.clear && len(c.allow) == 0 {
		return fmt.Errorf("either --policy or --clear is required")
	}

	if !c.clear {
		if err := policy.ValidatePolicy(c.allow); err != nil {
			return err
		}
	}

	name := c.name
	if c.useDefault || name == "" {
		name = c.Globals.Config.Auth.Default
	}
	if name == "" {
		return fmt.Errorf("no token specified and no default token set")
	}

	entry := c.Globals.Config.GetAuthToken(name)
	if entry == nil {
		return fmt.Errorf("token %q not found", name)
	}

	if c.clear {
		entry.Allow = []string{}
	} else {
		entry.Allow = c.allow
	}

	if err := c.Globals.Config.Write(c.Globals.ConfigPath); err != nil {
		return fmt.Errorf("error saving config: %w", err)
	}

	text.Success(out, "Policy for %q updated", name)
	return nil
}
