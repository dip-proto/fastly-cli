package auth

import (
	"fmt"
	"io"
	"strings"

	"github.com/fastly/cli/pkg/argparser"
	"github.com/fastly/cli/pkg/env"
	"github.com/fastly/cli/pkg/global"
	"github.com/fastly/cli/pkg/lookup"
	"github.com/fastly/cli/pkg/policy"
	"github.com/fastly/cli/pkg/text"
)

// PolicyShowCommand shows the policy for a stored token with a human-friendly explanation.
type PolicyShowCommand struct {
	argparser.Base
	name       string
	useDefault bool
}

// NewPolicyShowCommand returns a new command registered in the parent.
func NewPolicyShowCommand(parent argparser.Registerer, g *global.Data) *PolicyShowCommand {
	var c PolicyShowCommand
	c.Globals = g
	c.CmdClause = parent.Command("show", "Show the current policy for a stored token")
	c.CmdClause.Flag("name", "Name of the token").StringVar(&c.name)
	c.CmdClause.Flag("default", "Show policy for the default token").BoolVar(&c.useDefault)
	return &c
}

// Exec implements the command interface.
func (c *PolicyShowCommand) Exec(_ io.Reader, out io.Writer) error {
	if c.name != "" && c.useDefault {
		return fmt.Errorf("--name and --default are mutually exclusive")
	}

	name := c.name
	if c.useDefault || name == "" {
		// Resolve token the same way auth show does.
		if name == "" && !c.useDefault {
			_, src := c.Globals.Token()
			switch src {
			case lookup.SourceFlag, lookup.SourceEnvironment:
				return fmt.Errorf("current token is not stored (provided via --token or %s); policies only apply to stored tokens\n\nUse `fastly auth policy show --name <token>` to inspect a specific token", env.APIToken)
			case lookup.SourceUndefined:
				return fmt.Errorf("no token configured; run `fastly auth login` or pass a token name with --name")
			case lookup.SourceFile, lookup.SourceDefault, lookup.SourceAuth:
			}
			name = c.Globals.AuthTokenName()
		}
		if name == "" {
			name = c.Globals.Config.Auth.Default
		}
	}

	if name == "" {
		return fmt.Errorf("no token specified and no default token set")
	}

	entry := c.Globals.Config.GetAuthToken(name)
	if entry == nil {
		return fmt.Errorf("token %q not found", name)
	}

	isDefault := name == c.Globals.Config.Auth.Default
	defaultStr := ""
	if isDefault {
		defaultStr = " (default)"
	}

	text.Output(out, "Token: %s%s\n", name, defaultStr)

	if len(entry.Allow) > 0 {
		text.Output(out, "Policy: %s\n", strings.Join(entry.Allow, ", "))
	} else {
		text.Output(out, "Policy: unrestricted\n")
	}

	result := policy.Explain(entry.Allow)
	text.Output(out, "Summary: %s\n", result.Summary)
	text.Output(out, "Details: %s\n", strings.Join(result.Details, " "))

	if !env.AuthCommandDisabled() {
		text.Output(out, "\nTo change: `fastly auth policy set` | To list policies: `fastly auth policy list`\n")
	}

	return nil
}
