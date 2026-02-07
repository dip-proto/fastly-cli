package auth

import (
	"fmt"
	"io"

	"github.com/fastly/cli/pkg/argparser"
	"github.com/fastly/cli/pkg/global"
	"github.com/fastly/cli/pkg/policy"
)

// PolicyListCommand lists all known policy names.
type PolicyListCommand struct {
	argparser.Base
}

// NewPolicyListCommand returns a new command registered in the parent.
func NewPolicyListCommand(parent argparser.Registerer, g *global.Data) *PolicyListCommand {
	var c PolicyListCommand
	c.Globals = g
	c.CmdClause = parent.Command("list", "List available policy permissions for stored tokens")
	return &c
}

// Exec implements the command interface.
func (c *PolicyListCommand) Exec(_ io.Reader, out io.Writer) error {
	for _, name := range policy.KnownPolicies() {
		if name == "readonly" {
			fmt.Fprintf(out, "%-20s  Allow all read and local commands\n", name)
		} else {
			fmt.Fprintln(out, name)
		}
	}
	return nil
}
