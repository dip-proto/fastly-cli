package auth

import (
	"fmt"
	"io"

	"github.com/fastly/go-fastly/v12/fastly"

	"github.com/fastly/cli/pkg/argparser"
	"github.com/fastly/cli/pkg/config"
	"github.com/fastly/cli/pkg/global"
	"github.com/fastly/cli/pkg/policy"
	"github.com/fastly/cli/pkg/text"
)

// AddCommand adds a named token entry.
type AddCommand struct {
	argparser.Base
	name  string
	token string
	allow []string
}

// NewAddCommand returns a new command registered in the parent.
func NewAddCommand(parent argparser.Registerer, g *global.Data) *AddCommand {
	var c AddCommand
	c.Globals = g
	c.CmdClause = parent.Command("add", "Store a named token (optionally with a policy)")
	c.CmdClause.Arg("name", "Name for this token (pass to --token to use it later); if omitted, uses the API token's name").StringVar(&c.name)
	c.CmdClause.Flag("api-token", "Fastly API token to store").Required().StringVar(&c.token)
	c.CmdClause.Flag("policy", "Policy to apply to this token (run 'fastly auth policy list' to see valid policies)").HintOptions(policy.KnownPolicies()...).StringsVar(&c.allow)
	return &c
}

// Exec implements the command interface.
func (c *AddCommand) Exec(_ io.Reader, out io.Writer) error {
	if len(c.allow) > 0 {
		if err := policy.ValidatePolicy(c.allow); err != nil {
			return fmt.Errorf("invalid --policy value: %w", err)
		}
	}

	// Short-circuit: if an explicit name was provided and already exists,
	// fail before making any network calls.
	if c.name != "" && c.Globals.Config.GetAuthToken(c.name) != nil {
		return fmt.Errorf("token %q already exists; use 'fastly auth delete %s' first", c.name, c.name)
	}

	md, err := FetchTokenMetadata(c.Globals, c.token)
	if err != nil {
		return err
	}

	name := c.name
	if name == "" {
		name = md.APITokenName
		if name == "" {
			return fmt.Errorf("could not determine a name for this token; pass NAME as an argument")
		}
		// Check collision for the derived name too.
		if c.Globals.Config.GetAuthToken(name) != nil {
			return fmt.Errorf("token %q already exists; use 'fastly auth delete %s' first", name, name)
		}
	}

	entry := &config.AuthToken{
		Type:              config.AuthTokenTypeStatic,
		Token:             c.token,
		Email:             md.Email,
		AccountID:         md.AccountID,
		Allow:             c.allow,
		APITokenName:      md.APITokenName,
		APITokenScope:     md.APITokenScope,
		APITokenExpiresAt: md.APITokenExpiresAt,
		APITokenID:        md.APITokenID,
	}

	if md.APITokenScope == string(fastly.GlobalReadScope) && len(entry.Allow) == 0 {
		entry.Allow = []string{"readonly"}
	}

	c.Globals.Config.SetAuthToken(name, entry)

	if c.Globals.Config.Auth.Default == "" {
		c.Globals.Config.Auth.Default = name
	}

	if err := c.Globals.Config.Write(c.Globals.ConfigPath); err != nil {
		return fmt.Errorf("error saving config: %w", err)
	}

	text.Success(out, "Token %q added", name)
	text.Info(out, "Token saved to %s", c.Globals.ConfigPath)
	return nil
}
