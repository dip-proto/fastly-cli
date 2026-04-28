package auth

import (
	"fmt"
	"io"

	"github.com/fastly/cli/pkg/argparser"
	"github.com/fastly/cli/pkg/credentials"
	fsterr "github.com/fastly/cli/pkg/errors"
	"github.com/fastly/cli/pkg/global"
	"github.com/fastly/cli/pkg/text"
)

// AddCommand adds a named token entry.
type AddCommand struct {
	argparser.Base
	name  string
	token string
}

func NewAddCommand(parent argparser.Registerer, g *global.Data) *AddCommand {
	var c AddCommand
	c.Globals = g
	c.CmdClause = parent.Command("add", "Store a named token")
	// Optional.
	c.CmdClause.Arg("name", "Name for this token (pass to --token to use it later); if omitted, uses the API token's name").StringVar(&c.name)
	// Required.
	c.CmdClause.Flag("api-token", "Fastly API token to store").Required().StringVar(&c.token)
	return &c
}

func (c *AddCommand) Exec(_ io.Reader, out io.Writer) error {
	if c.name != "" {
		existing, err := credentials.Lookup(c.Globals.Credentials, c.name)
		if err != nil {
			return fmt.Errorf("loading credential %q: %w", c.name, err)
		}
		if existing != nil {
			return fmt.Errorf("token %q already exists; use 'fastly auth delete %s' first", c.name, c.name)
		}
	}

	md, err := FetchTokenMetadataLenient(c.Globals, c.token)
	if err != nil {
		return err
	}

	name := c.name
	if name == "" {
		if md.APITokenName == "" {
			return fsterr.RemediationError{
				Inner:       fmt.Errorf("could not determine a name for this token"),
				Remediation: "Provide a name as the first argument, e.g.: fastly auth add my-token --api-token <token>",
			}
		}
		name = md.APITokenName
		existing, err := credentials.Lookup(c.Globals.Credentials, name)
		if err != nil {
			return fmt.Errorf("loading credential %q: %w", name, err)
		}
		if existing != nil {
			return fmt.Errorf("token %q already exists; use 'fastly auth delete %s' first", name, name)
		}
	}

	entry := &credentials.Token{
		Type:              credentials.TypeStatic,
		Token:             c.token,
		Email:             md.Email,
		AccountID:         md.AccountID,
		APITokenName:      md.APITokenName,
		APITokenScope:     md.APITokenScope,
		APITokenExpiresAt: md.APITokenExpiresAt,
		APITokenID:        md.APITokenID,
	}

	previousDefault, err := credentials.SetAndPromote(c.Globals.Credentials, name, entry)
	if err != nil {
		return fmt.Errorf("storing credential %q: %w", name, err)
	}
	setDefault := previousDefault == ""

	text.Success(out, "Token %q added", name)
	if setDefault {
		text.Info(out, "Token %q set as default (no previous default was configured)", name)
	}
	text.Info(out, "%s", credentials.SavedMessage(credentials.Backend(c.Globals.CredentialsBackend), c.Globals.CredentialsPath))
	return nil
}
