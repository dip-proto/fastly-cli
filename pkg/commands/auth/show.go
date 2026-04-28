package auth

import (
	"fmt"
	"io"
	"time"

	"github.com/fastly/cli/pkg/argparser"
	"github.com/fastly/cli/pkg/credentials"
	"github.com/fastly/cli/pkg/env"
	"github.com/fastly/cli/pkg/global"
	"github.com/fastly/cli/pkg/lookup"
	"github.com/fastly/cli/pkg/text"
)

// ShowCommand shows token details.
type ShowCommand struct {
	argparser.Base
	name   string
	reveal bool
}

func NewShowCommand(parent argparser.Registerer, g *global.Data) *ShowCommand {
	var c ShowCommand
	c.Globals = g
	c.CmdClause = parent.Command("show", "Show details for a stored token")
	// Optional.
	c.CmdClause.Arg("name", "Name of the token to show (defaults to the current token)").StringVar(&c.name)
	// Optional.
	c.CmdClause.Flag("reveal", "Show the full token value (use with care)").BoolVar(&c.reveal)
	return &c
}

func (c *ShowCommand) Exec(_ io.Reader, out io.Writer) error {
	if c.name == "" {
		_, src, err := c.Globals.Token()
		if err != nil {
			return fmt.Errorf("resolving credential: %w", err)
		}
		switch src {
		case lookup.SourceUndefined:
			return fmt.Errorf("no token configured; run `fastly auth login` or pass a token name")
		case lookup.SourceFlag, lookup.SourceEnvironment:
			return fmt.Errorf("current token is not stored (provided via --token or %s); use `fastly auth add` or `fastly auth show <name>`", env.APIToken)
		case lookup.SourceFile, lookup.SourceDefault, lookup.SourceAuth:
			name, err := c.Globals.AuthTokenName()
			if err != nil {
				return fmt.Errorf("resolving credential name: %w", err)
			}
			c.name = name
		}
	}

	stored, err := credentials.Lookup(c.Globals.Credentials, c.name)
	if err != nil {
		return fmt.Errorf("loading credential %q: %w", c.name, err)
	}
	if stored == nil {
		return fmt.Errorf("token %q not found", c.name)
	}

	defaultName, err := credentials.DefaultOrEmpty(c.Globals.Credentials)
	if err != nil {
		return fmt.Errorf("resolving default credential: %w", err)
	}
	isDefault := c.name == defaultName
	defaultStr := ""
	if isDefault {
		defaultStr = " (default)"
	}

	text.Output(out, "Name: %s%s\n", c.name, defaultStr)
	text.Output(out, "Type: %s\n", stored.Type)

	if stored.Email != "" {
		text.Output(out, "Email: %s\n", stored.Email)
	}
	if stored.AccountID != "" {
		text.Output(out, "Account ID: %s\n", stored.AccountID)
	}
	if stored.Label != "" {
		text.Output(out, "Label: %s\n", stored.Label)
	}
	if stored.APITokenName != "" {
		text.Output(out, "API token name: %s\n", stored.APITokenName)
	}
	if stored.APITokenScope != "" {
		text.Output(out, "API token scope: %s\n", stored.APITokenScope)
	}
	now := time.Now()
	md := stored.Metadata()
	status, expires, parseErr := GetExpirationStatus(md, now)
	if parseErr != nil && c.Globals.ErrLog != nil {
		c.Globals.ErrLog.Add(parseErr)
	}

	if stored.APITokenExpiresAt != "" {
		line := "API token expires at: " + stored.APITokenExpiresAt
		if summary := apiTokenExpirySummary(stored, expires, now); summary != "" {
			line += " (" + summary + ")"
		}
		text.Output(out, "%s\n", line)
	}
	if stored.APITokenID != "" {
		text.Output(out, "API token ID: %s\n", stored.APITokenID)
	}

	// For SSO tokens, show the session (refresh) expiry as the user-actionable deadline.
	if stored.Type == credentials.TypeSSO && stored.RefreshExpiresAt != "" && !stored.NeedsReauth {
		line := "SSO session expires at: " + stored.RefreshExpiresAt
		if summary := ExpirationSummary(status, expires, now); summary != "" {
			line += " (" + summary + ")"
		}
		text.Output(out, "%s\n", line)
	}

	if c.reveal {
		text.Output(out, "Token: %s\n", stored.Token)
	} else {
		if len(stored.Token) > 8 {
			text.Output(out, "Token: %s...%s\n", stored.Token[:4], stored.Token[len(stored.Token)-4:])
		} else {
			text.Output(out, "Token: ****\n")
		}
	}

	if stored.NeedsReauth {
		text.Warning(out, "This token needs re-authentication. %s\n", ExpirationRemediation(stored.Type))
	} else if status == StatusExpired {
		text.Warning(out, "This token has expired. %s\n", ExpirationRemediation(stored.Type))
	}

	return nil
}

// apiTokenExpirySummary returns a relative-time string for the APITokenExpiresAt
// field specifically. For static tokens this uses the main expiry status; for SSO
// tokens the APITokenExpiresAt is secondary so we parse it independently.
func apiTokenExpirySummary(t *credentials.Token, mainExpires time.Time, now time.Time) string {
	if t.Type == credentials.TypeStatic {
		// For static tokens, APITokenExpiresAt IS the effective expiry.
		if mainExpires.IsZero() {
			return ""
		}
		if now.After(mainExpires) {
			return "expired " + humanDuration(now.Sub(mainExpires)) + " ago"
		}
		return "in " + humanDuration(mainExpires.Sub(now))
	}

	// For SSO tokens, parse APITokenExpiresAt independently since the main
	// expiry status tracks RefreshExpiresAt.
	if t.APITokenExpiresAt == "" {
		return ""
	}
	apiExpires, err := time.Parse(time.RFC3339, t.APITokenExpiresAt)
	if err != nil {
		return ""
	}
	if now.After(apiExpires) {
		return "expired " + humanDuration(now.Sub(apiExpires)) + " ago"
	}
	return "in " + humanDuration(apiExpires.Sub(now))
}
