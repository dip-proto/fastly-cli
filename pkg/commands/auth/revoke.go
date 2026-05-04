package auth

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/fastly/go-fastly/v14/fastly"

	"github.com/fastly/cli/pkg/api"
	"github.com/fastly/cli/pkg/argparser"
	"github.com/fastly/cli/pkg/credentials"
	fsterr "github.com/fastly/cli/pkg/errors"
	"github.com/fastly/cli/pkg/global"
	"github.com/fastly/cli/pkg/text"
)

// errCancelled is returned when a user declines a confirmation prompt.
// It signals intentional cancellation, not a failure condition.
var errCancelled = errors.New("cancelled")

// RevokeCommand revokes a token via the API and removes it from local config.
type RevokeCommand struct {
	argparser.Base
	current    bool
	name       string
	tokenValue string
	id         string
	file       string
}

func NewRevokeCommand(parent argparser.Registerer, g *global.Data) *RevokeCommand {
	var c RevokeCommand
	c.Globals = g
	c.CmdClause = parent.Command("revoke", "Revoke a token via the API and remove it from local config")
	c.CmdClause.Flag("current", "Revoke the token used to authenticate the current request").BoolVar(&c.current)
	c.CmdClause.Flag("name", "Name of a locally stored token to revoke").StringVar(&c.name)
	c.CmdClause.Flag("token-value", "Raw API token string to revoke (pass '-' to read from stdin)").StringVar(&c.tokenValue)
	c.CmdClause.Flag("id", "Alphanumeric string identifying a token to revoke").StringVar(&c.id)
	c.CmdClause.Flag("file", "Path to a newline-delimited file of token IDs to revoke in bulk").StringVar(&c.file)
	return &c
}

func (c *RevokeCommand) Exec(in io.Reader, out io.Writer) error {
	if err := c.validateFlags(); err != nil {
		return err
	}

	switch {
	case c.current:
		return c.revokeCurrent(in, out)
	case c.name != "":
		return c.revokeByName(in, out)
	case c.tokenValue != "":
		return c.revokeByTokenValue(in, out)
	case c.id != "":
		return c.revokeByID(out)
	case c.file != "":
		return c.revokeByFile(out)
	}

	return nil
}

func (c *RevokeCommand) validateFlags() error {
	count := 0
	if c.current {
		count++
	}
	if c.name != "" {
		count++
	}
	if c.tokenValue != "" {
		count++
	}
	if c.id != "" {
		count++
	}
	if c.file != "" {
		count++
	}
	if count == 0 {
		return fmt.Errorf("error parsing arguments: must provide one of --current, --name, --token-value, --id, or --file")
	}
	if count > 1 {
		return fmt.Errorf("error parsing arguments: only one of --current, --name, --token-value, --id, or --file may be used")
	}
	return nil
}

func (c *RevokeCommand) revokeCurrent(in io.Reader, out io.Writer) error {
	tok, _ := c.Globals.Token()

	names, err := findLocalTokensByValue(c.Globals, tok)
	if err != nil {
		return err
	}
	if err := c.confirmDefaultRevocation(names, in, out); err != nil {
		if errors.Is(err, errCancelled) {
			return nil
		}
		return err
	}

	client, err := c.authClient()
	if err != nil {
		return err
	}

	err = client.DeleteTokenSelf(context.TODO())
	if err != nil {
		c.Globals.ErrLog.Add(err)
		return err
	}

	text.Success(out, "Revoked current token")
	return c.removeLocalTokens(names, out)
}

func (c *RevokeCommand) revokeByName(in io.Reader, out io.Writer) error {
	entry, err := credentials.Lookup(c.Globals.Credentials, c.name)
	if err != nil {
		return fmt.Errorf("loading credential %q: %w", c.name, err)
	}
	if entry == nil {
		return fmt.Errorf("token %q not found", c.name)
	}

	if err := c.confirmDefaultRevocation([]string{c.name}, in, out); err != nil {
		if errors.Is(err, errCancelled) {
			return nil
		}
		return err
	}

	client, err := c.buildClient(entry.Token)
	if err != nil {
		return err
	}

	err = client.DeleteTokenSelf(context.TODO())
	if err != nil {
		if isSelfAlreadyGone(err) {
			text.Warning(out, "Token was already revoked remotely\n")
		} else {
			c.Globals.ErrLog.Add(err)
			return err
		}
	} else {
		text.Success(out, "Revoked token %q", c.name)
	}

	names := []string{c.name}
	matches, err := findLocalTokensByValue(c.Globals, entry.Token)
	if err != nil {
		return err
	}
	for _, n := range matches {
		if n != c.name {
			names = append(names, n)
		}
	}
	return c.removeLocalTokens(names, out)
}

func (c *RevokeCommand) revokeByTokenValue(in io.Reader, out io.Writer) error {
	raw, err := readTokenValue(c.tokenValue, in)
	if err != nil {
		return err
	}

	names, err := findLocalTokensByValue(c.Globals, raw)
	if err != nil {
		return err
	}
	if err := c.confirmDefaultRevocation(names, in, out); err != nil {
		if errors.Is(err, errCancelled) {
			return nil
		}
		return err
	}

	client, err := c.buildClient(raw)
	if err != nil {
		return err
	}

	err = client.DeleteTokenSelf(context.TODO())
	if err != nil {
		if isSelfAlreadyGone(err) {
			text.Warning(out, "Token was already revoked remotely\n")
		} else {
			c.Globals.ErrLog.Add(err)
			return err
		}
	} else {
		text.Success(out, "Revoked token")
	}

	if len(names) == 0 {
		text.Info(out, "No matching local token entry found\n")
		return nil
	}
	return c.removeLocalTokens(names, out)
}

func (c *RevokeCommand) revokeByID(out io.Writer) error {
	client, err := c.authClient()
	if err != nil {
		return err
	}

	err = client.DeleteToken(context.TODO(), &fastly.DeleteTokenInput{
		TokenID: c.id,
	})
	if err != nil {
		if isAlreadyGone(err) {
			text.Warning(out, "Token was already revoked remotely\n")
		} else {
			c.Globals.ErrLog.Add(err)
			return err
		}
	} else {
		text.Success(out, "Revoked token '%s'", c.id)
	}
	names, err := findLocalTokensByID(c.Globals, c.id)
	if err != nil {
		return err
	}
	if len(names) == 0 {
		text.Info(out, "No local token entry with matching API token ID found; local cleanup skipped\n")
		return nil
	}
	return c.removeLocalTokens(names, out)
}

func (c *RevokeCommand) revokeByFile(out io.Writer) error {
	ids, err := readTokenIDFile(c.file)
	if err != nil {
		return err
	}

	client, err := c.authClient()
	if err != nil {
		return err
	}

	tokens := make([]*fastly.BatchToken, len(ids))
	for i, id := range ids {
		tokens[i] = &fastly.BatchToken{ID: id}
	}

	err = client.BatchDeleteTokens(context.TODO(), &fastly.BatchDeleteTokensInput{
		Tokens: tokens,
	})
	if err != nil {
		c.Globals.ErrLog.Add(err)
		return err
	}

	text.Success(out, "Revoked %d token(s)", len(ids))
	if c.Globals.Verbose() {
		tbl := text.NewTable(out)
		tbl.AddHeader("TOKEN ID")
		for _, id := range ids {
			tbl.AddLine(id)
		}
		tbl.Print()
	}

	var names []string
	for _, id := range ids {
		matches, err := findLocalTokensByID(c.Globals, id)
		if err != nil {
			return err
		}
		names = append(names, matches...)
	}
	if len(names) == 0 {
		text.Info(out, "No local token entries with matching API token IDs found; local cleanup skipped\n")
		return nil
	}
	return c.removeLocalTokens(names, out)
}

func (c *RevokeCommand) authClient() (api.Interface, error) {
	tok, _ := c.Globals.Token()
	if tok == "" {
		return nil, fsterr.RemediationError{
			Inner:       fmt.Errorf("no token available for authentication"),
			Remediation: fsterr.AuthRemediation(),
		}
	}
	return c.buildClient(tok)
}

func (c *RevokeCommand) buildClient(token string) (api.Interface, error) {
	endpoint, _ := c.Globals.APIEndpoint()
	client, err := c.Globals.APIClientFactory(token, endpoint, c.Globals.Flags.Debug)
	if err != nil {
		return nil, fsterr.RemediationError{
			Inner:       fmt.Errorf("error creating API client: %w", err),
			Remediation: "Check your network connection and API endpoint configuration.",
		}
	}
	return client, nil
}

func (c *RevokeCommand) confirmDefaultRevocation(names []string, in io.Reader, out io.Writer) error {
	def, err := credentials.DefaultOrEmpty(c.Globals.Credentials)
	if err != nil {
		return fmt.Errorf("resolving default credential: %w", err)
	}
	if def == "" {
		return nil
	}

	isDefault := false
	for _, n := range names {
		if n == def {
			isDefault = true
			break
		}
	}
	if !isDefault {
		return nil
	}

	if c.Globals.Flags.AutoYes || c.Globals.Flags.NonInteractive {
		return nil
	}

	text.Warning(out, "%q is your current default token. Revoking it will invalidate it remotely and remove it from local config.", def)
	cont, err := text.AskYesNo(out, "Are you sure? [y/N]: ", in)
	if err != nil {
		return err
	}
	if !cont {
		return errCancelled
	}
	return nil
}

func isAlreadyGone(err error) bool {
	var httpErr *fastly.HTTPError
	return errors.As(err, &httpErr) && httpErr.StatusCode == http.StatusNotFound
}

func isSelfAlreadyGone(err error) bool {
	var httpErr *fastly.HTTPError
	return isAlreadyGone(err) || (errors.As(err, &httpErr) && httpErr.StatusCode == http.StatusUnauthorized)
}

func readTokenValue(flag string, in io.Reader) (string, error) {
	if flag == "-" {
		const maxTokenSize = 4096
		b, err := io.ReadAll(io.LimitReader(in, maxTokenSize+1))
		if err != nil {
			return "", fsterr.RemediationError{
				Inner:       fmt.Errorf("failed to read token from stdin: %w", err),
				Remediation: "Pipe a token value, e.g.: echo $TOKEN | fastly auth revoke --token-value=-",
			}
		}
		if len(b) > maxTokenSize {
			return "", fsterr.RemediationError{
				Inner:       fmt.Errorf("stdin input exceeds %d bytes", maxTokenSize),
				Remediation: "Pipe a single token value, not a file. Example: echo $TOKEN | fastly auth revoke --token-value=-",
			}
		}
		val := strings.TrimSpace(string(b))
		if val == "" {
			return "", fsterr.RemediationError{
				Inner:       fmt.Errorf("no token provided on stdin"),
				Remediation: "Pipe a token value, e.g.: echo $TOKEN | fastly auth revoke --token-value=-",
			}
		}
		return val, nil
	}

	return flag, nil
}

func readTokenIDFile(path string) ([]string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fsterr.RemediationError{
			Inner:       fmt.Errorf("invalid file path %q: %w", path, err),
			Remediation: "Check the file path and try again.",
		}
	}

	f, err := os.Open(abs) // #nosec
	if err != nil {
		return nil, fsterr.RemediationError{
			Inner:       fmt.Errorf("failed to open %q: %w", abs, err),
			Remediation: "Check the file path and permissions, then try again.",
		}
	}
	defer f.Close() // #nosec

	var ids []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			ids = append(ids, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fsterr.RemediationError{
			Inner:       fmt.Errorf("error reading %q: %w", abs, err),
			Remediation: "Check the file for encoding issues or try recreating it.",
		}
	}
	if len(ids) == 0 {
		return nil, fsterr.RemediationError{
			Inner:       fmt.Errorf("file %q contains no token IDs", abs),
			Remediation: "The file should contain one token ID per line.",
		}
	}
	return ids, nil
}

// findLocalTokensByValue returns credential names whose Token equals
// raw. Calls Get() per name; the cost is fine for a rare operation.
func findLocalTokensByValue(g *global.Data, raw string) ([]string, error) {
	names, err := g.Credentials.Names()
	if err != nil {
		return nil, err
	}
	var matches []string
	for _, name := range names {
		entry, err := credentials.Lookup(g.Credentials, name)
		if err != nil {
			return nil, fmt.Errorf("loading credential %q: %w", name, err)
		}
		if entry != nil && entry.Token == raw {
			matches = append(matches, name)
		}
	}
	return matches, nil
}

// findLocalTokensByID returns credential names whose APITokenID
// metadata equals id. Reads metadata only.
func findLocalTokensByID(g *global.Data, id string) ([]string, error) {
	names, err := g.Credentials.Names()
	if err != nil {
		return nil, err
	}
	var matches []string
	for _, name := range names {
		md, err := credentials.LookupMetadata(g.Credentials, name)
		if err != nil {
			return nil, fmt.Errorf("loading metadata %q: %w", name, err)
		}
		if md != nil && md.APITokenID == id {
			matches = append(matches, name)
		}
	}
	return matches, nil
}

func (c *RevokeCommand) removeLocalTokens(names []string, out io.Writer) error {
	if len(names) == 0 {
		return nil
	}

	originalDefault, err := credentials.DefaultOrEmpty(c.Globals.Credentials)
	if err != nil {
		return fmt.Errorf("resolving default credential: %w", err)
	}
	removedDefault := false
	for _, name := range names {
		if name == originalDefault {
			removedDefault = true
		}
		if err := c.Globals.Credentials.Delete(name); err != nil {
			return fsterr.RemediationError{
				Inner:       fmt.Errorf("token(s) revoked remotely but failed to remove local entry %q: %w", name, err),
				Remediation: fmt.Sprintf("Check file permissions on %s. The local store may be stale; use 'fastly auth delete' to clean up manually.", c.Globals.CredentialsPath),
			}
		}
	}

	for _, name := range names {
		text.Info(out, "Removed local token entry %q\n", name)
	}

	if removedDefault {
		text.Warning(out, "No default token configured; use 'fastly auth use <name>' to set one\n")
	}
	return nil
}
