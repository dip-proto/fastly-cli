package auth

import (
	"errors"
	"fmt"
	"io"

	"github.com/fastly/cli/pkg/argparser"
	"github.com/fastly/cli/pkg/credentials"
	"github.com/fastly/cli/pkg/global"
	"github.com/fastly/cli/pkg/text"
)

// MigrateCommand copies every credential from one backend to another.
// By default the source is left intact so a botched cutover does not
// strand the user; --purge-source is a separate invocation, run after
// the destination is verified active. Migration is symmetric: the
// same command serves both directions.
type MigrateCommand struct {
	argparser.Base
	to          string
	from        string
	purgeSource bool
}

// NewMigrateCommand returns a registered MigrateCommand.
func NewMigrateCommand(parent argparser.Registerer, g *global.Data) *MigrateCommand {
	var c MigrateCommand
	c.Globals = g
	c.CmdClause = parent.Command("migrate", "Copy credentials between backends (file <-> keychain)")
	c.CmdClause.Flag("to", "Destination backend (file or keychain)").StringVar(&c.to)
	c.CmdClause.Flag("from", "Source backend (defaults to the active backend)").StringVar(&c.from)
	c.CmdClause.Flag("purge-source", "After verifying the destination is active, delete every credential from the source backend").BoolVar(&c.purgeSource)
	return &c
}

func (c *MigrateCommand) Exec(in io.Reader, out io.Writer) error {
	active := credentials.Backend(c.Globals.CredentialsBackend)
	if active == "" {
		active = credentials.BackendFile
	}

	if c.purgeSource {
		return c.execPurge(in, out, active)
	}

	if c.to == "" {
		return fmt.Errorf("error parsing arguments: --to is required (file or keychain)")
	}
	to, ok := backendFromString(c.to)
	if !ok || to == credentials.BackendAuto {
		return fmt.Errorf("error parsing arguments: --to must be 'file' or 'keychain'")
	}

	from := active
	if c.from != "" {
		f, ok := backendFromString(c.from)
		if !ok || f == credentials.BackendAuto {
			return fmt.Errorf("error parsing arguments: --from must be 'file' or 'keychain'")
		}
		from = f
	}
	if from == to {
		return fmt.Errorf("error parsing arguments: --from and --to are the same backend (%s)", to)
	}

	source, sourcePath, err := credentials.Open(from)
	if err != nil {
		return fmt.Errorf("opening source backend %q: %w", from, err)
	}
	dest, _, err := credentials.Open(to)
	if err != nil {
		return fmt.Errorf("opening destination backend %q: %w", to, err)
	}

	names, err := source.Names()
	if err != nil {
		return fmt.Errorf("listing source credentials: %w", err)
	}
	if len(names) == 0 {
		text.Info(out, "Source backend %q is empty; nothing to migrate.", from)
		return nil
	}

	defaultName, err := credentials.DefaultOrEmpty(source)
	if err != nil {
		return fmt.Errorf("resolving source default: %w", err)
	}

	copied := 0
	for _, name := range names {
		t, err := source.Get(name)
		if err != nil {
			return fmt.Errorf("reading credential %q from source: %w", name, err)
		}
		if err := dest.Set(name, t); err != nil {
			return fmt.Errorf("writing credential %q to destination: %w", name, err)
		}
		copied++
	}
	if defaultName != "" {
		if err := dest.SetDefault(defaultName); err != nil {
			return fmt.Errorf("setting default %q on destination: %w", defaultName, err)
		}
	}

	text.Success(out, "Copied %d credential(s) from %s to %s.", copied, from, to)
	text.Info(out, "Source backend left intact at %s.", sourcePath)
	text.Info(out, "Run `fastly auth backend set %s` to make the destination active.", to)
	text.Info(out, "After verifying the destination is active, run `fastly auth migrate --purge-source` to remove the old data.")
	return nil
}

func (c *MigrateCommand) execPurge(in io.Reader, out io.Writer, active credentials.Backend) error {
	if c.from == "" {
		return fmt.Errorf("error parsing arguments: --purge-source requires --from")
	}
	from, ok := backendFromString(c.from)
	if !ok || from == credentials.BackendAuto {
		return fmt.Errorf("error parsing arguments: --from must be 'file' or 'keychain'")
	}
	if active == from {
		return fmt.Errorf("refusing to purge %q because it is the active backend; run `fastly auth backend set` first", from)
	}

	source, sourcePath, err := credentials.Open(from)
	if err != nil {
		return fmt.Errorf("opening source backend %q: %w", from, err)
	}

	names, err := source.Names()
	if err != nil {
		return fmt.Errorf("listing source credentials: %w", err)
	}
	if len(names) == 0 {
		text.Info(out, "Source backend %q is already empty.", from)
		return nil
	}

	text.Warning(out, "About to delete %d credential(s) from %s (%s).", len(names), from, sourcePath)
	if from == credentials.BackendKeychain {
		text.Output(out, "If you flip the backend back to file later, those refresh tokens are gone; the keychain version is the only copy.\n")
	}
	if !c.Globals.Flags.AutoYes && !c.Globals.Flags.NonInteractive {
		cont, err := text.AskYesNo(out, text.BoldYellow("Are you sure? [y/N]: "), in)
		if err != nil {
			return err
		}
		if !cont {
			return nil
		}
	}

	deleted := 0
	for _, name := range names {
		if err := source.Delete(name); err != nil {
			if errors.Is(err, credentials.ErrNotFound) {
				continue
			}
			return fmt.Errorf("deleting credential %q from source: %w", name, err)
		}
		deleted++
	}
	text.Success(out, "Deleted %d credential(s) from %s.", deleted, from)
	return nil
}

func backendFromString(s string) (credentials.Backend, bool) {
	switch s {
	case "file":
		return credentials.BackendFile, true
	case "keychain":
		return credentials.BackendKeychain, true
	case "auto":
		return credentials.BackendAuto, true
	}
	return "", false
}
