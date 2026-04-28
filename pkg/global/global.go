package global

import (
	"io"

	"github.com/fastly/cli/pkg/api"
	"github.com/fastly/cli/pkg/auth"
	"github.com/fastly/cli/pkg/config"
	"github.com/fastly/cli/pkg/credentials"
	fsterr "github.com/fastly/cli/pkg/errors"
	"github.com/fastly/cli/pkg/github"
	"github.com/fastly/cli/pkg/lookup"
	"github.com/fastly/cli/pkg/manifest"
)

// DefaultAPIEndpoint is the default Fastly API endpoint.
const DefaultAPIEndpoint = "https://api.fastly.com"

// DefaultAccountEndpoint is the default Fastly Accounts endpoint.
const DefaultAccountEndpoint = "https://accounts.fastly.com"

// APIClientFactory creates a Fastly API client (modeled as an api.Interface)
// from a user-provided API token. It exists as a type in order to parameterize
// the Run helper with it: in the real CLI, we can use NewClient from the Fastly
// API client library via RealClient; in tests, we can provide a mock API
// interface via MockClient.
type APIClientFactory func(token, apiEndpoint string, debugMode bool) (api.Interface, error)

// Versioners represents all supported versioner types.
type Versioners struct {
	CLI       github.AssetVersioner
	Viceroy   github.AssetVersioner
	WasmTools github.AssetVersioner
}

// Data holds global-ish configuration data from all sources: environment
// variables, config files, and flags. It has methods to give each parameter to
// the components that need it, including the place the parameter came from,
// which is a requirement.
//
// If the same parameter is defined in multiple places, it is resolved according
// to the following priority order: the config file (lowest priority), env vars,
// and then explicit flags (highest priority).
//
// This package and its types are only meant for parameters that are applicable
// to most/all subcommands (e.g. API token) and are consistent for a given user
// (e.g. an email address). Otherwise, parameters should be defined in specific
// command structs, and parsed as flags.
type Data struct {
	// APIClient is a Fastly API client instance.
	APIClient api.Interface
	// APIClientFactory is a factory function for creating an api.Interface type.
	APIClientFactory APIClientFactory
	// Args are the command line arguments provided by the user.
	Args []string
	// AuthServer is an instance of the authentication server type.
	// Used for interacting with Fastly's SSO/OAuth authentication provider.
	AuthServer auth.Runner
	// Config is an instance of the CLI configuration data.
	Config config.File
	// ConfigPath is the path to the CLI's application configuration.
	ConfigPath string
	// Credentials is the credential store. Token resolution assumes
	// it is non-nil.
	Credentials credentials.Store
	// CredentialsPath is the credentials.toml path for user-facing
	// messages. Empty for non-file backends.
	CredentialsPath string
	// Env is all the data that is provided by the environment.
	Env config.Environment
	// ErrLog provides an interface for recording errors to disk.
	ErrLog    fsterr.LogInterface
	ErrOutput io.Writer
	// ExecuteWasmTools is a function that executes the wasm-tools binary.
	ExecuteWasmTools func(bin string, args []string, global *Data) error
	// Flags are all the global CLI flags.
	Flags Flags
	// HTTPClient is a HTTP client.
	HTTPClient api.HTTPClient
	// Input is the standard input for accepting input from the user.
	Input io.Reader
	// Manifest represents the fastly.toml manifest file and associated flags.
	Manifest *manifest.Data
	// Opener is a function that can open a browser window.
	Opener func(string) error
	// Output is the output for displaying information (typically os.Stdout)
	Output io.Writer
	// RTSClient is a Fastly API client instance for the Real Time Stats endpoints.
	RTSClient api.RealtimeStatsInterface
	// SkipAuthPrompt is used to indicate to the `sso` command that the
	// interactive prompt can be skipped. This is for scenarios where the command
	// is executed directly by the user.
	SkipAuthPrompt bool
	// SSORunner runs the SSO authentication flow. It is set by commands.Define()
	// so that app/run.go can invoke SSO without a registered command.
	SSORunner func(in io.Reader, out io.Writer, forceReAuth bool, skipPrompt bool) error
	// Versioners contains multiple software versioning checkers.
	// e.g. Check for latest CLI or Viceroy version.
	Versioners Versioners
}

// Token yields the Fastly API token.
//
// Order of precedence:
//   - The --token flag (if it matches a stored credential name, use that token).
//   - The --token flag (treated as a raw API token).
//   - The FASTLY_API_TOKEN environment variable.
//   - The `profile` manifest field mapped to a credential name.
//   - The default credential (if configured).
//
// ErrNotFound silently falls through to the next source. ErrUnavailable
// and ErrCorrupt propagate so a locked or broken store never causes a
// credential name to be sent as a literal bearer token.
func (d *Data) Token() (string, lookup.Source, error) {
	// --token: check if it matches a stored auth token name first.
	if d.Flags.Token != "" {
		t, err := credentials.Lookup(d.Credentials, d.Flags.Token)
		if err != nil {
			return "", lookup.SourceUndefined, err
		}
		if t != nil && t.Token != "" {
			return t.Token, lookup.SourceAuth, nil
		}
		return d.Flags.Token, lookup.SourceFlag, nil
	}

	// FASTLY_API_TOKEN
	if d.Env.APIToken != "" {
		return d.Env.APIToken, lookup.SourceEnvironment, nil
	}

	if d.Manifest != nil && d.Manifest.File.Profile != "" {
		t, err := credentials.Lookup(d.Credentials, d.Manifest.File.Profile)
		if err != nil {
			return "", lookup.SourceUndefined, err
		}
		if t != nil && t.Token != "" {
			return t.Token, lookup.SourceAuth, nil
		}
	}

	name, err := credentials.DefaultOrEmpty(d.Credentials)
	if err != nil {
		return "", lookup.SourceUndefined, err
	}
	if name != "" {
		t, err := credentials.Lookup(d.Credentials, name)
		if err != nil {
			return "", lookup.SourceUndefined, err
		}
		if t != nil && t.Token != "" {
			return t.Token, lookup.SourceAuth, nil
		}
	}

	return "", lookup.SourceUndefined, nil
}

// AuthTokenName returns the name of the auth token being used, if any.
// This is used for display purposes and for SSO refresh of named tokens.
//
// Errors follow the Token policy: ErrNotFound becomes ("", nil);
// ErrUnavailable and ErrCorrupt propagate.
func (d *Data) AuthTokenName() (string, error) {
	if d.Flags.Token != "" {
		md, err := credentials.LookupMetadata(d.Credentials, d.Flags.Token)
		if err != nil {
			return "", err
		}
		if md != nil {
			return d.Flags.Token, nil
		}
		return "", nil
	}

	if d.Manifest != nil && d.Manifest.File.Profile != "" {
		md, err := credentials.LookupMetadata(d.Credentials, d.Manifest.File.Profile)
		if err != nil {
			return "", err
		}
		if md != nil {
			return d.Manifest.File.Profile, nil
		}
	}
	return credentials.DefaultOrEmpty(d.Credentials)
}

// Verbose yields the verbose flag, which can only be set via flags.
func (d *Data) Verbose() bool {
	return d.Flags.Verbose
}

// APIEndpoint yields the API endpoint.
func (d *Data) APIEndpoint() (string, lookup.Source) {
	if d.Flags.APIEndpoint != "" {
		return d.Flags.APIEndpoint, lookup.SourceFlag
	}

	if d.Env.APIEndpoint != "" {
		return d.Env.APIEndpoint, lookup.SourceEnvironment
	}

	if d.Config.Fastly.APIEndpoint != DefaultAPIEndpoint && d.Config.Fastly.APIEndpoint != "" {
		return d.Config.Fastly.APIEndpoint, lookup.SourceFile
	}

	return DefaultAPIEndpoint, lookup.SourceDefault // this method should not fail
}

// AccountEndpoint yields the Accounts endpoint.
func (d *Data) AccountEndpoint() (string, lookup.Source) {
	if d.Flags.AccountEndpoint != "" {
		return d.Flags.AccountEndpoint, lookup.SourceFlag
	}

	if d.Env.AccountEndpoint != "" {
		return d.Env.AccountEndpoint, lookup.SourceEnvironment
	}

	if d.Config.Fastly.AccountEndpoint != DefaultAccountEndpoint && d.Config.Fastly.AccountEndpoint != "" {
		return d.Config.Fastly.AccountEndpoint, lookup.SourceFile
	}

	return DefaultAccountEndpoint, lookup.SourceDefault // this method should not fail
}

// Flags represents all of the configuration parameters that can be set with
// explicit flags. Consumers should bind their flag values to these fields
// directly.
//
// IMPORTANT: Kingpin doesn't support global flags.
// We hack a solution in ../app/run.go (`configureKingpin` function).
type Flags struct {
	// AcceptDefaults auto-resolves prompts with a default defined.
	AcceptDefaults bool
	// AccountEndpoint is the authentication host address.
	AccountEndpoint string
	// APIEndpoint is the Fastly API address.
	APIEndpoint string
	// AutoYes auto-resolves Yes/No prompts by answering "Yes".
	AutoYes bool
	// Debug enables the CLI's debug mode.
	Debug bool
	// JSON indicates --json output was requested. Detected automatically by
	// Exec. Unlike Quiet, JSON mode does not suppress stderr warnings.
	JSON bool
	// NonInteractive auto-resolves all prompts.
	NonInteractive bool
	// Profile indicates the profile to use (consequently the 'token' used).
	Profile string
	// Quiet silences all output except direct command output.
	Quiet bool
	// SSO enables SSO authentication tokens for the current profile.
	SSO bool
	// Token is an override for a profile (when passed SSO is disabled).
	Token string
	// Verbose prints additional output.
	Verbose bool
}
