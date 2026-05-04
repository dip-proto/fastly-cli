package app

import (
	"bytes"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/fastly/cli/pkg/config"
	"github.com/fastly/cli/pkg/credentials"
	fsterr "github.com/fastly/cli/pkg/errors"
	"github.com/fastly/cli/pkg/global"
	"github.com/fastly/cli/pkg/manifest"
)

func staticToken(apiTokenExpiresAt string) credentials.Store {
	const name = "mytoken"
	s := credentials.NewMemoryStore()
	_ = s.Set(name, &credentials.Token{
		Type:              credentials.TypeStatic,
		Token:             "tok_abc123",
		APITokenExpiresAt: apiTokenExpiresAt,
	})
	_ = s.SetDefault(name)
	return s
}

func ssoToken(refreshExpiresAt string) credentials.Store {
	const name = "sso-tok"
	s := credentials.NewMemoryStore()
	_ = s.Set(name, &credentials.Token{
		Type:             credentials.TypeSSO,
		Token:            "tok_sso",
		RefreshExpiresAt: refreshExpiresAt,
	})
	_ = s.SetDefault(name)
	return s
}

func expiringTokenData(out *bytes.Buffer) *global.Data {
	soon := time.Now().Add(20 * time.Minute).Format(time.RFC3339)
	return &global.Data{
		Output:      out,
		ErrOutput:   out,
		ErrLog:      fsterr.Log,
		Manifest:    &manifest.Data{},
		Credentials: staticToken(soon),
	}
}

func TestCheckTokenExpirationWarning(t *testing.T) {
	soon := time.Now().Add(20 * time.Minute).Format(time.RFC3339)
	farFuture := time.Now().Add(60 * 24 * time.Hour).Format(time.RFC3339)

	tests := []struct {
		name        string
		commandName string
		data        func(out *bytes.Buffer) *global.Data
		wantWarn    bool
		wantSubstr  string
	}{
		{
			name:        "SourceAuth expiring soon shows warning",
			commandName: "service list",
			data: func(out *bytes.Buffer) *global.Data {
				return &global.Data{
					Output:      out,
					ErrOutput:   out,
					ErrLog:      fsterr.Log,
					Credentials: staticToken(soon),
				}
			},
			wantWarn:   true,
			wantSubstr: "expires in",
		},
		{
			name:        "SourceAuth not expiring soon no warning",
			commandName: "service list",
			data: func(out *bytes.Buffer) *global.Data {
				return &global.Data{
					Output:      out,
					ErrOutput:   out,
					ErrLog:      fsterr.Log,
					Credentials: staticToken(farFuture),
				}
			},
			wantWarn: false,
		},
		{
			name:        "SourceEnvironment JWT-like token no warning",
			commandName: "service list",
			data: func(out *bytes.Buffer) *global.Data {
				return &global.Data{
					Output:      out,
					ErrOutput:   out,
					ErrLog:      fsterr.Log,
					Env:         config.Environment{APIToken: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.fake"},
					Credentials: staticToken(soon),
				}
			},
			wantWarn: false,
		},
		{
			name:        "SourceFlag raw token no warning",
			commandName: "service list",
			data: func(out *bytes.Buffer) *global.Data {
				return &global.Data{
					Output:      out,
					ErrOutput:   out,
					ErrLog:      fsterr.Log,
					Flags:       global.Flags{Token: "some-raw-token"},
					Credentials: staticToken(soon),
				}
			},
			wantWarn: false,
		},
		{
			name:        "stale default name nil token no panic",
			commandName: "service list",
			data: func(out *bytes.Buffer) *global.Data {
				return &global.Data{
					Output:      out,
					ErrOutput:   out,
					ErrLog:      fsterr.Log,
					Credentials: credentials.NewMemoryStore(),
				}
			},
			wantWarn: false,
		},
		{
			name:        "malformed expiry logs error no visible warning",
			commandName: "service list",
			data: func(out *bytes.Buffer) *global.Data {
				return &global.Data{
					Output:      out,
					ErrOutput:   out,
					ErrLog:      fsterr.Log,
					Credentials: staticToken("not-a-date"),
				}
			},
			wantWarn: false,
		},
		{
			name:        "nil ErrLog does not panic",
			commandName: "service list",
			data: func(out *bytes.Buffer) *global.Data {
				return &global.Data{
					Output:      out,
					ErrOutput:   out,
					Credentials: staticToken("not-a-date"),
				}
			},
			wantWarn: false,
		},
		{
			name:        "SSO token expiring soon shows remediation",
			commandName: "service list",
			data: func(out *bytes.Buffer) *global.Data {
				return &global.Data{
					Output:      out,
					ErrOutput:   out,
					ErrLog:      fsterr.Log,
					Credentials: ssoToken(soon),
				}
			},
			wantWarn:   true,
			wantSubstr: "fastly auth login --sso",
		},
	}

	originalEnv := os.Getenv("FASTLY_DISABLE_AUTH_COMMAND")
	os.Setenv("FASTLY_DISABLE_AUTH_COMMAND", "")
	defer os.Setenv("FASTLY_DISABLE_AUTH_COMMAND", originalEnv)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			data := tt.data(&buf)
			if data.Manifest == nil {
				data.Manifest = &manifest.Data{}
			}
			checkTokenExpirationWarning(data, tt.commandName)
			output := buf.String()
			if tt.wantWarn && output == "" {
				t.Error("expected warning output but got none")
			}
			if !tt.wantWarn && output != "" {
				t.Errorf("expected no warning but got: %s", output)
			}
			if tt.wantSubstr != "" && !strings.Contains(output, tt.wantSubstr) {
				t.Errorf("expected output to contain %q, got: %s", tt.wantSubstr, output)
			}
		})
	}
}

func TestCheckTokenExpirationWarningDisabledAuth(t *testing.T) {
	originalEnv := os.Getenv("FASTLY_DISABLE_AUTH_COMMAND")
	os.Setenv("FASTLY_DISABLE_AUTH_COMMAND", "1")
	defer os.Setenv("FASTLY_DISABLE_AUTH_COMMAND", originalEnv)

	var buf bytes.Buffer
	data := expiringTokenData(&buf)

	checkTokenExpirationWarning(data, "service list")

	output := buf.String()
	if !strings.Contains(output, "FASTLY_API_TOKEN") {
		t.Errorf("expected FASTLY_API_TOKEN remediation in disabled-auth mode, got: %s", output)
	}
	if strings.Contains(output, "fastly auth") {
		t.Errorf("should not mention fastly auth in disabled mode, got: %s", output)
	}
}

func TestCheckTokenExpirationWarningSuppression(t *testing.T) {
	tests := []struct {
		name        string
		commandName string
		flags       global.Flags
	}{
		{name: "suppressed for auth list", commandName: "auth list"},
		{name: "suppressed for auth show", commandName: "auth show"},
		{name: "suppressed for auth login", commandName: "auth login"},
		{name: "suppressed for bare auth", commandName: "auth"},
		{name: "suppressed for sso", commandName: "sso"},
		{name: "suppressed for auth-token create", commandName: "auth-token create"},
		{name: "suppressed for bare auth-token", commandName: "auth-token"},
		{name: "suppressed for profile switch", commandName: "profile switch"},
		{name: "suppressed for bare profile", commandName: "profile"},
		{name: "suppressed for whoami", commandName: "whoami"},
		{name: "suppressed with --quiet flag", commandName: "service list", flags: global.Flags{Quiet: true}},
	}

	originalEnv := os.Getenv("FASTLY_DISABLE_AUTH_COMMAND")
	os.Setenv("FASTLY_DISABLE_AUTH_COMMAND", "")
	defer os.Setenv("FASTLY_DISABLE_AUTH_COMMAND", originalEnv)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			data := expiringTokenData(&buf)
			data.Flags = tt.flags
			checkTokenExpirationWarning(data, tt.commandName)
			output := buf.String()
			if output != "" {
				t.Errorf("expected no output for %q with flags %+v, got: %s", tt.commandName, tt.flags, output)
			}
		})
	}
}

func TestCheckTokenExpirationWarningShownForJSON(t *testing.T) {
	var buf bytes.Buffer
	data := expiringTokenData(&buf)
	data.Flags = global.Flags{JSON: true}
	checkTokenExpirationWarning(data, "service list")
	output := buf.String()
	if !strings.Contains(output, "expires in") {
		t.Errorf("expected expiry warning in --json mode (written to stderr), got: %s", output)
	}
}

func TestCheckTokenExpirationWarningNotSuppressedForNonAuth(t *testing.T) {
	originalEnv := os.Getenv("FASTLY_DISABLE_AUTH_COMMAND")
	os.Setenv("FASTLY_DISABLE_AUTH_COMMAND", "")
	defer os.Setenv("FASTLY_DISABLE_AUTH_COMMAND", originalEnv)
	var buf bytes.Buffer
	data := expiringTokenData(&buf)
	checkTokenExpirationWarning(data, "authtoken list")
	output := buf.String()
	if output == "" {
		t.Error("expected warning for non-auth command 'authtoken list' but got none")
	}
}
