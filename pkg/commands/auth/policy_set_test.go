package auth_test

import (
	"testing"

	"github.com/fastly/cli/pkg/config"
	"github.com/fastly/cli/pkg/global"
	"github.com/fastly/cli/pkg/testutil"
	"github.com/fastly/cli/pkg/threadsafe"
)

func TestAuthPolicySet(t *testing.T) {
	baseConfig := func() *config.File {
		return &config.File{
			Auth: config.Auth{
				Default: "user",
				Tokens: config.AuthTokens{
					"user": &config.AuthToken{
						Type:  config.AuthTokenTypeStatic,
						Token: "test-token",
						Allow: []string{"readonly"},
					},
				},
			},
		}
	}

	scenarios := []testutil.CLIScenario{
		{
			Name:       "set policy replaces existing",
			Args:       "policy set --policy service:write",
			ConfigFile: baseConfig(),
			WantOutput: "Policy for \"user\" updated",
			Validator: func(t *testing.T, _ *testutil.CLIScenario, opts *global.Data, _ *threadsafe.Buffer) {
				t.Helper()
				entry := opts.Config.GetAuthToken("user")
				if entry == nil {
					t.Fatal("expected token entry")
				}
				if len(entry.Allow) != 1 || entry.Allow[0] != "service:write" {
					t.Fatalf("expected Allow=[service:write], got %v", entry.Allow)
				}
			},
		},
		{
			Name:       "clear policy",
			Args:       "policy set --clear",
			ConfigFile: baseConfig(),
			WantOutput: "Policy for \"user\" updated",
			Validator: func(t *testing.T, _ *testutil.CLIScenario, opts *global.Data, _ *threadsafe.Buffer) {
				t.Helper()
				entry := opts.Config.GetAuthToken("user")
				if entry == nil {
					t.Fatal("expected token entry")
				}
				if entry.Allow == nil {
					t.Fatal("expected Allow to be empty slice, got nil")
				}
				if len(entry.Allow) != 0 {
					t.Fatalf("expected Allow to be empty, got %v", entry.Allow)
				}
			},
		},
		{
			Name:       "clear is idempotent",
			Args:       "policy set --clear",
			ConfigFile: &config.File{
				Auth: config.Auth{
					Default: "user",
					Tokens: config.AuthTokens{
						"user": &config.AuthToken{
							Type:  config.AuthTokenTypeStatic,
							Token: "test-token",
							Allow: []string{},
						},
					},
				},
			},
			WantOutput: "Policy for \"user\" updated",
		},
		{
			Name:      "clear and policy mutually exclusive",
			Args:      "policy set --clear --policy readonly",
			WantError: "--clear and --policy are mutually exclusive",
		},
		{
			Name:      "neither clear nor policy",
			Args:      "policy set",
			WantError: "either --policy or --clear is required",
		},
		{
			Name:       "set policy by name",
			Args:       "policy set --name user --policy service:read",
			ConfigFile: baseConfig(),
			WantOutput: "Policy for \"user\" updated",
		},
		{
			Name:      "token not found",
			Args:      "policy set --name nonexistent --policy readonly",
			ConfigFile: baseConfig(),
			WantError: "token \"nonexistent\" not found",
		},
	}

	testutil.RunCLIScenarios(t, []string{"auth"}, scenarios)
}
