package auth_test

import (
	"testing"

	"github.com/fastly/cli/pkg/config"
	"github.com/fastly/cli/pkg/testutil"
)

func TestAuthPolicyShow(t *testing.T) {
	scenarios := []testutil.CLIScenario{
		{
			Name: "unrestricted (empty allow)",
			Args: "policy show",
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
			WantOutputs: []string{
				"Token: user (default)",
				"Policy: unrestricted",
				"This token can run any command",
			},
		},
		{
			Name: "unrestricted (nil allow)",
			Args: "policy show --name user",
			ConfigFile: &config.File{
				Auth: config.Auth{
					Default: "user",
					Tokens: config.AuthTokens{
						"user": &config.AuthToken{
							Type:  config.AuthTokenTypeStatic,
							Token: "test-token",
							Allow: nil,
						},
					},
				},
			},
			WantOutputs: []string{
				"Policy: unrestricted",
				"any command",
			},
		},
		{
			Name: "readonly policy",
			Args: "policy show",
			ConfigFile: &config.File{
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
			},
			WantOutputs: []string{
				"Token: user (default)",
				"Policy: readonly",
				"Read-only across all groups",
			},
		},
		{
			Name: "mixed policy",
			Args: "policy show",
			ConfigFile: &config.File{
				Auth: config.Auth{
					Default: "user",
					Tokens: config.AuthTokens{
						"user": &config.AuthToken{
							Type:  config.AuthTokenTypeStatic,
							Token: "test-token",
							Allow: []string{"readonly", "service:write"},
						},
					},
				},
			},
			WantOutputs: []string{
				"Policy: readonly, service:write",
				"Read-only across all groups, plus full access to Service commands",
				"Writes in other groups remain blocked",
			},
		},
		{
			Name: "show by name (non-default)",
			Args: "policy show --name staging",
			ConfigFile: &config.File{
				Auth: config.Auth{
					Default: "user",
					Tokens: config.AuthTokens{
						"user": &config.AuthToken{
							Type:  config.AuthTokenTypeStatic,
							Token: "test-token",
						},
						"staging": &config.AuthToken{
							Type:  config.AuthTokenTypeStatic,
							Token: "staging-token",
							Allow: []string{"compute:write"},
						},
					},
				},
			},
			WantOutputs:    []string{"Token: staging", "Full access to Compute commands"},
			DontWantOutput: "(default)",
		},
		{
			Name: "show default flag",
			Args: "policy show --default",
			ConfigFile: &config.File{
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
			},
			WantOutputs: []string{"Token: user (default)", "readonly"},
		},
		{
			Name:      "name and default mutually exclusive",
			Args:      "policy show --name foo --default",
			WantError: "--name and --default are mutually exclusive",
		},
		{
			Name:      "token not found",
			Args:      "policy show --name nonexistent",
			WantError: `token "nonexistent" not found`,
		},
		{
			Name: "raw token via --token flag",
			Args: "policy show --token raw-api-token",
			ConfigFile: &config.File{
				Auth: config.Auth{
					Default: "user",
					Tokens: config.AuthTokens{
						"user": &config.AuthToken{
							Type:  config.AuthTokenTypeStatic,
							Token: "test-token",
						},
					},
				},
			},
			WantError: "current token is not stored",
		},
		{
			Name: "unknown policy entries",
			Args: "policy show",
			ConfigFile: &config.File{
				Auth: config.Auth{
					Default: "user",
					Tokens: config.AuthTokens{
						"user": &config.AuthToken{
							Type:  config.AuthTokenTypeStatic,
							Token: "test-token",
							Allow: []string{"future-policy"},
						},
					},
				},
			},
			WantOutputs: []string{
				"Custom policy: future-policy",
				"Unrecognized entries (ignored): future-policy",
			},
		},
	}

	testutil.RunCLIScenarios(t, []string{"auth"}, scenarios)
}
