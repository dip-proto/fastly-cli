package auth_test

import (
	"os"
	"testing"
	"time"

	authcmd "github.com/fastly/cli/pkg/commands/auth"
	"github.com/fastly/cli/pkg/credentials"
)

func TestGetExpirationStatus(t *testing.T) {
	now := time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name       string
		token      *credentials.Metadata
		wantStatus authcmd.ExpirationStatus
		wantErr    bool
	}{
		{
			name:       "nil token",
			token:      nil,
			wantStatus: authcmd.StatusNoExpiry,
		},

		{
			name: "needs reauth takes precedence over valid expiry",
			token: &credentials.Metadata{
				Type:             credentials.TypeSSO,
				NeedsReauth:      true,
				RefreshExpiresAt: now.Add(30 * 24 * time.Hour).Format(time.RFC3339),
			},
			wantStatus: authcmd.StatusNeedsReauth,
		},
		{
			name: "needs reauth takes precedence over expired",
			token: &credentials.Metadata{
				Type:             credentials.TypeSSO,
				NeedsReauth:      true,
				RefreshExpiresAt: now.Add(-1 * time.Hour).Format(time.RFC3339),
			},
			wantStatus: authcmd.StatusNeedsReauth,
		},

		{
			name: "static no expiry",
			token: &credentials.Metadata{
				Type: credentials.TypeStatic,
			},
			wantStatus: authcmd.StatusNoExpiry,
		},
		{
			name: "static future expiry OK",
			token: &credentials.Metadata{
				Type:              credentials.TypeStatic,
				APITokenExpiresAt: now.Add(30 * 24 * time.Hour).Format(time.RFC3339),
			},
			wantStatus: authcmd.StatusOK,
		},
		{
			name: "static not expiring soon (3 days out)",
			token: &credentials.Metadata{
				Type:              credentials.TypeStatic,
				APITokenExpiresAt: now.Add(3 * 24 * time.Hour).Format(time.RFC3339),
			},
			wantStatus: authcmd.StatusOK,
		},
		{
			name: "static expiring soon (within 30 minutes)",
			token: &credentials.Metadata{
				Type:              credentials.TypeStatic,
				APITokenExpiresAt: now.Add(20 * time.Minute).Format(time.RFC3339),
			},
			wantStatus: authcmd.StatusExpiringSoon,
		},
		{
			name: "static expiring soon (exactly 30 minutes)",
			token: &credentials.Metadata{
				Type:              credentials.TypeStatic,
				APITokenExpiresAt: now.Add(30 * time.Minute).Format(time.RFC3339),
			},
			wantStatus: authcmd.StatusExpiringSoon,
		},
		{
			name: "static expired",
			token: &credentials.Metadata{
				Type:              credentials.TypeStatic,
				APITokenExpiresAt: now.Add(-2 * time.Hour).Format(time.RFC3339),
			},
			wantStatus: authcmd.StatusExpired,
		},
		{
			name: "static malformed expiry",
			token: &credentials.Metadata{
				Type:              credentials.TypeStatic,
				APITokenExpiresAt: "not-a-date",
			},
			wantStatus: authcmd.StatusNoExpiry,
			wantErr:    true,
		},

		{
			name: "sso refresh OK",
			token: &credentials.Metadata{
				Type:             credentials.TypeSSO,
				HasRefreshToken:  true,
				RefreshExpiresAt: now.Add(30 * 24 * time.Hour).Format(time.RFC3339),
			},
			wantStatus: authcmd.StatusOK,
		},
		{
			name: "sso refresh not expiring soon (3 days out)",
			token: &credentials.Metadata{
				Type:             credentials.TypeSSO,
				HasRefreshToken:  true,
				RefreshExpiresAt: now.Add(3 * 24 * time.Hour).Format(time.RFC3339),
			},
			wantStatus: authcmd.StatusOK,
		},
		{
			name: "sso refresh expiring soon (within 30 minutes)",
			token: &credentials.Metadata{
				Type:             credentials.TypeSSO,
				HasRefreshToken:  true,
				RefreshExpiresAt: now.Add(20 * time.Minute).Format(time.RFC3339),
			},
			wantStatus: authcmd.StatusExpiringSoon,
		},
		{
			name: "sso refresh expired",
			token: &credentials.Metadata{
				Type:             credentials.TypeSSO,
				HasRefreshToken:  true,
				RefreshExpiresAt: now.Add(-1 * time.Hour).Format(time.RFC3339),
			},
			wantStatus: authcmd.StatusExpired,
		},

		// HasRefreshToken set but RefreshExpiresAt empty means refresh
		// metadata is not yet populated; do not warn on access expiry.
		{
			name: "sso has refresh token but no refresh expiry, access expired",
			token: &credentials.Metadata{
				Type:            credentials.TypeSSO,
				HasRefreshToken: true,
				AccessExpiresAt: now.Add(-1 * time.Hour).Format(time.RFC3339),
			},
			wantStatus: authcmd.StatusNoExpiry,
		},

		// SSO with no refresh token falls back to AccessExpiresAt.
		{
			name: "sso no refresh, access OK (beyond 1h threshold)",
			token: &credentials.Metadata{
				Type:            credentials.TypeSSO,
				AccessExpiresAt: now.Add(2 * time.Hour).Format(time.RFC3339),
			},
			wantStatus: authcmd.StatusOK,
		},
		{
			name: "sso no refresh, access expiring soon (within 1h)",
			token: &credentials.Metadata{
				Type:            credentials.TypeSSO,
				AccessExpiresAt: now.Add(30 * time.Minute).Format(time.RFC3339),
			},
			wantStatus: authcmd.StatusExpiringSoon,
		},
		{
			name: "sso no refresh, access expired",
			token: &credentials.Metadata{
				Type:            credentials.TypeSSO,
				AccessExpiresAt: now.Add(-10 * time.Minute).Format(time.RFC3339),
			},
			wantStatus: authcmd.StatusExpired,
		},

		{
			name: "sso malformed refresh, valid access fallback",
			token: &credentials.Metadata{
				Type:             credentials.TypeSSO,
				HasRefreshToken:  true,
				RefreshExpiresAt: "garbage",
				AccessExpiresAt:  now.Add(2 * time.Hour).Format(time.RFC3339),
			},
			wantStatus: authcmd.StatusOK,
		},
		{
			name: "sso malformed refresh, no access",
			token: &credentials.Metadata{
				Type:             credentials.TypeSSO,
				HasRefreshToken:  true,
				RefreshExpiresAt: "garbage",
			},
			wantStatus: authcmd.StatusNoExpiry,
		},
		{
			name: "sso no refresh, malformed access",
			token: &credentials.Metadata{
				Type:            credentials.TypeSSO,
				AccessExpiresAt: "garbage",
			},
			wantStatus: authcmd.StatusNoExpiry,
			wantErr:    true,
		},
		{
			name: "sso both malformed",
			token: &credentials.Metadata{
				Type:             credentials.TypeSSO,
				HasRefreshToken:  true,
				RefreshExpiresAt: "bad1",
				AccessExpiresAt:  "bad2",
			},
			wantStatus: authcmd.StatusNoExpiry,
			wantErr:    true,
		},
		{
			name: "sso no expiry fields at all",
			token: &credentials.Metadata{
				Type: credentials.TypeSSO,
			},
			wantStatus: authcmd.StatusNoExpiry,
		},

		{
			name: "unknown type with expiry (not soon)",
			token: &credentials.Metadata{
				Type:              "unknown",
				APITokenExpiresAt: now.Add(3 * 24 * time.Hour).Format(time.RFC3339),
			},
			wantStatus: authcmd.StatusOK,
		},
		{
			name: "unknown type with expiry (within 30 minutes)",
			token: &credentials.Metadata{
				Type:              "unknown",
				APITokenExpiresAt: now.Add(10 * time.Minute).Format(time.RFC3339),
			},
			wantStatus: authcmd.StatusExpiringSoon,
		},

		// Consistency with checkAndRefreshAuthSSOToken: when both access and
		// refresh are expired, the refresh function returns reauth=true.
		// ExpirationStatus must not return StatusOK.
		{
			name: "consistency: both expired yields StatusExpired not StatusOK",
			token: &credentials.Metadata{
				Type:             credentials.TypeSSO,
				HasRefreshToken:  true,
				AccessExpiresAt:  now.Add(-2 * time.Hour).Format(time.RFC3339),
				RefreshExpiresAt: now.Add(-1 * time.Hour).Format(time.RFC3339),
			},
			wantStatus: authcmd.StatusExpired,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, _, err := authcmd.GetExpirationStatus(tt.token, now)
			if status != tt.wantStatus {
				t.Errorf("GetExpirationStatus() status = %v, want %v", status, tt.wantStatus)
			}
			if (err != nil) != tt.wantErr {
				t.Errorf("GetExpirationStatus() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestExpirationSummary(t *testing.T) {
	now := time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name    string
		status  authcmd.ExpirationStatus
		expires time.Time
		want    string
	}{
		{
			name:    "expires in 3 days",
			status:  authcmd.StatusExpiringSoon,
			expires: now.Add(3 * 24 * time.Hour),
			want:    "expires in 3 days",
		},
		{
			name:    "expires in 2 hours",
			status:  authcmd.StatusExpiringSoon,
			expires: now.Add(2 * time.Hour),
			want:    "expires in 2 hours",
		},
		{
			name:    "expired 2 hours ago",
			status:  authcmd.StatusExpired,
			expires: now.Add(-2 * time.Hour),
			want:    "expired 2 hours ago",
		},
		{
			name:    "expired 1 day ago",
			status:  authcmd.StatusExpired,
			expires: now.Add(-24 * time.Hour),
			want:    "expired 1 day ago",
		},
		{
			name:    "OK returns summary too",
			status:  authcmd.StatusOK,
			expires: now.Add(30 * 24 * time.Hour),
			want:    "expires in 30 days",
		},
		{
			name:   "no expiry returns empty",
			status: authcmd.StatusNoExpiry,
			want:   "",
		},
		{
			name:   "needs reauth returns empty",
			status: authcmd.StatusNeedsReauth,
			want:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := authcmd.ExpirationSummary(tt.status, tt.expires, now)
			if got != tt.want {
				t.Errorf("ExpirationSummary() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestExpirationRemediation(t *testing.T) {
	originalEnv := os.Getenv("FASTLY_DISABLE_AUTH_COMMAND")
	defer os.Setenv("FASTLY_DISABLE_AUTH_COMMAND", originalEnv)

	tests := []struct {
		name       string
		tokenType  string
		disableEnv string
		wantSubstr string
	}{
		{
			name:       "sso with auth enabled",
			tokenType:  "sso",
			wantSubstr: "fastly auth login --sso",
		},
		{
			name:       "static with auth enabled",
			tokenType:  "static",
			wantSubstr: "fastly auth add",
		},
		{
			name:       "unknown type with auth enabled defaults to sso",
			tokenType:  "",
			wantSubstr: "fastly auth login --sso",
		},
		{
			name:       "sso with auth disabled",
			tokenType:  "sso",
			disableEnv: "1",
			wantSubstr: "FASTLY_API_TOKEN",
		},
		{
			name:       "static with auth disabled",
			tokenType:  "static",
			disableEnv: "1",
			wantSubstr: "FASTLY_API_TOKEN",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Setenv("FASTLY_DISABLE_AUTH_COMMAND", tt.disableEnv)
			got := authcmd.ExpirationRemediation(tt.tokenType)
			if got == "" {
				t.Fatal("ExpirationRemediation() returned empty string")
			}
			found := false
			if len(tt.wantSubstr) > 0 {
				for i := 0; i <= len(got)-len(tt.wantSubstr); i++ {
					if got[i:i+len(tt.wantSubstr)] == tt.wantSubstr {
						found = true
						break
					}
				}
			}
			if !found {
				t.Errorf("ExpirationRemediation() = %q, want substring %q", got, tt.wantSubstr)
			}
		})
	}
}
