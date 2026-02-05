package policy_test

import (
	"testing"

	"github.com/fastly/cli/pkg/policy"
)

func TestGroupLabel(t *testing.T) {
	tests := []struct {
		group policy.Group
		want  string
	}{
		{policy.GroupService, "Service"},
		{policy.GroupSecretStore, "Secret Store"},
		{policy.GroupKVStore, "KV Store"},
		{policy.GroupNGWAF, "NGWAF"},
		{policy.Group("unknown"), "unknown"},
	}
	for _, tt := range tests {
		got := policy.GroupLabel(tt.group)
		if got != tt.want {
			t.Errorf("GroupLabel(%q) = %q, want %q", tt.group, got, tt.want)
		}
	}
}

func TestExplain(t *testing.T) {
	tests := []struct {
		name        string
		allow       []string
		wantSummary string
		wantDetails []string
	}{
		{
			name:        "unrestricted (nil)",
			allow:       nil,
			wantSummary: "This token can run any command (read, write, and local).",
		},
		{
			name:        "unrestricted (empty)",
			allow:       []string{},
			wantSummary: "This token can run any command (read, write, and local).",
		},
		{
			name:        "readonly only",
			allow:       []string{"readonly"},
			wantSummary: "Read-only across all groups.",
		},
		{
			name:        "readonly plus write group",
			allow:       []string{"readonly", "service:write"},
			wantSummary: "Read-only across all groups, plus full access to Service commands.",
		},
		{
			name:        "single group write",
			allow:       []string{"compute:write"},
			wantSummary: "Full access to Compute commands.",
		},
		{
			name:        "single group read",
			allow:       []string{"logging:read"},
			wantSummary: "Read access to Logging commands.",
		},
		{
			name:        "multiple groups sorted",
			allow:       []string{"service:write", "compute:write"},
			wantSummary: "Full access to Compute commands, plus full access to Service commands.",
		},
		{
			name:        "unknown entries only",
			allow:       []string{"future-policy"},
			wantSummary: "Custom policy: future-policy.",
		},
		{
			name:        "known plus unknown entries",
			allow:       []string{"readonly", "alien"},
			wantSummary: "Read-only across all groups.",
		},
		{
			name:        "read and write for same group deduplicates",
			allow:       []string{"service:read", "service:write"},
			wantSummary: "Full access to Service commands.",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := policy.Explain(tt.allow)
			if result.Summary != tt.wantSummary {
				t.Errorf("Summary = %q, want %q", result.Summary, tt.wantSummary)
			}
			if len(result.Details) == 0 {
				t.Error("expected at least one detail line")
			}
		})
	}
}
