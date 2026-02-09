package policy

import (
	"errors"
	"strings"
	"testing"
)

// ---------- TestKnownPolicies ----------

func TestKnownPolicies(t *testing.T) {
	t.Parallel()

	policies := KnownPolicies()

	// All groups registered in init() plus "readonly".
	allGroups := []Group{
		GroupAuth, GroupCompute, GroupConfig, GroupConfigStore,
		GroupDashboard, GroupDomain, GroupIP, GroupKVStore,
		GroupLogging, GroupLogtail, GroupNGWAF, GroupObjectStorage,
		GroupPOP, GroupProducts, GroupSecretStore, GroupService,
		GroupStats, GroupTLS, GroupTools, GroupUser,
	}
	wantCount := 1 + len(allGroups)*2 // readonly + N groups × (read + write)
	if len(policies) != wantCount {
		t.Fatalf("expected %d known policies, got %d: %v", wantCount, len(policies), policies)
	}

	// Should be sorted.
	for i := 1; i < len(policies); i++ {
		if policies[i] < policies[i-1] {
			t.Errorf("not sorted: %q comes after %q", policies[i], policies[i-1])
		}
	}

	// Should contain "readonly" and both :read/:write for every group.
	policySet := make(map[string]bool, len(policies))
	for _, p := range policies {
		policySet[p] = true
	}
	if !policySet["readonly"] {
		t.Error("expected 'readonly' in known policies")
	}
	for _, g := range allGroups {
		if !policySet[string(g)+":read"] {
			t.Errorf("expected %s:read in known policies", g)
		}
		if !policySet[string(g)+":write"] {
			t.Errorf("expected %s:write in known policies", g)
		}
	}
}

// ---------- TestValidatePolicy ----------

func TestValidatePolicy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		policies  []string
		wantError bool
		errSubstr string
	}{
		{
			name:      "empty list is valid",
			policies:  nil,
			wantError: false,
		},
		{
			name:      "readonly is valid",
			policies:  []string{"readonly"},
			wantError: false,
		},
		{
			name:      "group:read is valid",
			policies:  []string{"service:read"},
			wantError: false,
		},
		{
			name:      "group:write is valid",
			policies:  []string{"service:write"},
			wantError: false,
		},
		{
			name:      "multiple valid policies",
			policies:  []string{"readonly", "service:write", "compute:read"},
			wantError: false,
		},
		{
			name:      "all group:read variants are valid",
			policies:  []string{"auth:read", "compute:read", "config:read", "configstore:read", "dashboard:read", "domain:read", "ip:read", "kvstore:read", "logging:read", "logtail:read", "ngwaf:read", "objectstorage:read", "pop:read", "products:read", "secretstore:read", "service:read", "stats:read", "tls:read", "tools:read", "user:read"},
			wantError: false,
		},
		{
			name:      "unknown policy name",
			policies:  []string{"bogus"},
			wantError: true,
			errSubstr: "bogus",
		},
		{
			name:      "error references list command",
			policies:  []string{"invalid"},
			wantError: true,
			errSubstr: "fastly auth policy list",
		},
		{
			name:      "mix of valid and unknown",
			policies:  []string{"readonly", "notreal"},
			wantError: true,
			errSubstr: "notreal",
		},
		{
			name:      "multiple unknown names listed",
			policies:  []string{"foo", "bar"},
			wantError: true,
			errSubstr: "foo, bar",
		},
		{
			name:      "group:local is not a registered policy",
			policies:  []string{"service:local"},
			wantError: true,
			errSubstr: "service:local",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := ValidatePolicy(tc.policies)
			if tc.wantError {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tc.errSubstr)
				}
				if !strings.Contains(err.Error(), tc.errSubstr) {
					t.Fatalf("expected error containing %q, got: %s", tc.errSubstr, err)
				}
			} else if err != nil {
				t.Fatalf("unexpected error: %s", err)
			}
		})
	}
}

// ---------- TestEffective ----------

func TestEffective(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		stored []string
		cli    []string
		want   []string
	}{
		{
			name:   "both empty",
			stored: nil,
			cli:    nil,
			want:   nil,
		},
		{
			name:   "stored only",
			stored: []string{"readonly"},
			cli:    nil,
			want:   []string{"readonly"},
		},
		{
			name:   "cli only",
			stored: nil,
			cli:    []string{"service:write"},
			want:   []string{"service:write"},
		},
		{
			name:   "union of stored and cli",
			stored: []string{"readonly"},
			cli:    []string{"service:write"},
			want:   []string{"readonly", "service:write"},
		},
		{
			name:   "deduplication",
			stored: []string{"readonly", "service:read"},
			cli:    []string{"service:read", "compute:write"},
			want:   []string{"readonly", "service:read", "compute:write"},
		},
		{
			name:   "duplicates within stored",
			stored: []string{"readonly", "readonly"},
			cli:    nil,
			want:   []string{"readonly"},
		},
		{
			name:   "duplicates within cli",
			stored: nil,
			cli:    []string{"service:write", "service:write"},
			want:   []string{"service:write"},
		},
		{
			name:   "stored order preserved",
			stored: []string{"b:read", "a:read"},
			cli:    []string{"c:read"},
			want:   []string{"b:read", "a:read", "c:read"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := Effective(tc.stored, tc.cli)
			if len(got) != len(tc.want) {
				t.Fatalf("length mismatch: got %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("index %d: got %q, want %q (full result: %v)", i, got[i], tc.want[i], got)
				}
			}
		})
	}
}

// ---------- TestCheck_Unrestricted ----------

func TestCheck_Unrestricted(t *testing.T) {
	t.Parallel()

	// An empty policy means unrestricted: every command should be allowed.
	commands := []string{
		"service create",
		"service list",
		"compute build",
		"totally-unknown-command",
	}
	for _, cmd := range commands {
		if err := Check(cmd, nil); err != nil {
			t.Errorf("empty policy should allow %q, got error: %s", cmd, err)
		}
		if err := Check(cmd, []string{}); err != nil {
			t.Errorf("empty slice policy should allow %q, got error: %s", cmd, err)
		}
	}
}

// ---------- TestCheck_ReadonlyPolicy ----------

func TestCheck_ReadonlyPolicy(t *testing.T) {
	t.Parallel()

	policy := []string{"readonly"}

	// Read commands should be allowed.
	readCmds := []string{
		"service list",
		"service describe",
		"service search",
		"ip-list",
		"log-tail",
		"pops",
		"stats historical",
		"whoami",
	}
	for _, cmd := range readCmds {
		if err := Check(cmd, policy); err != nil {
			t.Errorf("readonly should allow read command %q, got error: %s", cmd, err)
		}
	}

	// Local commands should be allowed (always allowed regardless of policy).
	localCmds := []string{
		"compute build",
		"config",
		"auth login",
		"version",
		"install",
	}
	for _, cmd := range localCmds {
		if err := Check(cmd, policy); err != nil {
			t.Errorf("readonly should allow local command %q, got error: %s", cmd, err)
		}
	}

	// Write commands should be blocked.
	writeCmds := []string{
		"service create",
		"service delete",
		"service update",
		"compute deploy",
		"domain create",
		"user create",
	}
	for _, cmd := range writeCmds {
		err := Check(cmd, policy)
		if err == nil {
			t.Errorf("readonly should block write command %q, got nil", cmd)
			continue
		}
		var blocked *BlockedError
		if !errors.As(err, &blocked) {
			t.Errorf("expected BlockedError for %q, got %T: %s", cmd, err, err)
		}
	}
}

// ---------- TestCheck_GroupPolicies ----------

func TestCheck_GroupPolicies(t *testing.T) {
	t.Parallel()

	t.Run("service:read allows read, blocks write", func(t *testing.T) {
		t.Parallel()
		policy := []string{"service:read"}

		// Should allow service read commands.
		if err := Check("service list", policy); err != nil {
			t.Errorf("service:read should allow 'service list': %s", err)
		}
		if err := Check("service describe", policy); err != nil {
			t.Errorf("service:read should allow 'service describe': %s", err)
		}

		// Should block service write commands.
		if err := Check("service create", policy); err == nil {
			t.Error("service:read should block 'service create'")
		}
		if err := Check("service delete", policy); err == nil {
			t.Error("service:read should block 'service delete'")
		}
	})

	t.Run("service:write allows both read and write", func(t *testing.T) {
		t.Parallel()
		policy := []string{"service:write"}

		if err := Check("service create", policy); err != nil {
			t.Errorf("service:write should allow 'service create': %s", err)
		}
		if err := Check("service list", policy); err != nil {
			t.Errorf("service:write should allow 'service list': %s", err)
		}
	})

	t.Run("group policy does not grant cross-group access", func(t *testing.T) {
		t.Parallel()
		policy := []string{"service:write"}

		// Should block commands from other groups.
		if err := Check("compute deploy", policy); err == nil {
			t.Error("service:write should not allow 'compute deploy'")
		}
		if err := Check("domain create", policy); err == nil {
			t.Error("service:write should not allow 'domain create'")
		}
	})

	t.Run("multiple group policies combine", func(t *testing.T) {
		t.Parallel()
		policy := []string{"service:read", "compute:write"}

		if err := Check("service list", policy); err != nil {
			t.Errorf("should allow service read: %s", err)
		}
		if err := Check("compute deploy", policy); err != nil {
			t.Errorf("should allow compute write: %s", err)
		}
		if err := Check("service create", policy); err == nil {
			t.Error("should block service write (only service:read granted)")
		}
	})

	t.Run("readonly combined with group:write", func(t *testing.T) {
		t.Parallel()
		policy := []string{"readonly", "service:write"}

		// readonly allows all reads.
		if err := Check("compute acl list", policy); err != nil {
			t.Errorf("readonly should allow compute read: %s", err)
		}
		// service:write additionally allows service writes.
		if err := Check("service create", policy); err != nil {
			t.Errorf("service:write should allow service create: %s", err)
		}
		// Write in a group without explicit grant should still be blocked.
		if err := Check("compute deploy", policy); err == nil {
			t.Error("should block compute deploy (no compute:write)")
		}
	})

	t.Run("logging group", func(t *testing.T) {
		t.Parallel()
		policy := []string{"logging:read"}

		if err := Check("service logging s3 list", policy); err != nil {
			t.Errorf("logging:read should allow 'service logging s3 list': %s", err)
		}
		if err := Check("service logging s3 create", policy); err == nil {
			t.Error("logging:read should block 'service logging s3 create'")
		}
	})
}

// ---------- TestCheck_UnknownCommand ----------

func TestCheck_UnknownCommand(t *testing.T) {
	t.Parallel()

	// Unknown commands default to write mutability with no group.
	// Under any restrictive policy they should be blocked.
	policy := []string{"readonly"}

	err := Check("completely-unknown-cmd", policy)
	if err == nil {
		t.Fatal("expected unknown command to be blocked under readonly policy")
	}

	var blocked *BlockedError
	if !errors.As(err, &blocked) {
		t.Fatalf("expected BlockedError, got %T: %s", err, err)
	}
	if blocked.Mutability != MutabilityWrite {
		t.Errorf("expected write mutability for unknown command, got %q", blocked.Mutability)
	}
	if blocked.CommandName != "completely-unknown-cmd" {
		t.Errorf("expected command name %q, got %q", "completely-unknown-cmd", blocked.CommandName)
	}

	// Under an unrestricted (empty) policy, unknown commands pass.
	if err := Check("completely-unknown-cmd", nil); err != nil {
		t.Errorf("unrestricted policy should allow unknown command: %s", err)
	}
}

// ---------- TestCheck_LocalCommands ----------

func TestCheck_LocalCommands(t *testing.T) {
	t.Parallel()

	// Local commands should always be allowed, even under a restrictive policy
	// that would normally block everything.
	restrictivePolicies := [][]string{
		{"readonly"},
		{"service:read"},
		{"compute:write"},
		{"user:read", "tls:read"},
	}

	localCmds := []string{
		"compute build",
		"compute hash-files",
		"compute init",
		"compute metadata",
		"compute pack",
		"compute serve",
		"compute validate",
		"config",
		"auth login",
		"auth add",
		"auth use",
		"auth list",
		"auth show",
		"auth delete",
		"auth policy set",
		"auth policy list",
		"install",
		"update",
		"version",
		"shellcomplete",
	}

	for _, policy := range restrictivePolicies {
		for _, cmd := range localCmds {
			if err := Check(cmd, policy); err != nil {
				t.Errorf("local command %q should be allowed under policy %v, got: %s", cmd, policy, err)
			}
		}
	}
}

// ---------- TestBlockedError ----------

func TestBlockedError(t *testing.T) {
	t.Parallel()

	be := &BlockedError{
		CommandName: "service create",
		Mutability:  MutabilityWrite,
		Group:       GroupService,
		Policy:      []string{"readonly"},
	}

	msg := be.Error()

	// Check that the error message includes all the relevant information.
	checks := []struct {
		label    string
		expected string
	}{
		{"command name", `command "service create" blocked by policy`},
		{"current policy", "Current policy allows: readonly"},
		{"add suggestion", "To allow this command, add: service:write"},
		{"set suggestion", "Run: fastly auth policy set --name <name> --policy service:write"},
	}
	for _, c := range checks {
		if !strings.Contains(msg, c.expected) {
			t.Errorf("error message missing %s: want substring %q in:\n%s", c.label, c.expected, msg)
		}
	}

	// Verify it satisfies the error interface.
	var err error = be
	if err.Error() != msg {
		t.Error("BlockedError does not satisfy error interface correctly")
	}

	// Verify errors.As works.
	wrappedErr := error(be)
	var target *BlockedError
	if !errors.As(wrappedErr, &target) {
		t.Error("errors.As should find BlockedError")
	}
	if target.CommandName != "service create" {
		t.Errorf("errors.As returned wrong command name: %q", target.CommandName)
	}
}

// ---------- TestBlockedError_MultiplePolicy ----------

func TestBlockedError_MultiplePolicy(t *testing.T) {
	t.Parallel()

	be := &BlockedError{
		CommandName: "compute deploy",
		Mutability:  MutabilityWrite,
		Group:       GroupCompute,
		Policy:      []string{"readonly", "service:write"},
	}

	msg := be.Error()
	if !strings.Contains(msg, "Current policy allows: readonly, service:write") {
		t.Errorf("expected comma-separated policy list in error, got:\n%s", msg)
	}
	if !strings.Contains(msg, "add: compute:write") {
		t.Errorf("expected suggestion to add compute:write, got:\n%s", msg)
	}
}
