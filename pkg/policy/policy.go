// Package policy implements CLI-level command permission guardrails.
//
// Policies are stored per-token and restrict which commands a managed credential
// can execute. When a token has no stored policy, it is unrestricted.
// Policy enforcement is bypassed when --token (if available) or FASTLY_API_TOKEN is used.
package policy

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/fastly/cli/pkg/env"
)

// Known policy names. "readonly" is a preset that allows all read + local commands.
var knownPolicies = map[string]bool{
	"readonly": true,
	// Group-scoped policies use the pattern "group:mutability".
	// e.g. "service:read", "service:write", "compute:write"
}

func init() {
	// Register all "group:read" and "group:write" policies.
	groups := []Group{
		GroupAuth, GroupCompute, GroupConfig, GroupConfigStore,
		GroupDashboard, GroupDomain, GroupIP, GroupKVStore,
		GroupLogging, GroupLogtail, GroupNGWAF, GroupObjectStorage,
		GroupPOP, GroupProducts, GroupSecretStore, GroupService,
		GroupStats, GroupTLS, GroupTools, GroupUser,
	}
	for _, g := range groups {
		knownPolicies[string(g)+":read"] = true
		knownPolicies[string(g)+":write"] = true
	}
}

// KnownPolicies returns a sorted list of all recognized policy names.
func KnownPolicies() []string {
	result := make([]string, 0, len(knownPolicies))
	for name := range knownPolicies {
		result = append(result, name)
	}
	sort.Strings(result)
	return result
}

// ValidatePolicy checks that all policy names are recognized.
// Returns an error listing any unknown names.
func ValidatePolicy(names []string) error {
	var unknown []string
	for _, name := range names {
		if !knownPolicies[name] {
			unknown = append(unknown, name)
		}
	}
	if len(unknown) > 0 {
		hint := ""
		if !env.AuthCommandDisabled() {
			hint = " (run 'fastly auth policy list' to see valid policies)"
		}
		return fmt.Errorf("unknown policy names: %s%s", strings.Join(unknown, ", "), hint)
	}
	return nil
}

// Effective computes the effective policy from the stored policy and CLI overrides.
// The effective policy is the union of both sets.
func Effective(stored, cli []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, p := range stored {
		if !seen[p] {
			seen[p] = true
			result = append(result, p)
		}
	}
	for _, p := range cli {
		if !seen[p] {
			seen[p] = true
			result = append(result, p)
		}
	}
	return result
}

// Check evaluates whether the given command name is allowed under the policy.
// An empty policy means unrestricted access.
// Returns nil if allowed, or an error describing why the command is blocked.
func Check(commandName string, effectivePolicy []string) error {
	if len(effectivePolicy) == 0 {
		return nil // unrestricted
	}

	meta, found := Taxonomy[commandName]
	if !found {
		// Unknown commands default to write, so check if write is allowed.
		meta = CommandMeta{Mutability: MutabilityWrite}
	}

	// Local commands are always allowed.
	if meta.Mutability == MutabilityLocal {
		return nil
	}

	// Check if "readonly" is in the policy.
	if slices.Contains(effectivePolicy, "readonly") {
		if meta.Mutability == MutabilityRead {
			return nil // readonly allows read
		}
		// readonly blocks write - fall through to group check
	}

	// Check group-specific policies.
	groupRead := string(meta.Group) + ":read"
	groupWrite := string(meta.Group) + ":write"

	for _, p := range effectivePolicy {
		switch p {
		case groupWrite:
			return nil // explicit group:write grants all access for this group
		case groupRead:
			if meta.Mutability == MutabilityRead {
				return nil
			}
		case "readonly":
			// Already handled above
		}
	}

	// Command is blocked.
	return &BlockedError{
		CommandName: commandName,
		Mutability:  meta.Mutability,
		Group:       meta.Group,
		Policy:      effectivePolicy,
	}
}

// BlockedError describes why a command was blocked by policy.
type BlockedError struct {
	CommandName string
	Mutability  Mutability
	Group       Group
	Policy      []string
}

func (e *BlockedError) Error() string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "command %q blocked by policy.\n", e.CommandName)
	fmt.Fprintf(&sb, "This token has a policy that limits which commands it can run.\n")
	fmt.Fprintf(&sb, "Current policy allows: %s\n", strings.Join(e.Policy, ", "))
	fmt.Fprintf(&sb, "To allow this command, add: %s:%s\n", e.Group, e.Mutability)
	if !env.AuthCommandDisabled() {
		fmt.Fprintf(&sb, "Run: fastly auth policy set --name <name> --policy %s:%s\n", e.Group, e.Mutability)
		fmt.Fprintf(&sb, "See `fastly auth policy list` for valid permissions.\n")
	} else {
		fmt.Fprintf(&sb, "Update the token policy via your managed auth workflow.\n")
	}
	if env.AuthCommandDisabled() {
		fmt.Fprintf(&sb, "Policies apply only to stored auth tokens; %s bypasses policy checks.", env.APIToken)
	} else {
		fmt.Fprintf(&sb, "Policies apply only to stored auth tokens; --token and %s bypass policy checks.", env.APIToken)
	}
	return sb.String()
}
