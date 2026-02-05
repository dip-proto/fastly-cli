package policy

import (
	"fmt"
	"sort"
	"strings"
)

// groupLabels maps Group constants to human-friendly display names.
var groupLabels = map[Group]string{
	GroupAuth:          "Auth",
	GroupCompute:       "Compute",
	GroupConfig:        "Config",
	GroupConfigStore:   "Config Store",
	GroupDashboard:     "Dashboard",
	GroupDomain:        "Domain",
	GroupIP:            "IP",
	GroupKVStore:       "KV Store",
	GroupLogging:       "Logging",
	GroupLogtail:       "Log Tail",
	GroupNGWAF:         "NGWAF",
	GroupObjectStorage: "Object Storage",
	GroupPOP:           "POP",
	GroupProducts:      "Products",
	GroupSecretStore:   "Secret Store",
	GroupService:       "Service",
	GroupStats:         "Stats",
	GroupTLS:           "TLS",
	GroupTools:         "Tools",
	GroupUser:          "User",
}

// GroupLabel returns a human-friendly label for a policy group.
func GroupLabel(g Group) string {
	if label, ok := groupLabels[g]; ok {
		return label
	}
	return string(g)
}

// ExplainResult holds the human-friendly explanation of a policy.
type ExplainResult struct {
	Summary string
	Details []string
}

// Explain produces a human-friendly explanation of a policy allow list.
// An empty allow list means unrestricted access.
func Explain(allow []string) ExplainResult {
	if len(allow) == 0 {
		return ExplainResult{
			Summary: "This token can run any command (read, write, and local).",
			Details: []string{"Local commands are always allowed.", "Policies only apply to stored tokens."},
		}
	}

	hasReadonly := false
	var readGroups, writeGroups, unknown []string
	writeSet := make(map[string]bool)

	for _, p := range allow {
		switch {
		case p == "readonly":
			hasReadonly = true
		case strings.HasSuffix(p, ":read"):
			readGroups = append(readGroups, strings.TrimSuffix(p, ":read"))
		case strings.HasSuffix(p, ":write"):
			g := strings.TrimSuffix(p, ":write")
			writeGroups = append(writeGroups, g)
			writeSet[g] = true
		default:
			unknown = append(unknown, p)
		}
	}

	sort.Strings(readGroups)
	sort.Strings(writeGroups)
	sort.Strings(unknown)

	var summaryParts []string
	var details []string

	if hasReadonly {
		summaryParts = append(summaryParts, "read-only across all groups")
		details = append(details, `"readonly" allows all read-only commands (list/describe).`)
	}

	for _, g := range writeGroups {
		label := GroupLabel(Group(g))
		summaryParts = append(summaryParts, fmt.Sprintf("full access to %s commands", label))
		details = append(details, fmt.Sprintf("%q allows all %s commands including writes.", g+":write", label))
	}

	for _, g := range readGroups {
		if hasReadonly || writeSet[g] {
			continue // readonly or group:write already covers read access
		}
		label := GroupLabel(Group(g))
		summaryParts = append(summaryParts, fmt.Sprintf("read access to %s commands", label))
		details = append(details, fmt.Sprintf("%q allows read-only %s commands.", g+":read", label))
	}

	if len(unknown) > 0 {
		details = append(details, fmt.Sprintf("Unrecognized entries (ignored): %s.", strings.Join(unknown, ", ")))
	}

	if len(summaryParts) == 0 {
		return ExplainResult{
			Summary: fmt.Sprintf("Custom policy: %s.", strings.Join(allow, ", ")),
			Details: details,
		}
	}

	summary := strings.Join(summaryParts, ", plus ")
	summary = strings.ToUpper(summary[:1]) + summary[1:] + "."

	if hasReadonly && len(writeGroups) > 0 {
		details = append(details, "Writes in other groups remain blocked.")
	} else if !hasReadonly {
		details = append(details, "Commands not covered by the policy are blocked.")
	}

	return ExplainResult{
		Summary: summary,
		Details: details,
	}
}
