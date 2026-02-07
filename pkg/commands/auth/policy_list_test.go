package auth_test

import (
	"testing"

	"github.com/fastly/cli/pkg/policy"
	"github.com/fastly/cli/pkg/testutil"
)

func TestAuthPolicyList(t *testing.T) {
	known := policy.KnownPolicies()
	wantOutputs := make([]string, len(known))
	copy(wantOutputs, known)

	scenarios := []testutil.CLIScenario{
		{
			Name:        "lists all policies",
			Args:        "policy list",
			WantOutputs: wantOutputs,
		},
		{
			Name:       "includes readonly description",
			Args:       "policy list",
			WantOutput: "Allow all read and local commands",
		},
	}

	testutil.RunCLIScenarios(t, []string{"auth"}, scenarios)
}
