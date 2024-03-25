package rules

import (
	trules "github.com/aquasecurity/trivy-policies/pkg/rules"
)

func init() {
	for _, r := range trules.GetRules() {
		Register(r)
	}
}
