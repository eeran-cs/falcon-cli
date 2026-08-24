// Copyright (c) 2026 CrowdStrike, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package policies

import (
	"github.com/crowdstrike/falcon-cli/pkg/factory"
	"github.com/crowdstrike/falcon-cli/pkg/output"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/spf13/cobra"
	"k8s.io/kubectl/pkg/util/templates"
)

// NewPoliciesCmd represents the fcs policies command group.
func NewPoliciesCmd(f *factory.Factory) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policies",
		Short: "Manage cloud security policies and rules",
		Long: templates.LongDesc(`
            Manage Falcon Cloud Security policies, rules, and related resources.
            Provides full lifecycle management for custom and default policy rules.`),
		Example: templates.Examples(`
            # List all policy rules
            falcon fcs policies rules list

            # Get a specific rule by ID
            falcon fcs policies rules get --ids <uuid>

            # Create a custom rule
            falcon fcs policies rules create --name "My Rule" --severity 3 --provider AWS

            # Delete a rule
            falcon fcs policies rules delete --ids <uuid>
        `),
	}

	cmd.AddCommand(
		NewRulesCmd(f),
		NewOverridesCmd(f),
	)
	return cmd
}

var ruleTableDef = &output.TableDefinition{
	Headers: []string{"UUID", "NAME", "SEVERITY", "PROVIDER", "ORIGIN", "DOMAIN", "STATUS"},
	RowFunc: func(item any) []string {
		r, ok := item.(*models.ApimodelsRule)
		if !ok || r == nil {
			return nil
		}

		severity := ""
		if r.Severity != nil {
			switch *r.Severity {
			case 1:
				severity = "Informational"
			case 2:
				severity = "Medium"
			case 3:
				severity = "High"
			case 4:
				severity = "Critical"
			}
		}

		return []string{
			deref(r.UUID),
			deref(r.Name),
			severity,
			deref(r.Provider),
			deref(r.Origin),
			deref(r.Domain),
			deref(r.Subdomain),
		}
	},
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
