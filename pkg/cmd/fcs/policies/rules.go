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
	"github.com/spf13/cobra"
	"k8s.io/kubectl/pkg/util/templates"
)

// NewRulesCmd represents the fcs policies rules command group.
func NewRulesCmd(f *factory.Factory) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rules",
		Short: "Manage policy rules",
		Long: templates.LongDesc(`
            List, get, create, update, and delete Falcon Cloud Security policy rules.
            Rules define the logic used to evaluate cloud resources for misconfigurations.`),
		Example: templates.Examples(`
            # List rules filtered by provider
            falcon fcs policies rules list --filter "rule_provider:'AWS'"

            # List rules by severity
            falcon fcs policies rules list --filter "rule_severity:'Critical'"
        `),
	}

	cmd.AddCommand(
		NewCmdRulesList(f),
		NewCmdRulesGet(f),
		NewCmdRulesCreate(f),
		NewCmdRulesUpdate(f),
		NewCmdRulesDelete(f),
	)
	return cmd
}
