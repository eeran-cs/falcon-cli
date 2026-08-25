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

package registration

import (
	"github.com/crowdstrike/falcon-cli/pkg/factory"
	"github.com/crowdstrike/falcon-cli/pkg/output"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/spf13/cobra"
	"k8s.io/kubectl/pkg/util/templates"
)

// NewAWSCmd represents the fcs registration aws command group.
func NewAWSCmd(f *factory.Factory) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "aws",
		Short: "Manage AWS account registrations",
		Long:  templates.LongDesc(`List, register, update, and delete AWS cloud account registrations.`),
		Example: templates.Examples(`
            # List all registered AWS accounts
            falcon fcs registration aws list

            # Get a specific AWS account
            falcon fcs registration aws get --ids <account-id>
        `),
	}

	cmd.AddCommand(
		NewCmdAWSList(f),
		NewCmdAWSGet(f),
		NewCmdAWSCreate(f),
		NewCmdAWSUpdate(f),
		NewCmdAWSDelete(f),
	)
	return cmd
}

var awsAccountTableDef = &output.TableDefinition{
	Headers: []string{"ACCOUNT_ID", "ACCOUNT_NAME", "TYPE", "ENVIRONMENT", "STATUS", "CSPM"},
	RowFunc: func(item any) []string {
		r, ok := item.(*models.DomainCloudAWSAccountV1)
		if !ok || r == nil {
			return nil
		}

		status := "unknown"
		if len(r.Conditions) > 0 && r.Conditions[0] != nil {
			if r.Conditions[0].Feature != nil {
				status = *r.Conditions[0].Feature
			}
		}

		cspm := "disabled"
		if r.CspmEnabled {
			cspm = "enabled"
		}

		return []string{
			r.AccountID,
			r.AccountName,
			r.AccountType,
			r.Environment,
			status,
			cspm,
		}
	},
}
