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
	"github.com/crowdstrike/falcon-cli/pkg/cmdutil"
	"github.com/crowdstrike/falcon-cli/pkg/factory"
	"github.com/crowdstrike/falcon-cli/pkg/output"
	"github.com/crowdstrike/gofalcon/falcon/client/cloud_policies"
	"github.com/spf13/cobra"
	"k8s.io/kubectl/pkg/util/templates"
)

// NewCmdRulesGet represents the fcs policies rules get command.
func NewCmdRulesGet(f *factory.Factory) *cobra.Command {
	var ids []string
	var out string

	cmd := &cobra.Command{
		Use:   "get",
		Short: "Get policy rules by ID",
		Long:  templates.LongDesc(`Get one or more Falcon Cloud Security policy rules by their UUIDs.`),
		Example: templates.Examples(`
            # Get a specific rule
            falcon fcs policies rules get --ids <uuid>

            # Get multiple rules
            falcon fcs policies rules get --ids <uuid1>,<uuid2>
        `),
		RunE: func(_ *cobra.Command, _ []string) error {
			client, err := f.FalconClient()
			if err != nil {
				return err
			}

			params := cloud_policies.NewGetRuleParams()
			params.Ids = ids

			resp, err := client.CloudPolicies.GetRule(params)
			if err != nil {
				return cmdutil.HandleAPIError(err, "get policy rules")
			}

			printer := output.NewPrinter(output.Format(out), ruleTableDef)
			if resp.Payload == nil {
				return printer.Print(f.IOStreams.Out, nil)
			}
			return printer.Print(f.IOStreams.Out, resp.Payload.Resources)
		},
	}

	cmdutil.AddIDsFlag(cmd, &ids, true)
	cmdutil.AddOutputFlag(cmd, &out)
	return cmd
}
