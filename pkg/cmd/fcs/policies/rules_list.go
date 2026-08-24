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

type rulesListOptions struct {
	Factory *factory.Factory

	Filter string
	Limit  int64
	Offset int64
	Sort   string
	Output string
	Table  cmdutil.TableFormattingOptions
	Client cmdutil.ClientFilterOptions
}

// NewCmdRulesList represents the fcs policies rules list command.
func NewCmdRulesList(f *factory.Factory) *cobra.Command {
	opts := &rulesListOptions{Factory: f}

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List policy rules",
		Long:  templates.LongDesc(`List Falcon Cloud Security policy rules with optional FQL filtering.`),
		Example: templates.Examples(`
            # List all rules
            falcon fcs policies rules list

            # Filter by provider
            falcon fcs policies rules list --filter "rule_provider:'AWS'"

            # Filter by severity and origin
            falcon fcs policies rules list --filter "rule_severity:'Critical'+rule_origin:'Custom'"

            # Sort by name
            falcon fcs policies rules list --sort "rule_name.asc" --limit 50
        `),
		RunE: func(_ *cobra.Command, _ []string) error {
			return runRulesList(opts)
		},
	}

	cmdutil.AddFilterFlag(cmd, &opts.Filter)
	cmdutil.AddPaginationFlags(cmd, &opts.Limit, &opts.Offset, 100)
	cmdutil.AddSortFlag(cmd, &opts.Sort)
	cmdutil.AddOutputFlag(cmd, &opts.Output)
	cmdutil.AddTableFormattingFlags(cmd, &opts.Table)
	cmdutil.AddClientFilterFlags(cmd, &opts.Client)

	return cmd
}

func runRulesList(opts *rulesListOptions) error {
	client, err := opts.Factory.FalconClient()
	if err != nil {
		return err
	}

	// First query for IDs
	queryParams := cloud_policies.NewQueryRuleParams()
	queryParams.Limit = &opts.Limit
	queryParams.Offset = &opts.Offset
	if opts.Filter != "" {
		queryParams.Filter = &opts.Filter
	}
	if opts.Sort != "" {
		queryParams.Sort = &opts.Sort
	}

	queryResp, err := client.CloudPolicies.QueryRule(queryParams)
	if err != nil {
		return cmdutil.HandleAPIError(err, "query policy rules")
	}

	if queryResp.Payload == nil || len(queryResp.Payload.Resources) == 0 {
		printer := output.NewPrinter(output.Format(opts.Output), ruleTableDef)
		return printer.Print(opts.Factory.IOStreams.Out, nil)
	}

	// Then get full entities
	getParams := cloud_policies.NewGetRuleParams()
	getParams.Ids = queryResp.Payload.Resources

	getResp, err := client.CloudPolicies.GetRule(getParams)
	if err != nil {
		return cmdutil.HandleAPIError(err, "get policy rules")
	}

	resources := getResp.Payload.Resources
	resources = output.FilterAndSort(resources, ruleTableDef, opts.Client.ToFilterOptions())

	tableOpts := opts.Table.ToOutputTableOptions()
	printer := output.NewPrinter(output.Format(opts.Output), ruleTableDef, tableOpts)
	return printer.Print(opts.Factory.IOStreams.Out, resources)
}
