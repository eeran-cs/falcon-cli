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

package suppression

import (
	"github.com/crowdstrike/falcon-cli/pkg/cmdutil"
	"github.com/crowdstrike/falcon-cli/pkg/factory"
	"github.com/crowdstrike/falcon-cli/pkg/output"
	"github.com/crowdstrike/gofalcon/falcon/client/cloud_policies"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/spf13/cobra"
	"k8s.io/kubectl/pkg/util/templates"
)

var (
	listShortDesc = `List cloud security suppression rules`
	listLongDesc  = templates.LongDesc(`
        List Falcon Cloud Security suppression rules.

        Rule IDs are queried first, then resolved to full rule details.`)
	listExamples = templates.Examples(`
        # List suppression rules
        falcon fcs suppression list

        # List the 10 most recently created suppression rules
        falcon fcs suppression list --limit 10 --sort created_at.desc

        # Filter suppression rules with FQL
        falcon fcs suppression list --filter "name:*'*dev*'"
    `)
)

type listOptions struct {
	factory *factory.Factory

	filter string
	limit  int64
	offset int64
	sort   string
	output string
	Table  cmdutil.TableFormattingOptions
	Client cmdutil.ClientFilterOptions
}

// NewCmdList represents the suppression list command.
func NewCmdList(f *factory.Factory) *cobra.Command {
	opts := &listOptions{factory: f}

	cmd := &cobra.Command{
		Use:     "list",
		Short:   listShortDesc,
		Long:    listLongDesc,
		Example: listExamples,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runList(opts)
		},
	}

	cmdutil.AddFilterFlag(cmd, &opts.filter)
	cmdutil.AddPaginationFlags(cmd, &opts.limit, &opts.offset, 100)
	cmdutil.AddSortFlag(cmd, &opts.sort)
	cmdutil.AddOutputFlag(cmd, &opts.output)
	cmdutil.AddTableFormattingFlags(cmd, &opts.Table)
	cmdutil.AddClientFilterFlags(cmd, &opts.Client)

	return cmd
}

func runList(opts *listOptions) error {
	client, err := opts.factory.FalconClient()
	if err != nil {
		return err
	}

	queryParams := cloud_policies.NewQuerySuppressionRulesParams()
	queryParams.Filter = cmdutil.StringPtr(opts.filter)
	queryParams.Sort = cmdutil.StringPtr(opts.sort)
	queryParams.Limit = cmdutil.Int64Ptr(opts.limit)
	queryParams.Offset = cmdutil.Int64Ptr(opts.offset)

	queryRes, err := client.CloudPolicies.QuerySuppressionRules(queryParams)
	if err != nil {
		return cmdutil.HandleAPIError(err, "query suppression rules")
	}

	ids := queryRes.Payload.Resources
	tableOpts := opts.Table.ToOutputTableOptions()
	printer := output.NewPrinter(output.Format(opts.output), suppressionTable, tableOpts)
	if len(ids) == 0 {
		return printer.Print(opts.factory.IOStreams.Out, []*models.ApimodelsSuppressionRule{})
	}

	getParams := cloud_policies.NewGetSuppressionRulesParams()
	getParams.Ids = ids

	getRes, err := client.CloudPolicies.GetSuppressionRules(getParams)
	if err != nil {
		return cmdutil.HandleAPIError(err, "get suppression rules")
	}

	resources := output.FilterAndSort(getRes.Payload.Resources, suppressionTable, opts.Client.ToFilterOptions())
	return printer.Print(opts.factory.IOStreams.Out, resources)
}
