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

package assets

import (
	"github.com/crowdstrike/falcon-cli/pkg/cmdutil"
	"github.com/crowdstrike/falcon-cli/pkg/factory"
	"github.com/crowdstrike/falcon-cli/pkg/output"
	"github.com/crowdstrike/gofalcon/falcon/client/cloud_security_assets"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/spf13/cobra"
	"k8s.io/kubectl/pkg/util/templates"
)

type listOptions struct {
	Factory *factory.Factory

	Filter string
	Limit  int64
	Offset int64
	Sort   string
	Output string
	Table  cmdutil.TableFormattingOptions
	Client cmdutil.ClientFilterOptions
}

// NewCmdList represents the fcs assets list command.
func NewCmdList(f *factory.Factory) *cobra.Command {
	opts := &listOptions{Factory: f}

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List cloud assets",
		Long:  templates.LongDesc(`List CSPM cloud assets across your cloud accounts.`),
		Example: templates.Examples(`
            # List cloud assets
            falcon fcs assets list

            # Filter by cloud provider
            falcon fcs assets list --filter "cloud_provider:'aws'"

            # Show only specific columns
            falcon fcs assets list --columns name,type,provider,region

            # Client-side grep and sort
            falcon fcs assets list --grep kubernetes --sort-by region

            # JSON output for jq
            falcon fcs assets list --output jsonl | jq '.resource_type'
        `),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runList(opts)
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

func runList(opts *listOptions) error {
	client, err := opts.Factory.FalconClient()
	if err != nil {
		return err
	}

	queryParams := cloud_security_assets.NewCloudSecurityAssetsQueriesParams()
	queryParams.Limit = &opts.Limit
	queryParams.Offset = &opts.Offset
	if opts.Filter != "" {
		queryParams.Filter = &opts.Filter
	}
	if opts.Sort != "" {
		queryParams.Sort = &opts.Sort
	}

	queryResp, err := client.CloudSecurityAssets.CloudSecurityAssetsQueries(queryParams)
	if err != nil {
		return cmdutil.HandleAPIError(err, "query cloud assets")
	}

	var ids []string
	if queryResp.Payload != nil {
		ids = queryResp.Payload.Resources
	}

	def := &output.TableDefinition{
		Headers: []string{"ID", "NAME", "TYPE", "PROVIDER", "REGION", "ACCOUNT"},
		RowFunc: func(item any) []string {
			r, ok := item.(*models.ResourcesCloudResource)
			if !ok || r == nil {
				return []string{"", "", "", "", "", ""}
			}
			return []string{
				r.ID,
				r.ResourceName,
				r.ResourceType,
				r.CloudProvider,
				r.Region,
				r.AccountID,
			}
		},
	}

	tableOpts := opts.Table.ToOutputTableOptions()
	printer := output.NewPrinter(output.Format(opts.Output), def, tableOpts)

	if len(ids) == 0 {
		return printer.Print(opts.Factory.IOStreams.Out, []*models.ResourcesCloudResource{})
	}

	entityParams := cloud_security_assets.NewCloudSecurityAssetsEntitiesGetParams()
	entityParams.Ids = ids

	entityResp, err := client.CloudSecurityAssets.CloudSecurityAssetsEntitiesGet(entityParams)
	if err != nil {
		return cmdutil.HandleAPIError(err, "get cloud assets")
	}

	var resources []*models.ResourcesCloudResource
	if entityResp.Payload != nil {
		resources = entityResp.Payload.Resources
	}

	resources = output.FilterAndSort(resources, def, opts.Client.ToFilterOptions())

	return printer.Print(opts.Factory.IOStreams.Out, resources)
}
