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

package kubernetes

import (
	"github.com/crowdstrike/falcon-cli/pkg/cmdutil"
	"github.com/crowdstrike/falcon-cli/pkg/factory"
	"github.com/crowdstrike/falcon-cli/pkg/output"
	"github.com/crowdstrike/gofalcon/falcon/client/kubernetes_protection"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/spf13/cobra"
	"k8s.io/kubectl/pkg/util/templates"
)

var clusterTableDef = &output.TableDefinition{
	Headers: []string{"ID", "NAME", "STATUS", "K8S_VERSION", "CLOUD", "REGION"},
	RowFunc: func(item any) []string {
		r, ok := item.(*models.ModelsCluster)
		if !ok {
			return nil
		}
		return []string{strp(r.ClusterID), strp(r.ClusterName), strp(r.ClusterStatus), strp(r.KubernetesVersion), strp(r.CloudName), strp(r.CloudRegion)}
	},
}

func NewCmdClusters(f *factory.Factory) *cobra.Command {
	opts := struct {
		filter string
		limit  int64
		offset int64
		out    string
		Table  cmdutil.TableFormattingOptions
		Client cmdutil.ClientFilterOptions
	}{limit: 25}

	cmd := &cobra.Command{
		Use:   "clusters",
		Short: "List Kubernetes clusters",
		Long:  templates.LongDesc(`List Kubernetes clusters monitored by Falcon.`),
		Example: templates.Examples(`
            # List clusters
            falcon fcs kubernetes clusters
        `),
		RunE: func(cmd *cobra.Command, args []string) error {
			falconClient, err := f.FalconClient()
			if err != nil {
				return err
			}

			p := kubernetes_protection.NewClusterCombinedParams()
			p.Filter = cmdutil.StringPtr(opts.filter)
			p.Limit = &opts.limit
			if opts.offset > 0 {
				p.Offset = &opts.offset
			}

			resp, err := falconClient.KubernetesProtection.ClusterCombined(p)
			if err != nil {
				return cmdutil.HandleAPIError(err, "ClusterCombined")
			}

			resources := output.FilterAndSort(resp.Payload.Resources, clusterTableDef, opts.Client.ToFilterOptions())
			tableOpts := opts.Table.ToOutputTableOptions()
			printer := output.NewPrinter(output.Format(opts.out), clusterTableDef, tableOpts)
			return printer.Print(f.IOStreams.Out, resources)
		},
	}

	cmdutil.AddFilterFlag(cmd, &opts.filter)
	cmdutil.AddPaginationFlags(cmd, &opts.limit, &opts.offset, 25)
	cmdutil.AddOutputFlag(cmd, &opts.out)
	cmdutil.AddTableFormattingFlags(cmd, &opts.Table)
	cmdutil.AddClientFilterFlags(cmd, &opts.Client)
	return cmd
}
