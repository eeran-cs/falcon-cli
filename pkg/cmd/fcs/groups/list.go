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

package groups

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/crowdstrike/falcon-cli/pkg/cmdutil"
	"github.com/crowdstrike/falcon-cli/pkg/factory"
	"github.com/crowdstrike/falcon-cli/pkg/output"
	"github.com/crowdstrike/gofalcon/falcon/client/cloud_security"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/spf13/cobra"
	"k8s.io/kubectl/pkg/util/templates"
)

func NewCmdList(f *factory.Factory) *cobra.Command {
	opts := struct {
		filter string
		limit  int64
		offset int64
		out    string
	}{limit: 25}

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List cloud groups",
		Long:  templates.LongDesc(`List Falcon Cloud Security asset groups.`),
		Example: templates.Examples(`
            # List all cloud groups
            falcon fcs groups list

            # Filter by environment (use 'falcon fcs groups values --field environment' to discover values)
            falcon fcs groups list --filter "environment:'production'"

            # Combine filters
            falcon fcs groups list --filter "environment:'production'+business_unit:'payments'"

            # Output as JSON
            falcon fcs groups list --output json
        `),
		RunE: func(cmd *cobra.Command, args []string) error {
			falconClient, err := f.FalconClient()
			if err != nil {
				return err
			}

			p := cloud_security.NewListCloudGroupsExternalParams()
			p.Filter = cmdutil.StringPtr(opts.filter)
			p.Limit = cmdutil.StringPtr(strconv.FormatInt(opts.limit, 10))
			if opts.offset > 0 {
				p.Offset = cmdutil.StringPtr(strconv.FormatInt(opts.offset, 10))
			}

			resp, err := falconClient.CloudSecurity.ListCloudGroupsExternal(p)
			if err != nil {
				if strings.Contains(err.Error(), "cannot unmarshal") {
					return fmt.Errorf("ListCloudGroupsExternal: request rejected by the API\n" +
						"  Feature flag fcs-fga-cloud-groups-external-endpoints may be disabled for this CID,\n" +
						"  or the filter expression may be invalid.\n" +
						"  Also ensure your API client has the 'Asset Groups: Read' scope")
				}
				return cmdutil.HandleAPIError(err, "ListCloudGroupsExternal")
			}

			printer := output.NewPrinter(output.Format(opts.out), groupTableDef)
			if resp.Payload == nil {
				return printer.Print(f.IOStreams.Out, []*models.AssetgroupmanagerV1CloudGroup{})
			}
			return printer.Print(f.IOStreams.Out, resp.Payload.Resources)
		},
	}

	cmdutil.AddFilterFlag(cmd, &opts.filter)
	cmdutil.AddPaginationFlags(cmd, &opts.limit, &opts.offset, 25)
	cmdutil.AddOutputFlag(cmd, &opts.out)
	return cmd
}
