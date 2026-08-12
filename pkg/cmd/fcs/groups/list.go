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
	"regexp"
	"sort"
	"strings"

	"github.com/crowdstrike/falcon-cli/pkg/cmdutil"
	"github.com/crowdstrike/falcon-cli/pkg/factory"
	"github.com/crowdstrike/falcon-cli/pkg/output"
	"github.com/crowdstrike/gofalcon/falcon/client/cloud_security"
	"github.com/spf13/cobra"
	"k8s.io/kubectl/pkg/util/templates"
)

// validFilterFields are the FQL fields supported by the groups list endpoints.
var validFilterFields = map[string]string{
	"name":             "string — group name",
	"description":      "string — group description",
	"owner":            "string — group owner",
	"environment":      "string — environment label",
	"business_unit":    "string — business unit label",
	"business_impact":  "string — business impact label",
	"account_id":       "string — cloud account IDs in the group",
	"image_registry":   "string — image registries in the group",
	"image_repository": "string — image repositories in the group",
	"image_tag":        "string — image tags in the group",
	"created_at":       "datetime — creation time",
	"updated_at":       "datetime — last update time",
}

// fqlFieldRe matches field names in FQL expressions.
var fqlFieldRe = regexp.MustCompile(`\b([a-zA-Z_][a-zA-Z0-9_]*)\s*[:<>!]`)

// validateGroupsFilter checks that all field names in an FQL expression are
// supported by the groups endpoints.
func validateGroupsFilter(filter string) error {
	if filter == "" {
		return nil
	}
	matches := fqlFieldRe.FindAllStringSubmatch(filter, -1)
	var unknown []string
	for _, m := range matches {
		if _, ok := validFilterFields[m[1]]; !ok {
			unknown = append(unknown, m[1])
		}
	}
	if len(unknown) == 0 {
		return nil
	}

	keys := make([]string, 0, len(validFilterFields))
	for k := range validFilterFields {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var sb strings.Builder
	fmt.Fprintf(&sb, "unknown FQL field(s): %s\n\n", strings.Join(unknown, ", "))
	fmt.Fprintf(&sb, "  Supported fields for 'falcon fcs groups list':\n")
	for _, k := range keys {
		fmt.Fprintf(&sb, "    %-20s  %s\n", k, validFilterFields[k])
	}
	fmt.Fprintf(&sb, "\n  FQL syntax examples:\n")
	fmt.Fprintf(&sb, "    --filter \"name:'Production'\"\n")
	fmt.Fprintf(&sb, "    --filter \"environment:'production'+business_unit:'payments'\"\n")
	fmt.Fprintf(&sb, "\n  Tip: run 'falcon fcs groups values --field environment' to see valid values.\n")
	return fmt.Errorf("%s", sb.String())
}

func NewCmdList(f *factory.Factory) *cobra.Command {
	opts := struct {
		filter string
		limit  string
		offset string
		out    string
	}{limit: "25"}

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
			if err := validateGroupsFilter(opts.filter); err != nil {
				return err
			}

			falconClient, err := f.FalconClient()
			if err != nil {
				return err
			}

			p := cloud_security.NewListCloudGroupsExternalParams()
			p.Filter = cmdutil.StringPtr(opts.filter)
			p.Limit = cmdutil.StringPtr(opts.limit)
			p.Offset = cmdutil.StringPtr(opts.offset)

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
			return printer.Print(f.IOStreams.Out, resp.Payload.Resources)
		},
	}

	cmdutil.AddFilterFlag(cmd, &opts.filter)
	cmd.Flags().StringVar(&opts.limit, "limit", "25", "Maximum number of results to return")
	cmd.Flags().StringVar(&opts.offset, "offset", "", "Starting offset for results")
	cmdutil.AddOutputFlag(cmd, &opts.out)
	return cmd
}
