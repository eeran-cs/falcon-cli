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
	"sort"
	"strings"

	"github.com/crowdstrike/falcon-cli/pkg/cmdutil"
	"github.com/crowdstrike/falcon-cli/pkg/factory"
	"github.com/crowdstrike/gofalcon/falcon/client/cloud_security"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/spf13/cobra"
	"k8s.io/kubectl/pkg/util/templates"
)

// validValueFields are the fields that have meaningful distinct string values.
var validValueFields = []string{"environment", "business_unit", "business_impact", "owner"}

func NewCmdValues(f *factory.Factory) *cobra.Command {
	var field string

	cmd := &cobra.Command{
		Use:   "values",
		Short: "List valid values for a filterable field",
		Long: templates.LongDesc(`
			Fetch all cloud groups and return the distinct non-empty values for a field.
			Use this to discover valid FQL filter values — the CLI equivalent of a UI dropdown.

			Supported fields: environment, business_unit, business_impact, owner`),
		Example: templates.Examples(`
			# See what environments exist (use in --filter)
			falcon fcs groups values --field environment

			# See what business units exist
			falcon fcs groups values --field business_unit

			# Then filter by one of those values
			falcon fcs groups list --filter "environment:'production'"
		`),
		RunE: func(cmd *cobra.Command, args []string) error {
			valid := false
			for _, f := range validValueFields {
				if f == field {
					valid = true
					break
				}
			}
			if !valid {
				return fmt.Errorf("unknown field %q\n  Supported fields: %s\n\n  Example: falcon fcs groups values --field environment",
					field, strings.Join(validValueFields, ", "))
			}

			falconClient, err := f.FalconClient()
			if err != nil {
				return err
			}

			// Paginate through all groups to collect distinct values.
			seen := map[string]struct{}{}
			pageOffset := 0
			pageLimit := 200

			for {
				p := cloud_security.NewListCloudGroupsExternalParams()
				p.Limit = cmdutil.StringPtr(fmt.Sprintf("%d", pageLimit))
				if pageOffset > 0 {
					p.Offset = cmdutil.StringPtr(fmt.Sprintf("%d", pageOffset))
				}

				resp, err := falconClient.CloudSecurity.ListCloudGroupsExternal(p)
				if err != nil {
					return cmdutil.HandleAPIError(err, "ListCloudGroupsExternal")
				}

				for _, g := range resp.Payload.Resources {
					v := extractField(g, field)
					if v != "" {
						seen[v] = struct{}{}
					}
				}

				if len(resp.Payload.Resources) < pageLimit {
					break
				}
				pageOffset += len(resp.Payload.Resources)
			}

			if len(seen) == 0 {
				fmt.Fprintf(f.IOStreams.Out, "No values found for field %q (all groups have it empty).\n", field)
				return nil
			}

			values := make([]string, 0, len(seen))
			for v := range seen {
				values = append(values, v)
			}
			sort.Strings(values)
			fmt.Fprintf(f.IOStreams.Out, "Valid values for %q:\n", field)
			for _, v := range values {
				fmt.Fprintf(f.IOStreams.Out, "  %s\n", v)
			}
			fmt.Fprintf(f.IOStreams.Out, "\nUse in a filter: --filter \"%s:'%s'\"\n", field, values[0])
			return nil
		},
	}

	cmd.Flags().StringVar(&field, "field", "", "Field to list values for (environment, business_unit, business_impact, owner)")
	_ = cmd.MarkFlagRequired("field")
	return cmd
}

func extractField(g *models.AssetgroupmanagerV1CloudGroup, field string) string {
	switch field {
	case "environment":
		return g.Environment
	case "business_unit":
		return g.BusinessUnit
	case "business_impact":
		return g.BusinessImpact
	case "owner":
		if len(g.Owners) > 0 {
			return g.Owners[0]
		}
	}
	return ""
}
