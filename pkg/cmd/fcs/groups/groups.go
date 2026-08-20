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
	"github.com/crowdstrike/falcon-cli/pkg/factory"
	"github.com/crowdstrike/falcon-cli/pkg/output"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/spf13/cobra"
	"k8s.io/kubectl/pkg/util/templates"
)

// NewGroupsCmd represents the groups command group.
func NewGroupsCmd(f *factory.Factory) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "groups",
		Short: "Manage cloud groups",
		Long:  templates.LongDesc(`List, create, update, and delete Falcon Cloud Security asset groups.`),
		Example: templates.Examples(`
            # List all cloud groups
            falcon fcs groups list

            # Create a cloud group
            falcon fcs groups create --name "Production" --description "Prod assets"

            # Delete a cloud group
            falcon fcs groups delete --ids <id>
        `),
	}

	cmd.AddCommand(
		NewCmdList(f),
		NewCmdGet(f),
		NewCmdCreate(f),
		NewCmdUpdate(f),
		NewCmdDelete(f),
		NewCmdValues(f),
	)
	return cmd
}

var groupTableDef = &output.TableDefinition{
	Headers: []string{"ID", "NAME", "DESCRIPTION", "ENVIRONMENT", "BUSINESS_UNIT"},
	RowFunc: func(item any) []string {
		r, ok := item.(*models.AssetgroupmanagerV1CloudGroup)
		if !ok {
			return nil
		}
		return []string{r.ID, r.Name, r.Description, r.Environment, r.BusinessUnit}
	},
}
