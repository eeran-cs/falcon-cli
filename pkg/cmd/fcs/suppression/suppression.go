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
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/spf13/cobra"
	"k8s.io/kubectl/pkg/util/templates"
)

var (
	shortDesc = `Manage cloud security suppression rules`
	longDesc  = templates.LongDesc(`
        List, create, and delete Falcon Cloud Security suppression rules.`)
	examples = templates.Examples(`
        # List suppression rules
        falcon fcs suppression list

        # Create a suppression rule
        falcon fcs suppression create --name "Ignore dev buckets" --reason accepted_risk

        # Delete suppression rules
        falcon fcs suppression delete --ids 1a2b3c4d
    `)
)

// NewSuppressionCmd represents the suppression command group.
func NewSuppressionCmd(f *factory.Factory) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "suppression",
		Short:   shortDesc,
		Long:    longDesc,
		Example: examples,
	}

	cmd.AddCommand(
		NewCmdList(f),
		NewCmdCreate(f),
		NewCmdDelete(f),
	)
	return cmd
}

var suppressionTable = &output.TableDefinition{
	Headers: []string{"ID", "NAME", "DESCRIPTION", "STATUS", "CREATED"},
	RowFunc: func(item any) []string {
		r, ok := item.(*models.ApimodelsSuppressionRule)
		if !ok {
			return nil
		}
		status := "enabled"
		if r.Disabled != nil && *r.Disabled {
			status = "disabled"
		}
		created := ""
		if r.CreatedAt != nil {
			created = r.CreatedAt.String()
		}
		return []string{cmdutil.Deref(r.ID), cmdutil.Deref(r.Name), r.Description, status, created}
	},
}
