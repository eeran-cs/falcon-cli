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

package iac

import (
	"fmt"

	"github.com/crowdstrike/falcon-cli/pkg/cmdutil"
	"github.com/crowdstrike/falcon-cli/pkg/factory"
	"github.com/crowdstrike/falcon-cli/pkg/output"
	"github.com/crowdstrike/gofalcon/falcon/client/cspg_iacapi"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/spf13/cobra"
	"k8s.io/kubectl/pkg/util/templates"
)

var iacTableDef = &output.TableDefinition{
	Headers: []string{"DETECTION_ID", "RESOURCE_TYPE", "FILE", "LINE", "RULE_ID", "LAST_DETECTED"},
	RowFunc: func(item any) []string {
		r, ok := item.(*models.ModelsAPIDetectionResponse)
		if !ok {
			return nil
		}
		line := ""
		if r.MisconfiguredLine != nil {
			line = fmt.Sprintf("%d", *r.MisconfiguredLine)
		}
		ruleID := ""
		if r.Rule != nil {
			ruleID = strp(r.Rule.RuleUUID)
		}
		lastDetected := ""
		if r.LastDetected != nil {
			lastDetected = r.LastDetected.String()[:10]
		}
		return []string{strp(r.DetectionUUID), strp(r.ResourceType), strp(r.FileName), line, ruleID, lastDetected}
	},
}

type listOptions struct {
	Factory *factory.Factory
	filter  string
	limit   int64
	offset  int64
	out     string
	Table   cmdutil.TableFormattingOptions
	Client  cmdutil.ClientFilterOptions
}

func NewCmdList(f *factory.Factory) *cobra.Command {
	opts := &listOptions{Factory: f, limit: 25}

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List IaC detections",
		Long:  templates.LongDesc(`List Infrastructure-as-Code security detections.`),
		Example: templates.Examples(`
            # List IaC detections
            falcon fcs iac list

            # Output as JSON
            falcon fcs iac list --output json

            # Grep for terraform findings
            falcon fcs iac list --grep terraform
        `),
		RunE: func(cmd *cobra.Command, args []string) error {
			falconClient, err := f.FalconClient()
			if err != nil {
				return err
			}

			p := cspg_iacapi.NewCombinedDetectionsParams()
			p.Filter = cmdutil.StringPtr(opts.filter)
			p.Limit = &opts.limit
			if opts.offset > 0 {
				p.Offset = &opts.offset
			}

			resp, err := falconClient.CspgIacapi.CombinedDetections(p)
			if err != nil {
				return cmdutil.HandleAPIError(err, "CombinedDetections")
			}

			resources := output.FilterAndSort(resp.Payload.Resources, iacTableDef, opts.Client.ToFilterOptions())
			tableOpts := opts.Table.ToOutputTableOptions()
			printer := output.NewPrinter(output.Format(opts.out), iacTableDef, tableOpts)
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
