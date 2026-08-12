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

package compliance

import (
	"github.com/crowdstrike/falcon-cli/pkg/cmdutil"
	"github.com/crowdstrike/falcon-cli/pkg/factory"
	"github.com/crowdstrike/falcon-cli/pkg/output"
	"github.com/crowdstrike/gofalcon/falcon/client/cloud_policies"
	"github.com/crowdstrike/gofalcon/falcon/client/cloud_security_compliance"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/spf13/cobra"
	"k8s.io/kubectl/pkg/util/templates"
)

var (
	frameworksShortDesc = `Show compliance posture summaries by framework`
	frameworksLongDesc  = templates.LongDesc(`
        Show compliance posture summaries grouped by compliance framework.

        When --ids is omitted, available framework IDs are discovered automatically.`)
	frameworksExamples = templates.Examples(`
        # Show posture for all available frameworks
        falcon fcs compliance frameworks

        # Show posture for specific frameworks
        falcon fcs compliance frameworks --ids cis-aws --ids nist-800-53

        # Filter by cloud provider
        falcon fcs compliance frameworks --filter "cloud_provider:'aws'"
    `)
)

type frameworksOptions struct {
	factory *factory.Factory

	filter string
	ids    []string
	output string
	Table  cmdutil.TableFormattingOptions
	Client cmdutil.ClientFilterOptions
}

var frameworksTable = &output.TableDefinition{
	Headers: []string{"FRAMEWORK", "SCORE", "PASS", "FAIL", "TOTAL"},
	RowFunc: func(item any) []string {
		f, ok := item.(*models.ComplianceFrameworkSummary)
		if !ok {
			return nil
		}
		name := str(f.Name)
		if v := str(f.Version); v != "" {
			name = name + " " + v
		}
		var score, pass, fail, total string
		if f.Posture != nil {
			score = i32p(f.Posture.Score)
			pass = i32(f.Posture.Passing)
			fail = i32(f.Posture.Failing)
			total = i32(f.Posture.Passing + f.Posture.Failing + f.Posture.Suppressed)
		}
		return []string{name, score, pass, fail, total}
	},
}

// NewCmdFrameworks represents the compliance frameworks command.
func NewCmdFrameworks(f *factory.Factory) *cobra.Command {
	opts := &frameworksOptions{factory: f}

	cmd := &cobra.Command{
		Use:     "frameworks",
		Short:   frameworksShortDesc,
		Long:    frameworksLongDesc,
		Example: frameworksExamples,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runFrameworks(opts)
		},
	}

	cmdutil.AddFilterFlag(cmd, &opts.filter)
	cmdutil.AddIDsFlag(cmd, &opts.ids, false)
	cmdutil.AddOutputFlag(cmd, &opts.output)
	cmdutil.AddTableFormattingFlags(cmd, &opts.Table)
	cmdutil.AddClientFilterFlags(cmd, &opts.Client)

	return cmd
}

func runFrameworks(opts *frameworksOptions) error {
	client, err := opts.factory.FalconClient()
	if err != nil {
		return err
	}

	ids := opts.ids
	if len(ids) == 0 {
		// Discover available framework IDs automatically
		qp := cloud_policies.NewQueryComplianceFrameworksParams()
		qp.Filter = cmdutil.StringPtr(opts.filter)
		qr, err := client.CloudPolicies.QueryComplianceFrameworks(qp)
		if err != nil {
			return cmdutil.HandleAPIError(err, "query compliance frameworks")
		}
		if qr.Payload != nil {
			ids = qr.Payload.Resources
		}
	}

	if len(ids) == 0 {
		tableOpts := opts.Table.ToOutputTableOptions()
		printer := output.NewPrinter(output.Format(opts.output), frameworksTable, tableOpts)
		return printer.Print(opts.factory.IOStreams.Out, []*models.ComplianceFrameworkSummary{})
	}

	params := cloud_security_compliance.NewCloudComplianceFrameworkPostureSummariesParams()
	params.Filter = cmdutil.StringPtr(opts.filter)
	params.Ids = ids

	res, err := client.CloudSecurityCompliance.CloudComplianceFrameworkPostureSummaries(params)
	if err != nil {
		return cmdutil.HandleAPIError(err, "get compliance framework posture summaries")
	}

	resources := output.FilterAndSort(res.Payload.Resources, frameworksTable, opts.Client.ToFilterOptions())
	tableOpts := opts.Table.ToOutputTableOptions()
	printer := output.NewPrinter(output.Format(opts.output), frameworksTable, tableOpts)
	return printer.Print(opts.factory.IOStreams.Out, resources)
}
