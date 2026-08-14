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
	rulesShortDesc = `Show compliance posture summaries by rule`
	rulesLongDesc  = templates.LongDesc(`
        Show compliance posture summaries for individual compliance rules.

        When --ids is omitted, available rule IDs are discovered automatically.`)
	rulesExamples = templates.Examples(`
        # Show posture for all available rules
        falcon fcs compliance rules

        # Show posture for specific rules
        falcon fcs compliance rules --ids 1a2b3c4d --ids 5e6f7g8h

        # Filter rule summaries with FQL
        falcon fcs compliance rules --filter "cloud_provider:'azure'"
    `)
)

type rulesOptions struct {
	factory *factory.Factory

	filter string
	limit  int64
	ids    []string
	output string
	Table  cmdutil.TableFormattingOptions
	Client cmdutil.ClientFilterOptions
}

var rulesTable = &output.TableDefinition{
	Headers: []string{"RULE_ID", "TITLE", "PROVIDER", "PASS", "FAIL", "SCORE"},
	RowFunc: func(item any) []string {
		r, ok := item.(*models.ComplianceRulePostureSummary)
		if !ok {
			return nil
		}
		var pass, fail, score string
		if r.Posture != nil {
			pass = i32(r.Posture.Passing)
			fail = i32(r.Posture.Failing)
			score = i32p(r.Posture.Score)
		}
		return []string{str(r.ID), str(r.Name), str(r.Provider), pass, fail, score}
	},
}

// NewCmdRules represents the compliance rules command.
func NewCmdRules(f *factory.Factory) *cobra.Command {
	opts := &rulesOptions{factory: f, limit: 100}

	cmd := &cobra.Command{
		Use:     "rules",
		Short:   rulesShortDesc,
		Long:    rulesLongDesc,
		Example: rulesExamples,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRules(opts)
		},
	}

	cmdutil.AddFilterFlag(cmd, &opts.filter)
	cmdutil.AddIDsFlag(cmd, &opts.ids, false)
	cmd.Flags().Int64Var(&opts.limit, "limit", 100, "Maximum rule IDs to discover when --ids is omitted")
	cmdutil.AddOutputFlag(cmd, &opts.output)
	cmdutil.AddTableFormattingFlags(cmd, &opts.Table)
	cmdutil.AddClientFilterFlags(cmd, &opts.Client)

	return cmd
}

func runRules(opts *rulesOptions) error {
	client, err := opts.factory.FalconClient()
	if err != nil {
		return err
	}

	ids := opts.ids
	if len(ids) == 0 {
		qp := cloud_policies.NewQueryComplianceControlsParams()
		qp.Filter = cmdutil.StringPtr(opts.filter)
		qp.Limit = &opts.limit
		qr, err := client.CloudPolicies.QueryComplianceControls(qp)
		if err != nil {
			return cmdutil.HandleAPIError(err, "query compliance controls")
		}
		if qr.Payload != nil {
			ids = qr.Payload.Resources
		}
	}

	if len(ids) == 0 {
		tableOpts := opts.Table.ToOutputTableOptions()
		printer := output.NewPrinter(output.Format(opts.output), rulesTable, tableOpts)
		return printer.Print(opts.factory.IOStreams.Out, []*models.ComplianceRulePostureSummary{})
	}

	params := cloud_security_compliance.NewCloudComplianceRulePostureSummariesParams()
	params.Filter = cmdutil.StringPtr(opts.filter)
	params.Ids = ids

	res, err := client.CloudSecurityCompliance.CloudComplianceRulePostureSummaries(params)
	if err != nil {
		return cmdutil.HandleAPIError(err, "get compliance rule posture summaries")
	}

	if res.Payload == nil {
		tableOpts := opts.Table.ToOutputTableOptions()
		printer := output.NewPrinter(output.Format(opts.output), rulesTable, tableOpts)
		return printer.Print(opts.factory.IOStreams.Out, []*models.ComplianceRulePostureSummary{})
	}
	resources := output.FilterAndSort(res.Payload.Resources, rulesTable, opts.Client.ToFilterOptions())
	tableOpts := opts.Table.ToOutputTableOptions()
	printer := output.NewPrinter(output.Format(opts.output), rulesTable, tableOpts)
	return printer.Print(opts.factory.IOStreams.Out, resources)
}
