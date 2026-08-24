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

package registration

import (
	"github.com/crowdstrike/falcon-cli/pkg/cmdutil"
	"github.com/crowdstrike/falcon-cli/pkg/factory"
	"github.com/crowdstrike/falcon-cli/pkg/output"
	"github.com/crowdstrike/gofalcon/falcon/client/cloud_aws_registration"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/spf13/cobra"
	"k8s.io/kubectl/pkg/util/templates"
)

type awsListOptions struct {
	Factory *factory.Factory

	Limit  int64
	Offset int64
	Output string
	Table  cmdutil.TableFormattingOptions
}

// NewCmdAWSList represents the fcs registration aws list command.
func NewCmdAWSList(f *factory.Factory) *cobra.Command {
	opts := &awsListOptions{Factory: f}

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List registered AWS accounts",
		Long:  templates.LongDesc(`List all AWS accounts registered with Falcon Cloud Security.`),
		Example: templates.Examples(`
            # List all AWS accounts
            falcon fcs registration aws list

            # Output as JSON
            falcon fcs registration aws list --output json
        `),
		RunE: func(_ *cobra.Command, _ []string) error {
			return runAWSList(opts)
		},
	}

	cmdutil.AddPaginationFlags(cmd, &opts.Limit, &opts.Offset, 100)
	cmdutil.AddOutputFlag(cmd, &opts.Output)
	cmdutil.AddTableFormattingFlags(cmd, &opts.Table)

	return cmd
}

func runAWSList(opts *awsListOptions) error {
	client, err := opts.Factory.FalconClient()
	if err != nil {
		return err
	}

	params := cloud_aws_registration.NewCloudRegistrationAwsQueryAccountsParams()
	params.Limit = &opts.Limit
	params.Offset = &opts.Offset

	queryResp, _, err := client.CloudAwsRegistration.CloudRegistrationAwsQueryAccounts(params)
	if err != nil {
		return cmdutil.HandleAPIError(err, "query AWS accounts")
	}

	if queryResp == nil || queryResp.Payload == nil || len(queryResp.Payload.Resources) == 0 {
		printer := output.NewPrinter(output.Format(opts.Output), awsAccountTableDef)
		return printer.Print(opts.Factory.IOStreams.Out, nil)
	}

	// Get full account details
	getParams := cloud_aws_registration.NewCloudRegistrationAwsGetAccountsParams()
	getParams.Ids = queryResp.Payload.Resources

	getResp, _, err := client.CloudAwsRegistration.CloudRegistrationAwsGetAccounts(getParams)
	if err != nil {
		return cmdutil.HandleAPIError(err, "get AWS accounts")
	}

	var resources []*models.DomainCloudAWSAccountV1
	if getResp != nil && getResp.Payload != nil {
		resources = getResp.Payload.Resources
	}

	tableOpts := opts.Table.ToOutputTableOptions()
	printer := output.NewPrinter(output.Format(opts.Output), awsAccountTableDef, tableOpts)
	return printer.Print(opts.Factory.IOStreams.Out, resources)
}
