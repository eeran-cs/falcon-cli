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

package vulnerabilities

import (
	"fmt"

	"github.com/crowdstrike/falcon-cli/pkg/cmdutil"
	"github.com/crowdstrike/falcon-cli/pkg/factory"
	"github.com/crowdstrike/falcon-cli/pkg/output"
	"github.com/crowdstrike/gofalcon/falcon/client/container_vulnerabilities"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/spf13/cobra"
	"k8s.io/kubectl/pkg/util/templates"
)

var vulnTableDef = &output.TableDefinition{
	Headers: []string{"CVE_ID", "SEVERITY", "CVSS", "IMAGES_IMPACTED", "CONTAINERS_IMPACTED", "REMEDIATION"},
	RowFunc: func(item any) []string {
		r, ok := item.(*models.ModelsAPIVulnerabilityCombined)
		if !ok {
			return nil
		}
		cvss := ""
		if r.CvssScore != nil {
			cvss = fmt.Sprintf("%.1f", *r.CvssScore)
		}
		images := ""
		if r.ImagesImpacted != nil {
			images = fmt.Sprintf("%d", *r.ImagesImpacted)
		}
		containers := ""
		if r.ContainersImpacted != nil {
			containers = fmt.Sprintf("%d", *r.ContainersImpacted)
		}
		remediation := "false"
		if r.RemediationAvailable != nil && *r.RemediationAvailable {
			remediation = "true"
		}
		return []string{strp(r.CveID), strp(r.Severity), cvss, images, containers, remediation}
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
		Short: "List container vulnerabilities",
		Long:  templates.LongDesc(`List container image vulnerabilities detected by Falcon.`),
		Example: templates.Examples(`
            # List all container vulnerabilities
            falcon fcs vulnerabilities list

            # Filter by severity
            falcon fcs vulnerabilities list --filter "severity:'CRITICAL'"

            # Output as JSON
            falcon fcs vulnerabilities list --output json
        `),
		RunE: func(cmd *cobra.Command, args []string) error {
			falconClient, err := f.FalconClient()
			if err != nil {
				return err
			}

			p := container_vulnerabilities.NewReadCombinedVulnerabilitiesParams()
			p.Filter = cmdutil.StringPtr(opts.filter)
			p.Limit = &opts.limit
			if opts.offset > 0 {
				p.Offset = &opts.offset
			}

			resp, err := falconClient.ContainerVulnerabilities.ReadCombinedVulnerabilities(p)
			if err != nil {
				return cmdutil.HandleAPIError(err, "ReadCombinedVulnerabilities")
			}

			resources := output.FilterAndSort(resp.Payload.Resources, vulnTableDef, opts.Client.ToFilterOptions())
			tableOpts := opts.Table.ToOutputTableOptions()
			printer := output.NewPrinter(output.Format(opts.out), vulnTableDef, tableOpts)
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
