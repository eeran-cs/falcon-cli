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

package kubernetes

import (
	"fmt"

	"github.com/crowdstrike/falcon-cli/pkg/cmdutil"
	"github.com/crowdstrike/falcon-cli/pkg/factory"
	"github.com/crowdstrike/falcon-cli/pkg/output"
	"github.com/crowdstrike/gofalcon/falcon/client/container_detections"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/spf13/cobra"
	"k8s.io/kubectl/pkg/util/templates"
)

// NewCmdDetections represents the fcs kubernetes detections command.
func NewCmdDetections(f *factory.Factory) *cobra.Command {
	opts := &detectionsListOptions{Factory: f}

	cmd := &cobra.Command{
		Use:   "detections",
		Short: "List container detections",
		Long:  templates.LongDesc(`List container security detections with optional FQL filtering.`),
		Example: templates.Examples(`
            # List all container detections
            falcon fcs kubernetes detections

            # Filter by severity
            falcon fcs kubernetes detections --filter "severity:'critical'"

            # Filter by detection type
            falcon fcs kubernetes detections --filter "detection_type:'malware'"
        `),
		RunE: func(_ *cobra.Command, _ []string) error {
			return runDetectionsList(opts)
		},
	}

	cmdutil.AddFilterFlag(cmd, &opts.Filter)
	cmdutil.AddPaginationFlags(cmd, &opts.Limit, &opts.Offset, 100)
	cmdutil.AddSortFlag(cmd, &opts.Sort)
	cmdutil.AddOutputFlag(cmd, &opts.Output)
	cmdutil.AddTableFormattingFlags(cmd, &opts.Table)

	return cmd
}

type detectionsListOptions struct {
	Factory *factory.Factory

	Filter string
	Limit  int64
	Offset int64
	Sort   string
	Output string
	Table  cmdutil.TableFormattingOptions
}

func runDetectionsList(opts *detectionsListOptions) error {
	client, err := opts.Factory.FalconClient()
	if err != nil {
		return err
	}

	params := container_detections.NewReadCombinedDetectionsParams()
	params.Limit = &opts.Limit
	params.Offset = &opts.Offset
	if opts.Filter != "" {
		params.Filter = &opts.Filter
	}
	if opts.Sort != "" {
		params.Sort = &opts.Sort
	}

	resp, err := client.ContainerDetections.ReadCombinedDetections(params)
	if err != nil {
		return cmdutil.HandleAPIError(err, "list container detections")
	}

	var resources []*models.ModelsAPICombinedDetections
	if resp.Payload != nil {
		resources = resp.Payload.Resources
	}

	def := &output.TableDefinition{
		Headers: []string{"ID", "NAME", "SEVERITY", "TYPE", "IMAGES", "CONTAINERS", "LAST_DETECTED"},
		RowFunc: func(item any) []string {
			r, ok := item.(*models.ModelsAPICombinedDetections)
			if !ok || r == nil {
				return nil
			}

			return []string{
				deref(r.DetectionID),
				deref(r.DetectionName),
				deref(r.DetectionSeverity),
				deref(r.DetectionType),
				fmtInt64(r.ImagesImpacted),
				fmtInt64(r.ContainersImpacted),
				deref(r.LastDetected),
			}
		},
	}

	tableOpts := opts.Table.ToOutputTableOptions()
	printer := output.NewPrinter(output.Format(opts.Output), def, tableOpts)
	return printer.Print(opts.Factory.IOStreams.Out, resources)
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func fmtInt64(v *int64) string {
	if v == nil {
		return "0"
	}
	return fmt.Sprintf("%d", *v)
}
