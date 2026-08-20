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
	"strconv"

	"github.com/crowdstrike/falcon-cli/pkg/cmdutil"
	"github.com/crowdstrike/falcon-cli/pkg/factory"
	"github.com/spf13/cobra"
	"k8s.io/kubectl/pkg/util/templates"
)

var (
	shortDesc = `Inspect cloud compliance posture`
	longDesc  = templates.LongDesc(`
        Inspect cloud compliance posture across frameworks and individual rules.`)
	examples = templates.Examples(`
        # Show posture summaries for all compliance frameworks
        falcon fcs compliance frameworks

        # Show posture summaries for individual compliance rules
        falcon fcs compliance rules
    `)
)

// NewComplianceCmd represents the compliance command group.
func NewComplianceCmd(f *factory.Factory) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "compliance",
		Short:   shortDesc,
		Long:    longDesc,
		Example: examples,
	}

	cmd.AddCommand(
		NewCmdFrameworks(f),
		NewCmdRules(f),
	)
	return cmd
}

func str(p *string) string { return cmdutil.Deref(p) }

func i32(v int32) string {
	return strconv.FormatInt(int64(v), 10)
}

func i32p(p *int32) string {
	if p == nil {
		return ""
	}
	return i32(*p)
}
