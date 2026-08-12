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

package fcs

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/crowdstrike/falcon-cli/pkg/factory"
	"github.com/crowdstrike/gofalcon/falcon/client/cloud_policies"
	"github.com/crowdstrike/gofalcon/falcon/client/cloud_security_assets"
	"github.com/crowdstrike/gofalcon/falcon/client/container_images"
	"github.com/crowdstrike/gofalcon/falcon/client/container_vulnerabilities"
	"github.com/crowdstrike/gofalcon/falcon/client/cspg_iacapi"
	"github.com/crowdstrike/gofalcon/falcon/client/kubernetes_protection"
	"github.com/spf13/cobra"
	"k8s.io/kubectl/pkg/util/templates"
)

type probeStatus string

const (
	probeOK           probeStatus = "ok"
	probeAccessDenied probeStatus = "access_denied"
	probeNotFound     probeStatus = "not_provisioned"
	probeError        probeStatus = "error"
)

type probeResult struct {
	Command string      `json:"command"`
	Scope   string      `json:"scope"`
	Status  probeStatus `json:"status"`
	Detail  string      `json:"detail,omitempty"`
}

type probeSpec struct {
	Command string
	Scope   string
	fn      func() probeStatus
}

// NewCmdDoctor returns a command that probes each fcs scope group and reports
// which commands will work with the current API credentials.
func NewCmdDoctor(f *factory.Factory) *cobra.Command {
	var outputFmt string

	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Check API client permissions for all fcs commands",
		Long: templates.LongDesc(`
			Probe each Falcon Cloud Security API endpoint with the current credentials
			and report which commands will work, which are missing scopes, and which
			require a feature that is not provisioned in this tenant.

			This is the OAuth2 equivalent of the Falcon console permission checker.
			It makes lightweight read requests (limit=1) to one representative endpoint
			per scope group.`),
		Example: templates.Examples(`
			# Check all fcs command permissions
			falcon fcs doctor

			# Check with a specific profile
			falcon fcs doctor --profile prod

			# Machine-readable output
			falcon fcs doctor --output json
		`),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDoctor(f, outputFmt)
		},
	}

	cmd.Flags().StringVarP(&outputFmt, "output", "o", "table", "Output format: table or json")
	return cmd
}

func runDoctor(f *factory.Factory, outputFmt string) error {
	cfg, err := f.Config()
	if err != nil {
		return err
	}

	falconClient, err := f.FalconClient()
	if err != nil {
		return err
	}

	one := int64(1)

	probes := []probeSpec{
		{
			Command: "fcs assets list / risks list / iom list",
			Scope:   "CSPM Assessment: Read",
			fn: func() probeStatus {
				p := cloud_security_assets.NewCloudSecurityAssetsQueriesParams()
				p.Limit = &one
				_, err := falconClient.CloudSecurityAssets.CloudSecurityAssetsQueries(p)
				return classifyErr(err)
			},
		},
		{
			Command: "fcs iac list",
			Scope:   "IaC Security: Read",
			fn: func() probeStatus {
				p := cspg_iacapi.NewCombinedDetectionsParams()
				p.Limit = &one
				_, err := falconClient.CspgIacapi.CombinedDetections(p)
				return classifyErr(err)
			},
		},
		{
			Command: "fcs suppression list / groups list",
			Scope:   "CSPM Registration: Read",
			fn: func() probeStatus {
				p := cloud_policies.NewQuerySuppressionRulesParams()
				p.Limit = &one
				_, err := falconClient.CloudPolicies.QuerySuppressionRules(p)
				return classifyErr(err)
			},
		},
		{
			Command: "fcs compliance frameworks / rules",
			Scope:   "CSPM Registration: Read + Compliance posture feature",
			fn: func() probeStatus {
				// Auto-discover framework IDs first; 404 = feature not provisioned
				p := cloud_policies.NewQueryComplianceFrameworksParams()
				p.Limit = &one
				_, err := falconClient.CloudPolicies.QueryComplianceFrameworks(p)
				return classifyErr(err)
			},
		},
		{
			Command: "fcs kubernetes clusters / containers",
			Scope:   "Falcon Container Image: Read",
			fn: func() probeStatus {
				p := kubernetes_protection.NewClusterCombinedParams()
				p.Limit = &one
				_, err := falconClient.KubernetesProtection.ClusterCombined(p)
				return classifyErr(err)
			},
		},
		{
			Command: "fcs kubernetes images",
			Scope:   "Falcon Container Image: Read",
			fn: func() probeStatus {
				p := container_images.NewCombinedImageDetailParams()
				p.Limit = &one
				_, err := falconClient.ContainerImages.CombinedImageDetail(p)
				return classifyErr(err)
			},
		},
		{
			Command: "fcs vulnerabilities list",
			Scope:   "Falcon Container Image: Read",
			fn: func() probeStatus {
				p := container_vulnerabilities.NewReadCombinedVulnerabilitiesParams()
				p.Limit = &one
				_, err := falconClient.ContainerVulnerabilities.ReadCombinedVulnerabilities(p)
				return classifyErr(err)
			},
		},
	}

	// Run all probes
	results := make([]probeResult, 0, len(probes))
	for _, p := range probes {
		status := p.fn()
		detail := ""
		switch status {
		case probeAccessDenied:
			detail = "HTTP 403 — add scope or check CWPP product provisioning"
		case probeNotFound:
			detail = "HTTP 404 — feature not provisioned in this tenant"
		case probeError:
			detail = "unexpected error"
		}
		results = append(results, probeResult{
			Command: p.Command,
			Scope:   p.Scope,
			Status:  status,
			Detail:  detail,
		})
	}

	if outputFmt == "json" {
		return printDoctorJSON(f, results)
	}

	// Print client ID prefix for context
	if cfg.ClientID != "" {
		fmt.Fprintf(f.IOStreams.Out, "\nChecking permissions for client: %s...\n", cfg.ClientID[:min(8, len(cfg.ClientID))])
	}
	return printDoctorTable(f, results)
}

func classifyErr(err error) probeStatus {
	if err == nil {
		return probeOK
	}
	msg := strings.ToLower(err.Error())
	if containsAny(msg, "403", "forbidden", "access denied", "scope not permitted") {
		return probeAccessDenied
	}
	if containsAny(msg, "404", "not found") {
		return probeNotFound
	}
	return probeError
}

func containsAny(s string, keywords ...string) bool {
	for _, k := range keywords {
		if strings.Contains(s, k) {
			return true
		}
	}
	return false
}

func printDoctorTable(f *factory.Factory, results []probeResult) error {
	out := f.IOStreams.Out

	// Header
	fmt.Fprintf(out, "\n")

	// Column widths
	const (
		cmdWidth   = 42
		scopeWidth = 42
		statWidth  = 8
	)

	header := fmt.Sprintf("%-*s  %-*s  %s", cmdWidth, "Command", scopeWidth, "Scope required", "Status")
	fmt.Fprintln(out, header)
	fmt.Fprintln(out, strings.Repeat("─", len(header)+4))

	missingScopes := map[string][]string{} // scope → commands

	for _, r := range results {
		icon := statusIcon(r.Status)
		cmd := truncateTo(r.Command, cmdWidth)
		scope := truncateTo(r.Scope, scopeWidth)
		fmt.Fprintf(out, "%-*s  %-*s  %s\n", cmdWidth, cmd, scopeWidth, scope, icon)

		if r.Status == probeAccessDenied {
			// Group by base scope (strip "..." suffix from long scopes)
			basescope := strings.Split(r.Scope, " +")[0]
			missingScopes[basescope] = append(missingScopes[basescope], r.Command)
		}
	}

	fmt.Fprintln(out, "")

	if len(missingScopes) > 0 {
		fmt.Fprintln(out, "Missing scopes — add at https://falcon.crowdstrike.com/api-clients-and-keys:")
		for scope, cmds := range missingScopes {
			fmt.Fprintf(out, "  • %s\n", scope)
			fmt.Fprintf(out, "    Commands: %s\n", strings.Join(cmds, ", "))
		}
		fmt.Fprintln(out, "")
		fmt.Fprintln(out, "  Note: If the scope is already enabled, the Falcon Cloud Workload Protection")
		fmt.Fprintln(out, "  (CWPP) product may not be provisioned in this tenant.")
		fmt.Fprintln(out, "  Contact your Falcon admin to verify product entitlements.")
		fmt.Fprintln(out, "")
	}

	// Summary line
	ok, denied, notFound, errCount := 0, 0, 0, 0
	for _, r := range results {
		switch r.Status {
		case probeOK:
			ok++
		case probeAccessDenied:
			denied++
		case probeNotFound:
			notFound++
		default:
			errCount++
		}
	}
	fmt.Fprintf(out, "Results: ✅ %d available  ❌ %d access denied  ⚠️  %d not provisioned\n\n", ok, denied, notFound+errCount)
	return nil
}

func printDoctorJSON(f *factory.Factory, results []probeResult) error {
	enc := json.NewEncoder(f.IOStreams.Out)
	enc.SetIndent("", "  ")
	return enc.Encode(results)
}

func statusIcon(s probeStatus) string {
	switch s {
	case probeOK:
		return "✅"
	case probeAccessDenied:
		return "❌"
	case probeNotFound:
		return "⚠️ "
	default:
		return "⚠️ "
	}
}

func truncateTo(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}
