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
	"github.com/crowdstrike/falcon-cli/pkg/factory"
	"github.com/spf13/cobra"
	"k8s.io/kubectl/pkg/util/templates"
)

// NewRegistrationCmd represents the fcs registration command group.
func NewRegistrationCmd(f *factory.Factory) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "registration",
		Short: "Manage cloud account registrations",
		Long: templates.LongDesc(`
            Manage Falcon Cloud Security cloud account registrations.
            Register, update, and remove AWS, Azure, GCP, and OCI accounts.`),
		Example: templates.Examples(`
            # List AWS accounts
            falcon fcs registration aws list

            # Register a new AWS account
            falcon fcs registration aws create --account-id 123456789012

            # Delete an AWS account registration
            falcon fcs registration aws delete --ids <id>
        `),
	}

	cmd.AddCommand(
		NewAWSCmd(f),
		NewAzureCmd(f),
		NewGCPCmd(f),
		NewOCICmd(f),
	)
	return cmd
}
