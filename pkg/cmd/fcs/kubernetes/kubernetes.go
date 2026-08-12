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
	"github.com/crowdstrike/falcon-cli/pkg/factory"
	"github.com/spf13/cobra"
	"k8s.io/kubectl/pkg/util/templates"
)

// NewKubernetesCmd represents the kubernetes command group.
func NewKubernetesCmd(f *factory.Factory) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "kubernetes",
		Short: "Manage Kubernetes security resources",
		Long:  templates.LongDesc(`Query Kubernetes containers, clusters, and images protected by Falcon.`),
		Example: templates.Examples(`
            # List running containers
            falcon fcs kubernetes containers

            # List clusters
            falcon fcs kubernetes clusters
        `),
	}

	cmd.AddCommand(
		NewCmdContainers(f),
		NewCmdClusters(f),
		NewCmdImages(f),
	)
	return cmd
}

func strp(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}
