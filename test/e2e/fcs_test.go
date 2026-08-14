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

package e2e_test

import (
	"net/http"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("falcon fcs", Label("fcs"), func() {

	Describe("assets", Label("assets"), func() {
		var routes []route

		BeforeEach(func() {
			routes = []route{
				{method: http.MethodGet, prefix: "/cloud-security-assets/queries/resources/v1", fixture: "assets_query.json"},
				{method: http.MethodGet, prefix: "/cloud-security-assets/entities/resources/v1", fixture: "assets_entities.json"},
			}
		})

		It("lists assets in table format", func() {
			server := newMockServer(routes)
			defer server.Close()
			f, stdout := newTestFactory(server)

			out, err := runFCS(f, stdout, "assets", "list", "--limit", "3")
			Expect(err).NotTo(HaveOccurred(), out)
			Expect(out).To(ContainSubstring("my-ec2-instance"))
			Expect(out).To(ContainSubstring("aws"))
			Expect(out).To(ContainSubstring("azure"))
		})

		It("outputs JSON", func() {
			server := newMockServer(routes)
			defer server.Close()
			f, stdout := newTestFactory(server)

			out, err := runFCS(f, stdout, "assets", "list", "--limit", "1", "--output", "json")
			Expect(err).NotTo(HaveOccurred(), out)
			Expect(out).To(ContainSubstring(`"resource_name"`))
		})

		It("outputs JSONL", func() {
			server := newMockServer(routes)
			defer server.Close()
			f, stdout := newTestFactory(server)

			out, err := runFCS(f, stdout, "assets", "list", "--limit", "1", "--output", "jsonl")
			Expect(err).NotTo(HaveOccurred(), out)
		})

		It("filters by columns", func() {
			server := newMockServer(routes)
			defer server.Close()
			f, stdout := newTestFactory(server)

			out, err := runFCS(f, stdout, "assets", "list", "--limit", "3", "--columns", "name,type,provider")
			Expect(err).NotTo(HaveOccurred(), out)
			Expect(out).To(ContainSubstring("NAME"))
		})

		It("greps output", func() {
			server := newMockServer(routes)
			defer server.Close()
			f, stdout := newTestFactory(server)

			out, err := runFCS(f, stdout, "assets", "list", "--limit", "10", "--grep", "aws")
			Expect(err).NotTo(HaveOccurred(), out)
			Expect(out).To(ContainSubstring("aws"))
			Expect(out).NotTo(ContainSubstring("azure"))
		})

		It("sorts output", func() {
			server := newMockServer(routes)
			defer server.Close()
			f, stdout := newTestFactory(server)

			out, err := runFCS(f, stdout, "assets", "list", "--limit", "10", "--sort-by", "provider")
			Expect(err).NotTo(HaveOccurred(), out)
		})
	})

	Describe("iom", Label("iom"), func() {
		It("lists IOMs", func() {
			server := newMockServer([]route{
				{method: http.MethodGet, prefix: "/cloud-security-evaluations/queries/ioms/v1", fixture: "iom_query.json"},
				{method: http.MethodGet, prefix: "/cloud-security-evaluations/entities/ioms/v1", fixture: "iom_entities.json"},
			})
			defer server.Close()
			f, stdout := newTestFactory(server)

			out, err := runFCS(f, stdout, "iom", "list", "--limit", "3")
			Expect(err).NotTo(HaveOccurred(), out)
			Expect(out).To(ContainSubstring("rule-abc-123"))
			Expect(out).To(ContainSubstring("high"))
		})

		It("rejects bare field name as invalid FQL", func() {
			server := newMockServer(nil)
			defer server.Close()
			f, stdout := newTestFactory(server)

			_, err := runFCS(f, stdout, "iom", "list", "--filter", "severity")
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("invalid FQL filter"))
		})
	})

	Describe("suppression", Label("suppression"), func() {
		It("lists suppression rules", func() {
			server := newMockServer([]route{
				{method: http.MethodGet, prefix: "/cloud-policies/queries/suppression-rules/v1", fixture: "suppression_query.json"},
				{method: http.MethodGet, prefix: "/cloud-policies/entities/suppression-rules/v1", fixture: "suppression_entities.json"},
			})
			defer server.Close()
			f, stdout := newTestFactory(server)

			out, err := runFCS(f, stdout, "suppression", "list", "--limit", "3")
			Expect(err).NotTo(HaveOccurred(), out)
		})
	})

	Describe("groups", Label("groups"), func() {
		It("lists groups", func() {
			server := newMockServer([]route{
				{method: http.MethodGet, prefix: "/cloud-security/combined/cloud-groups/v1", fixture: "groups_list.json"},
			})
			defer server.Close()
			f, stdout := newTestFactory(server)

			out, err := runFCS(f, stdout, "groups", "list", "--limit", "5")
			Expect(err).NotTo(HaveOccurred(), out)
			Expect(out).To(ContainSubstring("production-group"))
		})

		It("rejects bare field name as invalid FQL", func() {
			server := newMockServer(nil)
			defer server.Close()
			f, stdout := newTestFactory(server)

			_, err := runFCS(f, stdout, "groups", "list", "--filter", "badfield")
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("invalid FQL filter"))
		})

		Context("write round-trip", Label("write"), func() {
			It("creates, gets, and deletes a group", func() {
				server := newMockServer([]route{
					{method: http.MethodPost, prefix: "/cloud-security/entities/cloud-groups/v1", fixture: "groups_create.json", status: http.StatusOK},
					{method: http.MethodGet, prefix: "/cloud-security/entities/cloud-groups/v1", fixture: "groups_get.json"},
					{method: http.MethodDelete, prefix: "/cloud-security/entities/cloud-groups/v1", fixture: "groups_delete.json"},
				})
				defer server.Close()
				f, stdout := newTestFactory(server)

				By("creating the group")
				out, err := runFCS(f, stdout, "groups", "create",
					"--name", "falcon-cli-e2e-1", "--description", "e2e test - safe to delete")
				Expect(err).NotTo(HaveOccurred(), out)
				Expect(out).To(ContainSubstring("660e8400"))

				By("getting the group by ID")
				out, err = runFCS(f, stdout, "groups", "get", "--ids", "660e8400-e29b-41d4-a716-446655440001")
				Expect(err).NotTo(HaveOccurred(), out)
				Expect(out).To(ContainSubstring("falcon-cli-e2e-1"))

				By("deleting the group")
				out, err = runFCS(f, stdout, "groups", "delete", "--ids", "660e8400-e29b-41d4-a716-446655440001")
				Expect(err).NotTo(HaveOccurred(), out)
			})
		})
	})

	Describe("doctor", Label("doctor"), func() {
		It("reports probe results", func() {
			// Doctor probes multiple endpoints — serve all as 200 with generic JSON
			server := newMockServer([]route{
				{method: http.MethodGet, prefix: "/", fixture: "assets_query.json"},
			})
			defer server.Close()
			f, stdout := newTestFactory(server)

			out, err := runFCS(f, stdout, "doctor")
			Expect(err).NotTo(HaveOccurred(), out)
			Expect(out).To(ContainSubstring("✅"))
			Expect(out).To(ContainSubstring("available"))
		})

		It("outputs JSON", func() {
			server := newMockServer([]route{
				{method: http.MethodGet, prefix: "/", fixture: "assets_query.json"},
			})
			defer server.Close()
			f, stdout := newTestFactory(server)

			out, err := runFCS(f, stdout, "doctor", "--output", "json")
			Expect(err).NotTo(HaveOccurred(), out)
			Expect(out).To(ContainSubstring(`"status"`))
		})
	})
})
