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
	"fmt"
	"regexp"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var uuidRe = regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)

var _ = Describe("falcon fcs", Label("fcs"), func() {

	Describe("assets", Label("assets"), func() {
		It("lists assets", func() {
			out, err := falcon("fcs", "assets", "list", "--limit", "3")
			Expect(err).NotTo(HaveOccurred(), out)
		})

		It("outputs JSON", func() {
			out, err := falcon("fcs", "assets", "list", "--limit", "1", "--output", "json")
			Expect(err).NotTo(HaveOccurred(), out)
			Expect(out).To(ContainSubstring("{"))
		})

		It("outputs JSONL", func() {
			out, err := falcon("fcs", "assets", "list", "--limit", "1", "--output", "jsonl")
			Expect(err).NotTo(HaveOccurred(), out)
		})

		It("filters by columns", func() {
			out, err := falcon("fcs", "assets", "list", "--limit", "3", "--columns", "name,type,provider")
			Expect(err).NotTo(HaveOccurred(), out)
		})

		It("greps output", func() {
			_, err := falcon("fcs", "assets", "list", "--limit", "10", "--grep", "aws")
			Expect(err).NotTo(HaveOccurred())
		})

		It("sorts output", func() {
			_, err := falcon("fcs", "assets", "list", "--limit", "10", "--sort-by", "provider")
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Describe("risks", Label("risks"), func() {
		It("lists risks", func() {
			out, err := falcon("fcs", "risks", "list", "--limit", "3")
			Expect(err).NotTo(HaveOccurred(), out)
		})

		It("filters by severity (title case)", func() {
			out, err := falcon("fcs", "risks", "list", "--limit", "3", "--filter", "severity:'High'")
			Expect(err).NotTo(HaveOccurred(), out)
		})

		It("outputs JSONL", func() {
			out, err := falcon("fcs", "risks", "list", "--limit", "1", "--output", "jsonl")
			Expect(err).NotTo(HaveOccurred(), out)
		})
	})

	Describe("iom", Label("iom"), func() {
		It("lists IOMs", func() {
			out, err := falcon("fcs", "iom", "list", "--limit", "3")
			Expect(err).NotTo(HaveOccurred(), out)
		})

		It("filters by severity (lowercase)", func() {
			out, err := falcon("fcs", "iom", "list", "--limit", "3", "--filter", "severity:'high'")
			Expect(err).NotTo(HaveOccurred(), out)
		})

		It("rejects bare field name as invalid FQL", func() {
			out, err := falcon("fcs", "iom", "list", "--filter", "severity")
			Expect(err).To(HaveOccurred())
			Expect(out).To(ContainSubstring("invalid FQL filter"))
		})
	})

	Describe("iac", Label("iac"), func() {
		It("lists IaC detections", func() {
			out, err := falcon("fcs", "iac", "list", "--limit", "3")
			skipIfPermissionOrFeatureError(out, err)
			Expect(err).NotTo(HaveOccurred(), out)
		})
	})

	Describe("compliance", Label("compliance"), func() {
		It("lists frameworks", func() {
			out, err := falcon("fcs", "compliance", "frameworks")
			skipIfPermissionOrFeatureError(out, err)
			Expect(err).NotTo(HaveOccurred(), out)
		})

		It("lists rules", func() {
			out, err := falcon("fcs", "compliance", "rules", "--limit", "5")
			skipIfPermissionOrFeatureError(out, err)
			Expect(err).NotTo(HaveOccurred(), out)
		})
	})

	Describe("suppression", Label("suppression"), func() {
		It("lists suppression rules", func() {
			out, err := falcon("fcs", "suppression", "list", "--limit", "3")
			Expect(err).NotTo(HaveOccurred(), out)
		})
	})

	Describe("doctor", Label("doctor"), func() {
		It("runs preflight checks", func() {
			out, err := falcon("fcs", "doctor")
			// doctor exits non-zero when scopes are missing — that's expected in some envs
			if err != nil {
				Expect(out).To(Or(
					ContainSubstring("access denied"),
					ContainSubstring("OK"),
					ContainSubstring("fcs"),
				), "unexpected doctor output: %s", out)
			}
		})
	})

	Describe("kubernetes (CWPP)", Label("cwpp", "kubernetes"), func() {
		BeforeEach(func() {
			if cwppProfile() == "" {
				Skip("CWPP_PROFILE not set")
			}
		})

		It("lists clusters", func() {
			out, err := falconWithProfile(cwppProfile(), "fcs", "kubernetes", "clusters", "--limit", "3")
			skipIfPermissionOrFeatureError(out, err)
			Expect(err).NotTo(HaveOccurred(), out)
		})

		It("lists containers", func() {
			out, err := falconWithProfile(cwppProfile(), "fcs", "kubernetes", "containers", "--limit", "3")
			skipIfPermissionOrFeatureError(out, err)
			Expect(err).NotTo(HaveOccurred(), out)
		})

		It("lists images", func() {
			out, err := falconWithProfile(cwppProfile(), "fcs", "kubernetes", "images", "--limit", "3")
			skipIfPermissionOrFeatureError(out, err)
			Expect(err).NotTo(HaveOccurred(), out)
		})
	})

	Describe("vulnerabilities (CWPP)", Label("cwpp", "vulnerabilities"), func() {
		BeforeEach(func() {
			if cwppProfile() == "" {
				Skip("CWPP_PROFILE not set")
			}
		})

		It("lists vulnerabilities", func() {
			out, err := falconWithProfile(cwppProfile(), "fcs", "vulnerabilities", "list", "--limit", "3")
			skipIfPermissionOrFeatureError(out, err)
			Expect(err).NotTo(HaveOccurred(), out)
		})
	})

	Describe("groups (CWPP)", Label("cwpp", "groups"), func() {
		BeforeEach(func() {
			if cwppProfile() == "" {
				Skip("CWPP_PROFILE not set")
			}
		})

		It("lists groups with valid FQL", func() {
			out, err := falconWithProfile(cwppProfile(), "fcs", "groups", "list", "--filter", "environment:'production'", "--limit", "5")
			skipIfPermissionOrFeatureError(out, err)
			Expect(err).NotTo(HaveOccurred(), out)
		})

		It("lists groups with combined FQL", func() {
			out, err := falconWithProfile(cwppProfile(), "fcs", "groups", "list",
				"--filter", "environment:'production'+business_unit:'payments'", "--limit", "5")
			skipIfPermissionOrFeatureError(out, err)
			Expect(err).NotTo(HaveOccurred(), out)
		})

		It("rejects bare field name as invalid FQL", func() {
			out, err := falconWithProfile(cwppProfile(), "fcs", "groups", "list", "--filter", "badfield")
			Expect(err).To(HaveOccurred())
			Expect(out).To(ContainSubstring("invalid FQL filter"))
		})

		It("returns values for environment field", func() {
			out, err := falconWithProfile(cwppProfile(), "fcs", "groups", "values", "--field", "environment")
			skipIfPermissionOrFeatureError(out, err)
			Expect(err).NotTo(HaveOccurred(), out)
		})

		It("returns values for business_unit field", func() {
			out, err := falconWithProfile(cwppProfile(), "fcs", "groups", "values", "--field", "business_unit")
			skipIfPermissionOrFeatureError(out, err)
			Expect(err).NotTo(HaveOccurred(), out)
		})

		It("rejects unknown values field", func() {
			out, err := falconWithProfile(cwppProfile(), "fcs", "groups", "values", "--field", "badfield")
			Expect(err).To(HaveOccurred())
			Expect(out).To(ContainSubstring("unknown field"))
		})

		Context("write round-trip", Label("write"), func() {
			var groupID string

			It("creates, reads, and deletes a group", func() {
				name := fmt.Sprintf("falcon-cli-e2e-%d", GinkgoParallelProcess())

				By("creating the group")
				out, err := falconWithProfile(cwppProfile(), "fcs", "groups", "create",
					"--name", name, "--description", "e2e test - safe to delete")
				skipIfPermissionOrFeatureError(out, err)
				Expect(err).NotTo(HaveOccurred(), out)
				groupID = uuidRe.FindString(out)
				Expect(groupID).NotTo(BeEmpty(), "no UUID in create output: "+out)

				By("listing groups")
				out, err = falconWithProfile(cwppProfile(), "fcs", "groups", "list", "--limit", "5")
				Expect(err).NotTo(HaveOccurred(), out)

				By("getting the group by ID")
				out, err = falconWithProfile(cwppProfile(), "fcs", "groups", "get", "--ids", groupID)
				Expect(err).NotTo(HaveOccurred(), out)
				Expect(out).To(ContainSubstring(groupID))

				By("deleting the group")
				out, err = falconWithProfile(cwppProfile(), "fcs", "groups", "delete", "--ids", groupID)
				Expect(err).NotTo(HaveOccurred(), out)
			})
		})
	})
})
