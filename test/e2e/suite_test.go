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
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestE2E(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "falcon fcs e2e")
}

var _ = BeforeSuite(func() {
	// Require a runnable binary
	bin := falconBin()
	if _, err := exec.LookPath(bin); err != nil {
		if _, err2 := os.Stat(bin); err2 != nil {
			Skip("falcon binary not found — run 'make build' first or set FALCON_BIN")
		}
	}

	// Require credentials or a config file
	hasEnvCreds := os.Getenv("FALCON_CLIENT_ID") != "" && os.Getenv("FALCON_CLIENT_SECRET") != ""
	configFile := filepath.Join(os.Getenv("HOME"), ".falcon", "config.yaml")
	_, configErr := os.Stat(configFile)
	hasConfigFile := configErr == nil
	if !hasEnvCreds && !hasConfigFile {
		Skip("e2e tests require FALCON_CLIENT_ID and FALCON_CLIENT_SECRET or a config file at ~/.falcon/config.yaml")
	}
})

// falconBin returns the path to the falcon binary under test.
// Resolved from FALCON_BIN env var, then ./falcon, then PATH.
func falconBin() string {
	if b := os.Getenv("FALCON_BIN"); b != "" {
		return b
	}
	if _, err := os.Stat("../../falcon"); err == nil {
		return "../../falcon"
	}
	if b, err := exec.LookPath("falcon"); err == nil {
		return b
	}
	return "falcon"
}

// cwppProfile returns the CWPP-provisioned profile name from CWPP_PROFILE env var.
// Empty string means CWPP tests should be skipped.
func cwppProfile() string {
	return os.Getenv("CWPP_PROFILE")
}

// falcon runs the falcon binary with the given args and returns stdout+stderr combined.
func falcon(args ...string) (string, error) {
	cmd := exec.Command(falconBin(), args...) //nolint:gosec
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// falconWithProfile runs the falcon binary with -p <profile> prepended to args.
func falconWithProfile(profile string, args ...string) (string, error) {
	full := append([]string{"-p", profile}, args...)
	return falcon(full...)
}

// isPermissionError returns true when the output contains a 403/scope error.
func isPermissionError(out string) bool {
	for _, kw := range []string{"403", "access denied", "scope not permitted", "Forbidden"} {
		if strings.Contains(strings.ToLower(out), strings.ToLower(kw)) {
			return true
		}
	}
	return false
}

// isFeatureError returns true when output indicates a missing feature/404.
func isFeatureError(out string) bool {
	for _, kw := range []string{"404", "feature not available", "not provisioned", "not found"} {
		if strings.Contains(strings.ToLower(out), strings.ToLower(kw)) {
			return true
		}
	}
	return false
}

// skipIfPermissionOrFeatureError skips the current spec if the output looks like
// a known API limitation (missing scope or feature not provisioned).
func skipIfPermissionOrFeatureError(out string, err error) {
	if err == nil {
		return
	}
	if isPermissionError(out) {
		Skip("missing API scope: " + firstLine(out))
	}
	if isFeatureError(out) {
		Skip("feature not provisioned or no data: " + firstLine(out))
	}
}

func firstLine(s string) string {
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			return line
		}
	}
	return s
}
