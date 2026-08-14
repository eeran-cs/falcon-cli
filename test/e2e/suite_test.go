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

// Package e2e_test exercises fcs commands end-to-end using in-process cobra
// execution against an httptest.Server that replays fixture JSON. No network
// calls, no credentials, no pre-built binary required.
package e2e_test

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	httptransport "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
	openapi "github.com/go-openapi/runtime"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/crowdstrike/falcon-cli/pkg/cmd/fcs"
	"github.com/crowdstrike/falcon-cli/pkg/config"
	"github.com/crowdstrike/falcon-cli/pkg/factory"
	"github.com/crowdstrike/falcon-cli/pkg/iostreams"
	"github.com/crowdstrike/gofalcon/falcon/client"
)

func TestE2E(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "falcon fcs e2e")
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// testdataPath resolves a fixture file under testdata/.
func testdataPath(name string) string {
	return filepath.Join("testdata", name)
}

// mustReadFixture reads a testdata file or fails the test.
func mustReadFixture(name string) []byte {
	data, err := os.ReadFile(testdataPath(name))
	Expect(err).NotTo(HaveOccurred(), "fixture %s", name)
	return data
}

// route is a single endpoint mapping for the mock server.
type route struct {
	method  string
	prefix  string
	fixture string
	status  int
}

// newMockServer creates an httptest.Server backed by a list of routes.
// Routes are matched by method + path prefix (first match wins).
func newMockServer(routes []route) *httptest.Server {
	mux := http.NewServeMux()

	// Fallback handler for unmatched routes
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, rt := range routes {
			if r.Method == rt.method && strings.HasPrefix(r.URL.Path, rt.prefix) {
				status := rt.status
				if status == 0 {
					status = http.StatusOK
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(status)
				data := mustReadFixture(rt.fixture)
				_, _ = w.Write(data)
				return
			}
		}
		// No match — return 404
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"errors":[{"message":"not found"}]}`))
	})
	mux.Handle("/", handler)
	return httptest.NewServer(mux)
}

// newTestFactory creates a Factory wired to the given httptest.Server.
// Returns the factory and the stdout buffer for assertion.
func newTestFactory(server *httptest.Server) (*factory.Factory, *bytes.Buffer) {
	var stdout bytes.Buffer

	// Build a go-openapi transport pointing at the test server
	u := server.URL
	host := strings.TrimPrefix(u, "http://")
	transport := httptransport.New(host, "/", []string{"http"})
	transport.Transport = server.Client().Transport
	// Ensure JSON consumer is used for all responses
	transport.Consumers["application/json"] = openapi.JSONConsumer()
	transport.Producers["application/json"] = openapi.JSONProducer()

	falconClient := client.New(transport, strfmt.Default)

	f := &factory.Factory{
		IOStreams: &iostreams.IOStreams{
			In:     io.NopCloser(strings.NewReader("")),
			Out:    &stdout,
			ErrOut: &stdout,
		},
		Config: func() (config.Config, error) {
			return config.Config{
				ClientID:     "test-client-id-1234",
				ClientSecret: "test-secret",
			}, nil
		},
		FalconClient: func() (*client.CrowdStrikeAPISpecification, error) {
			return falconClient, nil
		},
	}

	return f, &stdout
}

// runFCS executes an fcs subcommand in-process and returns the combined output.
func runFCS(f *factory.Factory, stdout *bytes.Buffer, args ...string) (string, error) {
	stdout.Reset()
	cmd := fcs.NewFCSCmd(f)
	cmd.SetArgs(args)
	// Silence usage/error printing so we only get our output
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	err := cmd.Execute()
	return stdout.String(), err
}
