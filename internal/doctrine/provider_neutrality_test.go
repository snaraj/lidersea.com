// provider_neutrality_test pins owner requirement R9: the origin is
// provider-neutral. It speaks standard HTTP (RFC 9110/9111) only; ingress,
// DNS, edge, and access are injected deployment concerns. Deployment-provider
// names may therefore appear in exactly one sanctioned location — the chart's
// values.yaml ingress defaults, the provider binding point — and never in
// application code, frontend source, or chart templates. This test fails
// closed against coupling creep in every future change.

package doctrine

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// providerMarks are the deployment-provider names banned from the neutral
// trees, matched case-insensitively. Each needle is assembled from fragments
// so this file never contains the banned spelling itself and can live inside
// a scanned tree; the connector-daemon form is listed explicitly even though
// the base name subsumes it, so a failure names the exact coupling found.
var providerMarks = []string{
	"cloud" + "flare",  // the current edge provider's name
	"cloud" + "flared", // its tunnel connector daemon
}

// neutralTrees are the module-relative roots that must stay provider-neutral.
// chart/values.yaml is deliberately absent: its ingress defaults are the one
// sanctioned provider binding point.
var neutralTrees = []string{
	"cmd",
	"internal",
	filepath.Join("frontend", "src"),
	filepath.Join("chart", "templates"),
}

// TestProviderNeutrality walks every neutral tree and requires zero
// occurrences of any provider mark, in any casing, in any file.
func TestProviderNeutrality(t *testing.T) {
	t.Parallel()
	root := moduleRoot(t)
	for _, tree := range neutralTrees {
		t.Run(tree, func(t *testing.T) {
			t.Parallel()
			// Reduced build contexts (the image test stage prunes frontend
			// sources after the asset build and never copies the chart) cannot
			// scan trees they do not contain. Absence is a context capability,
			// not a pass - the full-checkout CI job enforces this pin on every
			// tree, and any tree that IS present is still scanned here.
			if _, statErr := os.Stat(filepath.Join(root, tree)); os.IsNotExist(statErr) {
				t.Skipf("%s absent from this build context; the full-checkout gate enforces this pin", tree)
			}
			walkErr := filepath.WalkDir(filepath.Join(root, tree), func(path string, entry fs.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if entry.IsDir() {
					return nil
				}
				data, readErr := os.ReadFile(path)
				if readErr != nil {
					return readErr
				}
				content := strings.ToLower(string(data))
				for _, mark := range providerMarks {
					if strings.Contains(content, mark) {
						t.Errorf("%s contains the provider name %q: the origin is provider-neutral (R9), and chart/values.yaml ingress defaults are the only sanctioned location for a provider name — override values there; never wire a provider into code or templates", path, mark)
					}
				}
				return nil
			})
			if walkErr != nil {
				t.Fatalf("walk %s: %v", tree, walkErr)
			}
		})
	}
}

// moduleRoot ascends from the test's working directory to the go.mod
// boundary, so the walk covers the repository no matter where go test runs.
func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found above the test directory")
		}
		dir = parent
	}
}
