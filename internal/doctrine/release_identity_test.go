// A second repository pin beside provider neutrality: what a deployed
// workload says about which release it is.
//
// Until this contract a Pod from this chart named its image as
// `repository@sha256:<hex>` and carried no version label. That is a precise
// machine identity and a useless human one — `kubectl describe pod` could not
// tell an operator that the running bytes are release v0.1.9, and neither
// could `kubectl get po -L app.kubernetes.io/version`, because nothing emitted
// that label.
//
// The reference now states both halves, and these pins exist to keep them
// honest about each other:
//
//   - the digest remains mandatory and remains the only thing that resolves.
//     Kubernetes content-addresses it, cosign signs it, and the platform's
//     admission policies verify it. A tag never substitutes for it
//     (platform safety invariant 6, requirement 10 here).
//   - the tag is exactly the release this chart claims to be. The gate's
//     version lock already ties VERSION to the chart version and appVersion;
//     the image tag is the fourth leg, because a reference reading
//     `:v0.1.8@sha256:<v0.1.9 bytes>` would be worse than no tag at all.
//
// Requirement 9 keeps this module standard-library only, so these are byte
// pins over the chart sources rather than a YAML decode — which also means
// what is asserted is exactly what a reviewer reads in the diff.
package doctrine

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// chartSource reads one file from the chart, relative to this package.
func chartSource(t *testing.T, parts ...string) string {
	t.Helper()
	path := filepath.Join(append([]string{"..", "..", "chart"}, parts...)...)
	raw, err := os.ReadFile(path)
	if err != nil {
		// Reduced build contexts do not contain the chart: the image's test
		// stage copies only the module sources and the built frontend assets,
		// so `go test ./...` inside the container has no chart/ to read.
		// Absence is a context capability, NOT a pass — the full-checkout gate
		// runs this file on every pull request and enforces every assertion
		// below. Skipping here and passing here are different outcomes, and
		// only one of them is honest.
		if os.IsNotExist(err) {
			t.Skipf("%s absent from this build context; the full-checkout gate enforces this pin", path)
		}
		t.Fatalf("read %s: %v", path, err)
	}
	return string(raw)
}

// firstScalar returns the value of the first `key:` line at any indentation,
// unquoted. Deliberately minimal — it reads four scalars and nothing else.
func firstScalar(t *testing.T, text, key string) string {
	t.Helper()
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, key+":") {
			return strings.Trim(strings.TrimSpace(strings.TrimPrefix(trimmed, key+":")), `"'`)
		}
	}
	t.Fatalf("chart source has no %q line", key)
	return ""
}

func TestTheImageTagNamesThisChartsOwnRelease(t *testing.T) {
	appVersion := firstScalar(t, chartSource(t, "Chart.yaml"), "appVersion")
	if appVersion == "" {
		t.Fatal("Chart.yaml appVersion is empty")
	}
	// Publication adds the conventional `v` prefix (the platform's ADR 0014);
	// appVersion is the bare SemVer. Deriving the expectation from appVersion
	// keeps this assertion correct at every future release with no edit.
	want := "v" + appVersion
	if got := firstScalar(t, chartSource(t, "values.yaml"), "tag"); got != want {
		t.Errorf(
			"chart/values.yaml image.tag is %q; appVersion %q publishes as %q. "+
				"The tag is what a human reads off the running Pod, so a chart "+
				"that ships another release's name is a legible lie",
			got, appVersion, want,
		)
	}
}

func TestTheReferenceKeepsTheDigestInFrontOfNothing(t *testing.T) {
	deployment := chartSource(t, "templates", "deployment.yaml")
	const want = `image: "{{ .Values.image.repository }}:{{ .Values.image.tag }}@{{ .Values.image.digest }}"`
	if !strings.Contains(deployment, want) {
		t.Errorf("chart/templates/deployment.yaml must render %s", want)
	}
	// The failure mode worth naming: a future edit that "simplifies" the
	// reference by dropping the digest keeps the template rendering and keeps
	// the workload starting, while silently deleting every guarantee the
	// digest carried.
	if strings.Contains(deployment, `{{ .Values.image.tag }}"`) {
		t.Error("a reference that ends at the tag has replaced the digest, not accompanied it")
	}
}

func TestTheSchemaRefusesAFloatingOrAbsentReleaseName(t *testing.T) {
	schema := chartSource(t, "values.schema.json")
	for _, fragment := range []string{
		`"required": ["repository", "tag", "digest", "pullPolicy"]`,
		`"pattern": "^sha256:[0-9a-f]{64}$"`,
		`"pattern": "^v(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)$"`,
	} {
		if !strings.Contains(schema, fragment) {
			t.Errorf(
				"chart/values.schema.json must contain %s. Both values are "+
					"supplied by an override in the cluster, so this schema is "+
					"the first place `latest`, a branch name, or a missing "+
					"digest can be refused",
				fragment,
			)
		}
	}
}

func TestTheSharedLabelsHelperPublishesTheRunningVersion(t *testing.T) {
	helpers := chartSource(t, "templates", "_helpers.tpl")
	const want = `app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}`
	if !strings.Contains(helpers, want) {
		t.Errorf("chart/templates/_helpers.tpl must emit %s", want)
	}
	// Derived from the chart, never handed in. A values-sourced version label
	// could be overridden to disagree with the chart that rendered it, which
	// would reintroduce the lie one layer up.
	if strings.Contains(helpers, "app.kubernetes.io/version: {{ .Values") {
		t.Error("the version label must come from .Chart.AppVersion, not from values")
	}
}

// A Deployment's selector is immutable, and any selector that matched on
// version would stop matching its own Pods one release later. The label is
// metadata only; every selector in this chart writes its keys literally, and
// this proves the shared helper never leaks into one.
func TestVersionIsALabelAndNeverASelectorKey(t *testing.T) {
	selectors := regexp.MustCompile(`(?s)(selector|podSelector):\n(?:\s+matchLabels:\n)?((?:\s{4,}\S[^\n]*\n)+)`)
	for _, name := range []string{"deployment.yaml", "service.yaml", "network-policy.yaml"} {
		text := chartSource(t, "templates", name)
		for _, match := range selectors.FindAllStringSubmatch(text, -1) {
			if strings.Contains(match[2], "app.kubernetes.io/version") {
				t.Errorf(
					"chart/templates/%s selects on app.kubernetes.io/version; a "+
						"version-scoped selector stops matching at the next release",
					name,
				)
			}
		}
		if strings.Contains(text, "matchLabels:\n    {{- include") {
			t.Errorf("chart/templates/%s builds a selector from the labels helper", name)
		}
	}
}
