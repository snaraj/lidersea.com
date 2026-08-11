// media.go builds the canonical media fixtures: tiny deterministic files in
// the digest-immutable layout the media pipeline serves, so every suite
// exercises the same honest content-addressed shapes. Fixture bytes are
// sentinel patterns, not real encoded media — handlers type by extension and
// never sniff — and each fixture's digest really is the SHA-256 of its
// bytes, keeping the URL class truthful inside tests.

package testsupport

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

// MediaFixture is one digest-addressed test asset.
type MediaFixture struct {
	// Name is the served filename, the final URL segment.
	Name string
	// ContentType is the exact Content-Type the pipeline must answer with.
	ContentType string
	// Bytes is the deterministic sentinel content.
	Bytes []byte
	// Digest is the lowercase hex SHA-256 of Bytes — the URL's digest
	// segment and (quoted) the response's strong ETag.
	Digest string
}

// URL returns the fixture's full path in the digest-immutable URL class.
func (f MediaFixture) URL() string {
	return "/media/immutable/" + f.Digest + "/" + f.Name
}

// MediaFixtures returns the canonical fixture set: a small "image" and a
// larger "video" whose 4 KiB size gives Range tests room for start, middle,
// suffix, and multipart slices. Fresh values are returned on every call so a
// test may mutate its copy freely.
func MediaFixtures() []MediaFixture {
	return []MediaFixture{
		newMediaFixture("fixture-hull.avif", "image/avif", sentinelBytes("lidersea-media-fixture:image", 512)),
		newMediaFixture("fixture-walkthrough.mp4", "video/mp4", sentinelBytes("lidersea-media-fixture:video", 4096)),
	}
}

// WriteMediaRoot lays the fixtures out as a media root — <digest>/<name>
// under a fresh temporary directory — and returns the root path for
// MEDIA_ROOT or media configuration.
func WriteMediaRoot(t *testing.T, fixtures []MediaFixture) string {
	t.Helper()
	root := t.TempDir()
	for _, fixture := range fixtures {
		dir := filepath.Join(root, fixture.Digest)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("create fixture digest directory: %v", err)
		}
		if err := os.WriteFile(filepath.Join(dir, fixture.Name), fixture.Bytes, 0o644); err != nil {
			t.Fatalf("write fixture %s: %v", fixture.Name, err)
		}
	}
	return root
}

// newMediaFixture completes a fixture by computing its honest digest.
func newMediaFixture(name, contentType string, data []byte) MediaFixture {
	sum := sha256.Sum256(data)
	return MediaFixture{Name: name, ContentType: contentType, Bytes: data, Digest: hex.EncodeToString(sum[:])}
}

// sentinelBytes builds size deterministic bytes by repeating a labelled
// sentinel, so range assertions can slice exact expected windows.
func sentinelBytes(sentinel string, size int) []byte {
	pattern := []byte(sentinel + "|")
	data := bytes.Repeat(pattern, size/len(pattern)+1)
	return data[:size]
}
