// types.go collects the package's type declarations and package-level
// const/var blocks so the theme vocabulary — the catalog, the cookie
// contract, and the stamp's failure modes — can be surveyed in one place.
// Parsing and stamping stay in theme.go.

package theme

import "errors"

// Attribute is the root-element attribute the origin stamps a visitor's
// chosen theme onto. lidersea.com's own contract already names it: the
// stylesheet's theme overrides are `[data-theme]` blocks, so the attribute
// is the seam between a server decision and a stylesheet rule.
const Attribute = "data-theme"

// CookieName is the only cookie this site reads. It carries a display
// preference and nothing else: no identifier, no session, no personal data,
// and no security decision anywhere in the origin consults it. The origin
// never SETS it — the browser writes it when a visitor picks a theme — so
// the response side of this site stays free of cookie state entirely.
const CookieName = "lidersea_theme"

// MaxCookieValueBytes bounds how much of a cookie value Parse will even
// look at. Catalog values are single short words, so anything longer is not
// a preference; refusing early keeps a hostile header cheap to reject.
const MaxCookieValueBytes = 16

// Theme is one reading theme this site serves. The type is closed by
// Catalog: every value that ever reaches a stamp comes from Parse, which
// only ever returns a catalog member, so no visitor-controlled byte can be
// written into a served document.
type Theme string

const (
	// System follows the visitor's operating-system preference through the
	// stylesheet's prefers-color-scheme mapping. It is the default, so a
	// first-time visitor with no cookie is answered with the shell their
	// device already asked for — no flash, no negotiation, no script.
	System Theme = "system"
	// Light is the explicit daylight theme.
	Light Theme = "light"
	// Dark is the explicit low-light theme.
	Dark Theme = "dark"
	// Sepia is the explicit warm low-light theme — the same reading comfort
	// as Dark on a paper-toned surface rather than a cool one. It is a third
	// EXPLICIT choice, not a variant of Dark: a visitor who picks it is
	// answered with it whatever their device prefers.
	Sepia Theme = "sepia"
)

// Default is the theme served when a request expresses no valid preference:
// no cookie, an empty cookie, an oversized cookie, or a value naming no
// catalog member. Every one of those is answered with System rather than a
// guess.
const Default = System

// Catalog is the ordered set of themes the site serves. Order is the order
// the switcher presents them in, and it is the ONLY source of legal theme
// values: Parse rejects everything outside it and Stamp refuses to write
// anything outside it.
var Catalog = []Theme{System, Light, Dark, Sepia}

// Stamp failure modes. A shell that cannot be stamped is a broken build,
// not a request-time condition, so these surface during construction and
// keep the process from becoming ready with an unthemeable document.
var (
	// ErrNoRootElement reports a document with no single <html> element to
	// stamp. Zero occurrences means the bundle is not a document; more than
	// one means the shell is ambiguous and the stamp would be a guess.
	ErrNoRootElement = errors.New("shell has no single <html> element to stamp")
	// ErrRootElementUnterminated reports an <html> open tag with no closing
	// '>', which no complete document can produce.
	ErrRootElementUnterminated = errors.New("shell's <html> element is unterminated")
	// ErrAlreadyStamped reports a shell that already carries the theme
	// attribute. Stamping is a build-output transformation, never a patch of
	// a previously stamped document.
	ErrAlreadyStamped = errors.New("shell already carries the theme attribute")
	// ErrUnknownTheme reports an attempt to stamp a value outside Catalog.
	ErrUnknownTheme = errors.New("theme is not a catalog member")
)

// rootElementOpen is the byte sequence that begins the document's root
// element. The stamp searches for it literally: the shell is this
// repository's own build output, not visitor input, and a literal search
// with an occurrence count is a stronger contract than a permissive parse.
const rootElementOpen = "<html"
