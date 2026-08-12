// Package theme is lidersea.com's reading-theme domain: the catalog of
// themes the site serves, the cookie value contract that selects one, and
// the pure document stamp that writes the selected theme onto a shell's
// root element.
//
// The mechanism it exists to make possible is a server-decided theme with
// no first-paint flash and no layout shift. The origin precomputes one
// shell per catalog theme AT CONSTRUCTION, each already carrying its
// data-theme attribute, and a request is answered by choosing precomputed
// bytes — never by editing a document on the request path. The visitor's
// browser therefore parses a document that already declares its theme, so
// the correct palette applies on the first style resolution: there is no
// scripted correction to flash, and because the attribute only selects
// custom-property values, no box can move when it changes.
//
// The package is pure — no HTTP, no I/O, no cookie types — so the server
// layer composes it and every rule here is testable as plain functions.
package theme

import (
	"bytes"
	"strings"
)

// Parse resolves a raw cookie value to a catalog theme. It is deliberately
// total and fail-safe: every value that names no catalog member — absent,
// empty, oversized, mixed case, or hostile — resolves to Default with false,
// so a caller that ignores the boolean still serves a legal theme and no
// visitor-controlled byte can reach a document.
func Parse(value string) (Theme, bool) {
	if value == "" || len(value) > MaxCookieValueBytes {
		return Default, false
	}
	for _, candidate := range Catalog {
		if value == string(candidate) {
			return candidate, true
		}
	}
	return Default, false
}

// Known reports whether t is a catalog member. Stamp refuses everything
// else, so a theme value invented anywhere but Parse can never be written
// into a served document.
func Known(t Theme) bool {
	for _, candidate := range Catalog {
		if t == candidate {
			return true
		}
	}
	return false
}

// Stamp returns document with t written onto its root element as the theme
// attribute. It never mutates its argument, and every byte outside the
// inserted attribute is copied through unchanged, so the stamp is a pure
// function of (document, theme).
//
// It fails closed on anything ambiguous: a theme outside the catalog, a
// document without exactly one <html> element, an unterminated open tag, or
// a root element that already carries the attribute. Callers stamp build
// output during construction, so every one of these is a broken bundle that
// must stop a rollout rather than reach a visitor.
func Stamp(document []byte, t Theme) ([]byte, error) {
	if !Known(t) {
		return nil, ErrUnknownTheme
	}
	start, err := rootElementOffset(document)
	if err != nil {
		return nil, err
	}
	end := bytes.IndexByte(document[start:], '>')
	if end < 0 {
		return nil, ErrRootElementUnterminated
	}
	insertAt := start + len(rootElementOpen)
	if bytes.Contains(document[start:start+end], []byte(Attribute)) {
		return nil, ErrAlreadyStamped
	}
	attribute := []byte(" " + Attribute + `="` + string(t) + `"`)
	stamped := make([]byte, 0, len(document)+len(attribute))
	stamped = append(stamped, document[:insertAt]...)
	stamped = append(stamped, attribute...)
	stamped = append(stamped, document[insertAt:]...)
	return stamped, nil
}

// Variants precomputes one stamped shell per catalog theme. The server calls
// it once, at construction, so serving a themed document costs a map lookup
// and nothing else — no parsing, no concatenation, no allocation on the
// request path. A document that cannot be stamped fails here, before the
// process can report itself ready.
func Variants(document []byte) (map[Theme][]byte, error) {
	variants := make(map[Theme][]byte, len(Catalog))
	for _, candidate := range Catalog {
		stamped, err := Stamp(document, candidate)
		if err != nil {
			return nil, err
		}
		variants[candidate] = stamped
	}
	return variants, nil
}

// rootElementOffset locates the document's single root element open tag. It
// counts DELIMITED occurrences — "<html" followed by whitespace or the tag's
// own '>' — so an element merely starting with the same letters is not a
// root element, and it requires exactly one: zero means the bundle is not a
// document, and more than one means the shell is ambiguous and any stamp
// would be a guess.
func rootElementOffset(document []byte) (int, error) {
	offset, found, searched := 0, -1, 0
	for {
		index := bytes.Index(document[searched:], []byte(rootElementOpen))
		if index < 0 {
			break
		}
		offset = searched + index
		searched = offset + len(rootElementOpen)
		if searched < len(document) && !isTagDelimiter(document[searched]) {
			continue
		}
		if found >= 0 {
			return 0, ErrNoRootElement
		}
		found = offset
	}
	if found < 0 {
		return 0, ErrNoRootElement
	}
	return found, nil
}

// isTagDelimiter reports whether b ends an HTML tag name: the tag's own
// terminator or any character HTML treats as whitespace between a tag name
// and its attributes.
func isTagDelimiter(b byte) bool {
	return b == '>' || b == '/' || strings.IndexByte(" \t\n\r\f", b) >= 0
}
