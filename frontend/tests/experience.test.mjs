import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const [fallback, component, styles, themeSource] = await Promise.all([
  readFile(new URL('../index.html', import.meta.url), 'utf8'),
  readFile(new URL('../src/App.svelte', import.meta.url), 'utf8'),
  readFile(new URL('../src/styles.css', import.meta.url), 'utf8'),
  readFile(new URL('../../internal/theme/types.go', import.meta.url), 'utf8'),
]);

const sources = { fallback, component, styles };

// Comments explain the rules and sometimes have to name the very patterns
// those rules ban, so every source-fact assertion reads the code alone.
const stylesCode = styles.replace(/\/\*[\s\S]*?\*\//g, '');

// Comments and string literals are not code, and an assertion about code
// that reads either is not testing what its message says. The delta review
// proved both directions on the previous spelling of this file: '/*' and
// '*/' in two string literals spliced two function bodies together, which
// revived a repaired bug at 14/14 green, while `const s = "}"` in ordinary
// correct code produced a FALSE RED.
//
// So the component is read through two offset-preserving masks. Both blank
// comments; the SHAPE additionally blanks the contents of string and
// template literals, but only inside <script>, because outside it the
// quotes are markup attribute delimiters rather than JavaScript strings and
// blanking them would hide the markup this file has to read.
function maskComponent(source, blankScriptStrings) {
  const out = source.split('');
  const scriptStart = source.indexOf('>', source.indexOf('<script')) + 1;
  const scriptEnd = source.indexOf('</script>');
  const blank = (from, to) => {
    for (let k = from; k < to && k < out.length; k += 1) if (out[k] !== '\n') out[k] = ' ';
  };
  let i = 0;
  while (i < source.length) {
    const quote = source[i];
    // Strings are ALWAYS walked, never only when they are being blanked.
    // The previous version gated the whole quote branch on the caller's
    // request, so the code mask walked straight into a string and treated
    // `const opener = '/*';` as the start of a comment — a FALSE RED on
    // ordinary correct code, which is the worse half of getting this wrong.
    if (quote === '"' || quote === "'" || quote === '`') {
      let k = i + 1;
      while (k < source.length) {
        if (source[k] === '\\') { k += 2; continue; }
        if (source[k] === quote) break;
        k += 1;
      }
      if (blankScriptStrings && i > scriptStart && i < scriptEnd) blank(i + 1, k);
      i = k + 1;
      continue;
    }
    const pair = source.slice(i, i + 2);
    if (pair === '/*') {
      const end = source.indexOf('*/', i + 2);
      const stop = end < 0 ? source.length : end + 2;
      blank(i, stop);
      i = stop;
      continue;
    }
    if (pair === '//') {
      let stop = source.indexOf('\n', i);
      if (stop < 0) stop = source.length;
      blank(i, stop);
      i = stop;
      continue;
    }
    i += 1;
  }
  return out.join('');
}
const componentCode = maskComponent(component, false);
const componentShape = maskComponent(component, true);

// The brace-matched block that follows a marker, located and matched in the
// SHAPE so neither a decoy marker in a string nor a brace in one can move
// it. Used to ask whether a handler CALLS something, which a windowed regex
// cannot answer.
function blockAfter(marker, opener = '{', content = false) {
  const closer = opener === '[' ? ']' : '}';
  const start = componentShape.indexOf(marker);
  assert.notEqual(start, -1, `the component has no ${marker}`);
  const open = componentShape.indexOf(opener, start + marker.length - 1);
  assert.notEqual(open, -1, `${marker} opens no ${opener}${closer} block`);
  let depth = 0;
  for (let i = open; i < componentShape.length; i += 1) {
    if (componentShape[i] === opener) depth += 1;
    else if (componentShape[i] === closer) {
      depth -= 1;
      // Offsets are preserved by the mask, so the SHAPE locates the span and
      // the CODE supplies its text: structure is read where strings cannot
      // interfere, content is read where strings are still real.
      if (depth === 0) {
        // Shape by default: an assertion about a CALL must not be satisfied
        // by a string that merely spells one. `const why = 'trigger?.focus()'`
        // survived the previous head for exactly that reason. Content is
        // requested explicitly, and only where real string values are the
        // thing being read — the switcher's option ids.
        return content ? componentCode.slice(open + 1, i) : componentShape.slice(open + 1, i);
      }
    }
  }
  return assert.fail(`${marker} has an unbalanced ${opener}${closer} block`);
}

// Every theme the ORIGIN can stamp must be one this stylesheet paints, and
// exactly one — the device-following mode — resolves through the
// prefers-color-scheme mapping instead of a block of its own. A fifth theme
// with no block would otherwise simply fall out of every loop below, which
// is precisely how an unvalidated palette shipped green.
function assertCatalogIsFullyStamped() {
  const unblocked = catalogThemes.filter((theme) => !themeBlockPattern(theme).test(stylesCode));
  assert.deepEqual(
    unblocked.length,
    1,
    `${unblocked.join(', ') || 'no theme'} has no [data-theme] block; exactly one catalog theme (the one that follows the device) may resolve through prefers-color-scheme`
  );
  assert.ok(
    stampedThemes.length >= 2,
    `only ${stampedThemes.length} catalog themes have a [data-theme] block`
  );
}

// THE CATALOG IS THE ORIGIN'S, not the stylesheet's and not the switcher's.
// Deriving it from either presentation file was the previous repair and it
// was not enough: both derivations failed SYMMETRICALLY on a double-quoted
// attribute selector — which is Prettier's default output — so the
// cross-check could not see the disagreement and a fifth theme at 1.00:1
// shipped with the whole gate green. internal/theme/types.go is what the
// server actually stamps, so it is the only non-circular anchor, and
// AGENTS.md agrees: "Adding a theme means adding a catalog entry, its
// [data-theme] token block, and its switcher option."
function catalogFromGo(source) {
  const values = new Map();
  for (const [, ident, value] of source.matchAll(/(\w+)\s+Theme\s*=\s*"([^"]+)"/g)) {
    values.set(ident, value);
  }
  // Extension is the SILENT direction: `Catalog = append(Catalog, Amber)` in
  // an init() serves and ETags a fifth theme while this literal still reads
  // four, so the frontend validates a catalog the origin no longer has.
  // Shrinking and reassignment are already loud; this closes the quiet one.
  assert.doesNotMatch(
    source,
    /Catalog\s*=\s*append\(/,
    'Catalog is extended at run time; the frontend reads the literal, so the two would silently disagree'
  );
  const list = /var\s+Catalog\s*=\s*\[\]Theme\{([^}]*)\}/.exec(source);
  assert.ok(list, 'internal/theme/types.go declares no Catalog for the frontend to follow');
  const names = list[1].split(',').map((part) => part.trim()).filter(Boolean);
  assert.ok(names.length >= 3, `Catalog lists only ${names.length} themes; it cannot have shrunk this far`);
  return names.map((name) => {
    const value = values.get(name);
    assert.ok(value, `Catalog names ${name}, which is not a Theme constant in the same file`);
    return value;
  });
}
const catalogThemes = catalogFromGo(themeSource);

// Quote-agnostic and whitespace-tolerant on purpose: the attribute selector
// a formatter emits is not the frontend's choice to make.
const themeBlockPattern = (theme) => new RegExp(`\\[data-theme\\s*=\\s*['"]${theme}['"]\\s*\\]`);
const stampedThemes = catalogThemes.filter((theme) => themeBlockPattern(theme).test(stylesCode));

// Source-size budgets. Perf budgets are tests here, so a shell that grows
// past its cap is a red build rather than a discussion. The caps are the
// current sizes rounded up with room to work in; they ratchet DOWN as the
// shell is trimmed, never up to accommodate a regression on an unchanged
// surface.
//
// They were raised once when the ratings strip landed, and again for the
// sepia reading mode and the icon appearance menu — both under the same
// new-surface carve-out in AGENTS.md, because each time the old cap
// measured a shell that no longer exists. The static fallback did not gain
// a surface, so its cap does not move.
//
// Headroom is stated as a fraction of the CAP, the same basis the previous
// raise used, so the rows stay comparable across raises:
//
//   surface     old cap   measured   new cap   headroom
//   fallback       1800       1421      1800        21%
//   component      7600       9303      9600         3%
//   styles         9800      12724     13600         6%
//
// Both raises are disclosed in the PR body so a reviewer can check the
// headroom is working room and not cover for a regression. The component
// row is re-measured at THIS head, not at the head that proposed the cap:
// the focus-return repair grew App.svelte by 449 bytes after the raise was
// written, so the earlier "8854 / 8%" described a component that no longer
// exists. The real working room is 297 bytes, which is deliberately NOT
// answered with a third raise in the same pull request — a cap that moves
// every time the surface under it grows measures nothing.
const sourceByteBudgets = { fallback: 1800, component: 9600, styles: 13600 };

// Every declaration block in the stylesheet, as { selector, body } pairs.
// The parser is deliberately small: this stylesheet is hand-written, flat,
// and nested only inside at-rules, so a brace-counting scan reads it
// exactly and needs no dependency.
function declarationBlocks(css) {
  const withoutComments = css.replace(/\/\*[\s\S]*?\*\//g, '');
  const blocks = [];
  const openAtRules = [];
  let cursor = 0;
  while (cursor < withoutComments.length) {
    const open = withoutComments.indexOf('{', cursor);
    if (open < 0) break;
    const close = withoutComments.indexOf('}', open);
    const prelude = withoutComments.slice(cursor, open).replace(/^[};\s]+/, '').trim();
    if (prelude.startsWith('@')) {
      openAtRules.push(prelude);
      cursor = open + 1;
      continue;
    }
    blocks.push({
      atRules: [...openAtRules],
      selector: prelude,
      body: withoutComments.slice(open + 1, close),
    });
    cursor = close + 1;
    // A rule closing at the end of an at-rule body closes that at-rule too.
    while (openAtRules.length > 0 && /^\s*}/.test(withoutComments.slice(cursor))) {
      openAtRules.pop();
      cursor = withoutComments.indexOf('}', cursor) + 1;
    }
  }
  return blocks;
}

// Declarations of a block as { property, value } pairs.
function declarations(body) {
  return body
    .split(';')
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0)
    .map((entry) => {
      const colon = entry.indexOf(':');
      return { property: entry.slice(0, colon).trim(), value: entry.slice(colon + 1).trim() };
    });
}

// Viewport-height units, split by the only distinction that matters on a
// phone. `vh` and `lvh` both measure the LARGE viewport — the height the page
// has only while iOS Safari's URL bar is hidden — so a full-height box written
// in either is taller than the screen whenever the bar is showing. `svh` and
// `dvh` are the two that never are. The unit must sit directly against its
// number, which is what keeps `100svh` out of the banned match and `12vw` out
// of both.
const TALL_VIEWPORT_UNIT = /\b\d*\.?\d+(?:vh|lvh)\b/;
const SHORT_VIEWPORT_UNIT = /\b\d*\.?\d+(?:svh|dvh)\b/;

// The viewport-height contract as a RULE over the parsed stylesheet rather
// than a pinned literal. The literal pin it replaces asserted that the exact
// string `min-block-size: 100svh` appeared somewhere and that some `@supports`
// mentioned it; both stayed green while a second rule added `block-size:
// 100dvh` with no guard and no fallback, because neither assertion looked at
// any declaration but the one it named. Three findings replace it:
//
//   1. a tall unit anywhere, which is the iOS bug itself;
//   2. a short unit outside an `@supports` naming that same property and unit,
//      which drops the declaration entirely on an engine that cannot resolve
//      it — the `@supports` fallback floor, for the one non-universal feature
//      this stylesheet actually uses;
//   3. a guarded short unit whose selector declares no unguarded fallback for
//      the same property, which leaves that engine with nothing at all.
//
// The returned `guarded` list is what expresses the POSITIVE half: the floor
// is "use svh/dvh", not merely "never use 100vh", and a stylesheet that had
// quietly stopped asking for a small-viewport height would satisfy every ban
// while meeting none of the requirement.
function viewportUnitFindings(css) {
  const blocks = declarationBlocks(css);
  const findings = [];
  const guarded = [];
  for (const block of blocks) {
    for (const { property, value } of declarations(block.body)) {
      if (TALL_VIEWPORT_UNIT.test(value)) {
        findings.push(
          `${block.selector} declares "${property}: ${value}": vh and lvh measure the large viewport, which a collapsing URL bar makes taller than the screen`,
        );
        continue;
      }
      const short = SHORT_VIEWPORT_UNIT.exec(value);
      if (!short) continue;
      const unit = short[0].replace(/[\d.]/g, '');
      const guard = block.atRules.find(
        (rule) => rule.startsWith('@supports') && rule.includes(property) && rule.includes(unit),
      );
      if (!guard) {
        findings.push(
          `${block.selector} declares "${property}: ${value}" outside an @supports guard naming ${property} and ${unit}, so an engine without the unit drops it`,
        );
        continue;
      }
      const hasFallback = blocks.some(
        (other) =>
          other.selector === block.selector &&
          !other.atRules.some((rule) => rule.startsWith('@supports')) &&
          declarations(other.body).some(
            (entry) =>
              entry.property === property &&
              !SHORT_VIEWPORT_UNIT.test(entry.value) &&
              !TALL_VIEWPORT_UNIT.test(entry.value),
          ),
      );
      if (!hasFallback) {
        findings.push(
          `${block.selector} guards "${property}: ${value}" but declares no unguarded ${property}, so an engine without ${unit} gets no height at all`,
        );
        continue;
      }
      guarded.push(`${block.selector} { ${property}: ${value} }`);
    }
  }
  return { findings, guarded };
}

// Each video floor is a NAMED SHAPE rather than a bare token, because the two
// ways to fail it are not the same. `poster` with no value is not a poster,
// and `muted={false}` is not muted — both satisfy a presence check and both
// are refused by a phone. `autoplay` is deliberately not part of the trigger:
// conditioning the floors on it would mean a video that gains autoplay later
// silently loses its guard, and a poster on a tap-to-play video is correct
// anyway.
const VIDEO_FLOORS = [
  {
    name: 'muted',
    present: /\bmuted\b/i,
    disabled: /\bmuted\s*=\s*(?:"false"|'false'|\{false\})/i,
  },
  {
    name: 'playsinline',
    present: /\bplaysinline\b/i,
    disabled: /\bplaysinline\s*=\s*(?:"false"|'false'|\{false\})/i,
  },
  // A value is part of the shape here, so `poster` and `poster=""` both fail.
  { name: 'poster', present: /\bposter\s*=\s*(?:"[^"]+"|'[^']+'|\{[^}]+\})/i },
];

function videoFindings(source) {
  const findings = [];
  for (const [tag] of source.matchAll(/<video\b[^>]*>/gi)) {
    const flat = tag.replace(/\s+/g, ' ');
    for (const floor of VIDEO_FLOORS) {
      if (!floor.present.test(flat)) findings.push(`${flat}: missing ${floor.name}`);
      else if (floor.disabled?.test(flat)) findings.push(`${flat}: ${floor.name} is switched off`);
    }
  }
  return findings;
}

// WCAG 2.2 relative luminance and contrast ratio, computed here so the
// palette is validated rather than asserted. Six-digit hex only: the
// palette block is pinned to that form by its own test.
function relativeLuminance(hex) {
  const channels = [1, 3, 5].map((offset) => {
    const value = parseInt(hex.slice(offset, offset + 2), 16) / 255;
    return value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * channels[0] + 0.7152 * channels[1] + 0.0722 * channels[2];
}

function contrastRatio(foreground, background) {
  const [lighter, darker] = [relativeLuminance(foreground), relativeLuminance(background)].sort(
    (a, b) => b - a,
  );
  return (lighter + 0.05) / (darker + 0.05);
}

// The palette block's literals, keyed by token name.
function paletteLiterals() {
  const palette = {};
  for (const [, name, value] of stylesCode.matchAll(
    /(--palette-[a-z-]+)\s*:\s*(#[0-9a-f]{6})\s*;/g,
  )) {
    palette[name] = value;
  }
  return palette;
}

// Browser execution is deliberately outside this dependency-free test. These
// assertions keep the accessible, responsive first response intact even when
// JavaScript is slow, unavailable, or rejected by a visitor's policy.
test('static and hydrated shells preserve the same accessible identity', () => {
  assert.match(fallback, /<html lang="en">/);
  assert.match(fallback, /name="viewport"/);
  assert.match(fallback, /data-static-fallback/);
  assert.match(fallback, /<main aria-labelledby="static-page-title"/);
  // Structure, never copy: each shell must render a non-empty labelling
  // heading, but the text itself is temporary placeholder content and will be
  // replaced by the real site — it is deliberately not a contract.
  assert.match(fallback, /<h1 id="static-page-title">[^<]+<\/h1>/);
  assert.match(component, /<svelte:head>/);
  assert.match(component, /name="description"/);
  assert.match(component, /<main aria-labelledby="page-title">/);
  assert.match(component, /<h1 id="page-title">[^<]+<\/h1>/);
});

// The remote-origin ban (requirement 1) used to be spelled as "no // bytes
// anywhere", which also outlawed every JavaScript line comment and would
// have fought real component source. It is now scoped to the two shapes a
// remote origin can actually take — an absolute scheme URL, and a
// protocol-relative URL in a string, attribute, or url() context — so the
// ban is unchanged in force and no longer collateral. Any remote reference
// the site ever needs arrives as data from this origin's own API, never as
// a literal in shell source.
//
// The string-opening class must name EVERY quote this source can use. It
// once omitted the backtick, which let a protocol-relative origin hide in a
// JavaScript template literal — a shape the old blanket ban did catch. The
// regression that shape represents is pinned by the mutation this test's
// PR records.
test('initial source remains local and viewport-responsive', () => {
  for (const [name, source] of Object.entries(sources)) {
    assert.doesNotMatch(source, /https?:\/\//i, `${name} introduces an absolute remote origin`);
    assert.doesNotMatch(
      source,
      /(?:["'`(=]|url\()\s*\/\/[a-z0-9-]/i,
      `${name} introduces a protocol-relative remote origin`,
    );
  }
  assert.match(styles, /font-size:\s*clamp\(/);
  assert.match(styles, /prefers-color-scheme:\s*light/);
});

test('source stays inside its size budget', () => {
  for (const [name, cap] of Object.entries(sourceByteBudgets)) {
    const size = Buffer.byteLength(sources[name], 'utf8');
    assert.ok(size <= cap, `${name} is ${size} bytes, over its ${cap}-byte budget`);
  }
});

// The zero-layout-shift pin. A theme may change what a box looks like and
// never how large it is, so every theme rule is restricted to custom
// properties: the [data-theme] blocks the origin's stamp selects, and the
// prefers-color-scheme mapping the "system" theme resolves through. A
// padding, font-size, border-width, or display declaration smuggled into
// one of these blocks fails here — which is exactly the regression that
// would make a theme switch reflow the page.
test('theme rules can only change colour, never layout', () => {
  const themeBlocks = declarationBlocks(styles).filter(
    (block) =>
      block.selector.includes('[data-theme') ||
      block.atRules.some((rule) => rule.includes('prefers-color-scheme')),
  );
  assert.ok(themeBlocks.length >= 3, 'expected the light, dark, and system theme rules');
  for (const block of themeBlocks) {
    for (const { property } of declarations(block.body)) {
      assert.ok(
        property.startsWith('--'),
        `theme rule "${block.selector}" declares "${property}", which is not a custom property`,
      );
    }
  }
});

test('every theme defines the same token set', () => {
  const blocks = declarationBlocks(styles);
  const tokensOf = (predicate) =>
    blocks
      .filter(predicate)
      .flatMap((block) => declarations(block.body).map(({ property }) => property))
      .filter((property) => property.startsWith('--') && !property.startsWith('--palette-'))
      .sort();

  const light = tokensOf((block) => themeBlockPattern('light').test(block.selector));
  const system = tokensOf((block) =>
    block.atRules.some((rule) => rule.includes('prefers-color-scheme')),
  );
  assert.ok(light.length > 0, 'the light theme defines no tokens');
  assertCatalogIsFullyStamped();
  for (const theme of stampedThemes) {
    assert.deepEqual(
      tokensOf((block) => themeBlockPattern(theme).test(block.selector)),
      light,
      `the ${theme} theme does not define the light theme token set`,
    );
  }
  assert.deepEqual(system, light, 'the system mapping does not define the light theme token set');
});

// Palette literals live in one block and nowhere else, so a component can
// never hard-code a colour that a theme then fails to change.
test('colour literals exist only in the palette block', () => {
  for (const line of stylesCode.split('\n')) {
    if (!/#[0-9a-f]{3,8}\b/i.test(line)) continue;
    assert.match(
      line.trim(),
      /^--palette-[a-z-]+:\s*#[0-9a-f]{6};$/,
      `colour literal outside the palette block: ${line.trim()}`,
    );
  }
});

// Both palettes are validated for contrast, not asserted to be pretty. The
// pairs below are every foreground the shell paints on every background it
// paints them on. Text meets WCAG 2.2 AA (4.5:1); the switcher's border and
// the focus ring are non-text interface boundaries and meet 3:1.
test('both palettes clear their contrast floors', () => {
  const palette = paletteLiterals();
  const textPairs = [
    ['ink', 'canvas'],
    ['ink', 'raised'],
    ['ink-muted', 'canvas'],
    ['ink-muted', 'raised'],
    ['accent-ink', 'accent'],
  ];
  const interfacePairs = [
    ['edge', 'canvas'],
    ['edge', 'raised'],
    ['accent', 'canvas'],
    ['accent', 'raised'],
  ];
  assertCatalogIsFullyStamped();
  for (const theme of stampedThemes) {
    for (const [foreground, background, floor] of [
      ...textPairs.map((pair) => [...pair, 4.5]),
      ...interfacePairs.map((pair) => [...pair, 3]),
    ]) {
      const front = palette[`--palette-${theme}-${foreground}`];
      const back = palette[`--palette-${theme}-${background}`];
      assert.ok(front && back, `${theme} palette is missing ${foreground} or ${background}`);
      const ratio = contrastRatio(front, back);
      assert.ok(
        ratio >= floor,
        `${theme}: ${foreground} on ${background} is ${ratio.toFixed(2)}:1, below ${floor}:1`,
      );
    }
  }
});

// Rendering lanes, stage 1: the static cross-browser floors, pinned as
// source facts so a regression is a red build on every browser at once.
test('rendering-lane floors hold in the shell source', () => {
  assert.match(fallback, /viewport-fit=cover/, 'safe-area insets need viewport-fit=cover');
  assert.match(styles, /env\(safe-area-inset-top\)/);
  assert.match(styles, /env\(safe-area-inset-bottom\)/);
  assert.match(styles, /env\(safe-area-inset-left\)/);
  assert.match(styles, /env\(safe-area-inset-right\)/);

  // iOS Safari's collapsing URL bar makes 100vh taller than the visible
  // viewport, so the small-viewport unit is the only correct answer and the
  // fallback is a percentage of an already-bounded chain. The ban is spelled
  // over the whole stylesheet as well as per declaration, because an at-rule
  // prelude — `@media (min-height: 100vh)` — is not a declaration and would
  // otherwise slip past the block walk.
  assert.doesNotMatch(
    stylesCode,
    TALL_VIEWPORT_UNIT,
    'vh and lvh are banned; use svh or dvh behind an @supports guard with a percentage floor',
  );
  for (const [name, source] of Object.entries({ fallback, component: componentCode })) {
    assert.doesNotMatch(
      source,
      TALL_VIEWPORT_UNIT,
      `${name} sizes something in vh or lvh; an inline style evades the stylesheet's rule but not a phone`,
    );
  }

  const viewportUnits = viewportUnitFindings(styles);
  assert.deepEqual(viewportUnits.findings, [], viewportUnits.findings.join('\n'));
  assert.ok(
    viewportUnits.guarded.length >= 1,
    'the shell asks for no small- or dynamic-viewport height at all; svh/dvh is a positive floor, not only a ban on 100vh',
  );

  assert.match(stylesCode, /--tap-target:\s*44px/);
  assert.match(stylesCode, /min-block-size:\s*var\(--tap-target\)/);
  // 16px is the threshold below which iOS Safari zooms a focused control.
  const controlFontSize = stylesCode.match(/--font-size-control:\s*([\d.]+)rem/);
  assert.ok(controlFontSize, 'the control font-size token is missing');
  assert.ok(Number(controlFontSize[1]) >= 1, 'control text must be at least 1rem');

  assert.match(styles, /@media\s*\(prefers-reduced-motion:\s*reduce\)/);

  // Nothing may be wider than the narrowest supported viewport, or the body
  // scrolls sideways at 320px.
  for (const [declaration, pixels] of stylesCode.matchAll(
    /(?:min-)?(?:width|inline-size)\s*:\s*(\d+)px/g,
  )) {
    assert.ok(Number(pixels) <= 320, `fixed size forces horizontal scroll: ${declaration.trim()}`);
  }
});

// The viewport-height rule above passes on the current stylesheet, which is
// the one input that proves nothing: a rule with no violation to find reads
// exactly like a rule that cannot find one. So it is run here against a
// compliant fixture and against one fixture per finding branch, and each
// hostile case must name the floor it breaks. Every mutation the rule claims
// to catch is therefore killed in the suite itself, not only in a reviewer's
// scratch worktree.
test('the viewport-height rule catches every shape it bans', () => {
  const guarded = [
    '.shell { min-block-size: 100%; }',
    '@supports (min-block-size: 100svh) { .shell { min-block-size: 100svh; } }',
  ].join('\n');
  const compliant = viewportUnitFindings(guarded);
  assert.deepEqual(compliant.findings, []);
  assert.deepEqual(compliant.guarded.length, 1, 'the compliant fixture expresses one guarded unit');

  for (const [label, css, expected] of [
    ['a tall unit', '.hero { block-size: 100vh; }', [/vh and lvh measure the large viewport/]],
    [
      'the large-viewport unit',
      '.hero { block-size: 100lvh; }',
      [/vh and lvh measure the large viewport/],
    ],
    [
      'an unguarded short unit',
      '.hero { min-block-size: 100%; block-size: 100dvh; }',
      [/outside an @supports guard naming block-size and dvh/],
    ],
    [
      'a guard that names another property',
      '.hero { min-block-size: 100%; }\n@supports (display: grid) { .hero { block-size: 100dvh; } }',
      [/outside an @supports guard naming block-size and dvh/],
    ],
    [
      'a guarded unit with no fallback',
      '@supports (min-block-size: 100svh) { .hero { min-block-size: 100svh; } }',
      [/declares no unguarded min-block-size/],
    ],
    // Two findings, and deliberately so: the fallback declaration is itself an
    // unguarded viewport unit, which is both a violation on its own line AND
    // the reason the guarded rule is left without a floor. Collapsing this to
    // one message would hide half of what is wrong.
    [
      'a fallback that is itself a viewport unit',
      '.hero { min-block-size: 100dvh; }\n@supports (min-block-size: 100svh) { .hero { min-block-size: 100svh; } }',
      [
        /outside an @supports guard naming min-block-size and dvh/,
        /declares no unguarded min-block-size/,
      ],
    ],
  ]) {
    const { findings, guarded: passed } = viewportUnitFindings(css);
    assert.deepEqual(passed, [], `${label} was accepted as a compliant guarded unit`);
    assert.deepEqual(
      findings.length,
      expected.length,
      `${label} produced ${findings.length} findings, not ${expected.length}: ${findings.join(' | ')}`,
    );
    for (const [index, pattern] of expected.entries()) {
      assert.match(findings[index], pattern, `${label} finding ${index} was reported as something else`);
    }
  }
});

// The last stage-1 floor with no expression anywhere in this repository: a
// phone refuses to autoplay a video that is not muted, refuses to play it in
// place unless it is playsinline, and paints nothing at all until enough of
// it has downloaded unless it carries a poster. No shell renders a video
// today — heavy media is an owner decision per AGENTS.md, not incremental
// drift — so the rule exists to make the FIRST one conscious rather than to
// repair an existing mistake.
test('any video a shell renders survives a phone autoplay policy', () => {
  for (const [name, source] of Object.entries({ fallback, component })) {
    const findings = videoFindings(source);
    assert.deepEqual(findings, [], `${name}: ${findings.join('; ')}`);
  }

  // Both shells carry zero <video> tags, so the loop above is empty by
  // construction and proves nothing on its own. The fixtures are what make
  // this a guard rather than a decoration.
  assert.deepEqual(
    videoFindings('<video autoplay muted playsinline poster="/poster.avif" loop></video>'),
    [],
    'a fully compliant video was rejected',
  );
  for (const [fixture, expected] of [
    ['<video src="/reel.mp4"></video>', ['missing muted', 'missing playsinline', 'missing poster']],
    ['<video muted poster="/p.avif"></video>', ['missing playsinline']],
    ['<video playsinline poster="/p.avif"></video>', ['missing muted']],
    ['<video muted playsinline></video>', ['missing poster']],
    ['<video muted playsinline poster></video>', ['missing poster']],
    ['<video muted playsinline poster=""></video>', ['missing poster']],
    ['<video muted={false} playsinline poster="/p.avif"></video>', ['muted is switched off']],
    ['<video muted playsinline="false" poster="/p.avif"></video>', ['playsinline is switched off']],
  ]) {
    const findings = videoFindings(fixture);
    assert.deepEqual(
      findings.map((finding) => finding.split(': ')[1]),
      expected,
      `${fixture} was not reported as ${expected.join(', ')}`,
    );
  }

  // Multi-line and multi-video sources are the realistic shapes, and the tag
  // scanner has to survive both: a Svelte block indents its attributes across
  // lines, and one hostile video hidden after a compliant one must still be
  // found. Findings quote the flattened OPENING tag, which is where every
  // attribute lives.
  const pair = [
    '<video\n  muted\n  playsinline\n  poster="/a.avif"\n></video>',
    '<video muted></video>',
  ].join('\n');
  assert.deepEqual(videoFindings(pair), [
    '<video muted>: missing playsinline',
    '<video muted>: missing poster',
  ]);
});

// The theme switcher is a real control: labelled, keyboard reachable, and
// honest about which option is active. It reads the origin's stamp rather
// than deciding a theme itself, which is what keeps the first paint free of
// a scripted correction.
test('the theme switcher is accessible and origin-led', () => {
  assert.match(component, /role="group"/);
  assert.match(component, /aria-label="Appearance"/);
  assert.match(component, /aria-pressed=\{active === option\.id\}/);
  assert.match(component, /type="button"/);
  // Cross-bound rather than listed: the switcher must offer "system" plus
  // exactly the modes the stylesheet stamps. A mode with a token block and
  // no way to reach it, and an option that stamps an attribute no block
  // answers, are both caught — and neither file can shrink on its own.
  // Bounded to the options array itself, not scanned across the file: the
  // review deleted the sepia option outright and stayed green because the
  // string `id: 'sepia'` survived elsewhere in the component.
  const optionsBlock = blockAfter('const options', '[', true);
  const offered = [...optionsBlock.matchAll(/id:\s*['"]([a-z0-9-]+)['"]/g)].map((match) => match[1]);
  assert.deepEqual(
    offered.slice().sort(),
    catalogThemes.slice().sort(),
    'the switcher options and internal/theme/types.go disagree about which reading modes exist',
  );
  assert.match(
    component,
    /getAttribute\(themeAttribute\)/,
    'the switcher must read the theme the origin stamped',
  );
  assert.match(component, /SameSite=Lax/);
  assert.match(component, /'Secure'/);
  // A selected option must not change weight: a bolder label is a wider
  // label, and a wider label is a layout shift inside the switcher. EVERY
  // rule that styles the pressed state is inspected, not just the first
  // one found: a later, more specific rule wins the cascade, so checking
  // one and stopping would let the winning declaration go unexamined.
  const pressedBlocks = declarationBlocks(styles).filter((block) =>
    block.selector.includes("[aria-pressed='true']"),
  );
  assert.ok(pressedBlocks.length >= 1, 'the pressed-state rule is missing');
  for (const block of pressedBlocks) {
    for (const { property } of declarations(block.body)) {
      assert.ok(
        ['background', 'background-color', 'color', 'border-color'].includes(property),
        `the pressed-state rule "${block.selector}" declares "${property}", which can change the control's size`,
      );
    }
  }
});

// The switcher is ONE icon now, so the reading modes live behind a
// disclosure. A disclosure that cannot be dismissed is a trap, and one that
// tells its modes apart by colour alone is unreadable to anyone who cannot
// separate the swatches — so both properties are pinned here rather than
// left to a reviewer's eye.
test('the appearance menu is a dismissible disclosure, not a colour-only control', () => {
  assert.match(component, /aria-expanded=\{open\}/);
  // NOT aria-haspopup. ARIA 1.2 maps aria-haspopup="true" to "menu", and a
  // menu promises menu semantics — arrow-key roving focus, menuitem roles.
  // What actually opens is a role="group" of toggle buttons, so claiming the
  // menu mapping would announce an interaction model that is not there. A
  // plain disclosure is what this is, and aria-expanded says exactly that.
  assert.doesNotMatch(
    component,
    /aria-haspopup/,
    'the popup is a group of toggles, not a menu; do not promise menu semantics',
  );

  // Closing unmounts whatever the keyboard was on, so focus must be handed
  // back deliberately. Without this it lands on <body> and the next Tab
  // restarts at the top of the page.
  // Anchored to the three places that have to be true, because the delta
  // review evaded the previous spelling of this pin three ways while
  // svelte-check stayed at 0 and all 14 tests stayed green: it relocated
  // bind:this onto an option button inside {#if open} (a markup
  // restructure does that by accident, and .focus() on a detached node is
  // a silent no-op), it retained the trigger?.focus() token in dead code
  // outside dismissMenu, and it satisfied both path assertions from a doc
  // comment. A binding on the wrong element, a call in the wrong function,
  // and a mention that is not a call are all now red.
  assert.match(
    blockAfter('function dismissMenu(): void'),
    /trigger\?\.focus\(\)/,
    'dismissMenu must hand focus back to the trigger, not merely set open to false',
  );
  const triggerTag = componentCode.match(/<button\b[^>]*class="theme-menu__trigger"[^>]*>/);
  assert.ok(triggerTag, 'the appearance control is not a button carrying theme-menu__trigger');
  assert.match(
    triggerTag[0],
    /bind:this=\{trigger\}/,
    'trigger must bind the always-mounted trigger button; a node inside {#if open} is destroyed before focus lands',
  );
  for (const [path, marker] of [
    ['choose', 'function choose(id: string): void'],
    ['Escape', 'onkeydown='],
  ]) {
    assert.match(
      blockAfter(marker),
      /dismissMenu\(\)/,
      `the ${path} path must close through dismissMenu so focus returns`,
    );
  }
  // The trigger names the mode currently in force, so its accessible name
  // is never a bare "Appearance" with the state hidden inside the popover.
  assert.match(component, /aria-label="Appearance: \{activeLabel\}"/);

  // Two dismissal paths, because neither alone covers every target browser:
  // Safari does not focus a button when it is clicked, so a blur-only close
  // would leave the popover stuck open there.
  assert.match(component, /event\.key === 'Escape'/);
  assert.match(component, /addEventListener\('pointerdown'/);
  assert.match(
    component,
    /removeEventListener\('pointerdown'/,
    'the dismiss listener must be torn down with the open state',
  );

  // Every mode is named in text and ticked when active. The swatch previews
  // the canvas that mode paints; it is never the only way to tell them apart.
  assert.match(component, /\{option\.label\}/);
  assert.match(component, /data-swatch=\{option\.id\}/);
  assert.match(component, /active === option\.id \? '✓' : ''/);

  // The icon button is a touch target like every other control here.
  const trigger = declarationBlocks(styles).find(
    (block) => block.selector === '.theme-menu__trigger',
  );
  assert.ok(trigger, 'the trigger rule is missing');
  const bounds = declarations(trigger.body).filter(({ property }) =>
    ['min-block-size', 'min-inline-size'].includes(property),
  );
  assert.equal(bounds.length, 2, 'the icon trigger must bound both of its axes');
  for (const { property, value } of bounds) {
    assert.equal(value, 'var(--tap-target)', `${property} must use the tap-target token`);
  }

  // The tick column is fixed width, so moving the tick to another mode
  // cannot resize the popover — the zero-layout-shift rule, applied inside
  // the control this time.
  const check = declarationBlocks(styles).find((block) => block.selector === '.theme-menu__check');
  assert.ok(check, 'the tick column rule is missing');
  assert.ok(
    declarations(check.body).some(({ property }) => property === 'inline-size'),
    'the tick column must claim a fixed inline size',
  );
});

// The chrome exists in BOTH shells so the switcher's arrival at hydration
// replaces reserved space instead of pushing the page down.
test('the static shell reserves the chrome the mounted shell fills', () => {
  assert.match(fallback, /<header class="chrome"><\/header>/);
  assert.match(component, /<header class="chrome">/);
  assert.match(styles, /--chrome-block-size:/);
  assert.match(styles, /min-block-size:\s*var\(--chrome-block-size\)/);
});

// The ratings strip. Every byte of it is our own markup: no third-party
// script, widget, iframe, or image is involved, which is precisely why the
// site's CSP can stay as strict as it is. The values arrive as data from
// this origin's own surface, so no remote origin appears in shell source
// either — the remote-origin ban above covers that, and this test covers
// the shapes that ban cannot see.
test('the ratings strip is our own markup and links out safely', () => {
  assert.match(component, /const ratingsSurface = '\/api\/ratings'/, 'the strip must read this origin');
  assert.match(component, /fetch\(ratingsSurface/);
  for (const embed of [/<iframe/i, /<script\s+src=/i, /<embed/i, /<object/i]) {
    assert.doesNotMatch(component, embed, 'the strip must never embed a third party');
  }
  // Outbound links open away from this document and hand the destination
  // no handle on it and no referrer.
  assert.match(component, /target="_blank"/);
  assert.match(component, /rel="noopener noreferrer"/);
  assert.match(component, /aria-label=\{linkLabel\(/, 'each outbound link needs an accessible name');
  assert.match(component, /Opens in a new tab/, 'the accessible name must say the link opens a new tab');

  // Honest states, all three reachable from the source.
  assert.match(component, /data-ratings-state=\{ratingsState\}/);
  for (const state of ["'loading'", "'ready'", "'unavailable'"]) {
    assert.ok(component.includes(state), `the strip cannot report the ${state} state`);
  }
  // A platform with no captured rating says so instead of showing a zero.
  assert.match(component, /platform\.state === 'published'/);
});

// Dataviz floor: a value is never encoded by colour alone. The rating is
// text, the meter repeats it as length, and the review count is text —
// so the meter is decorative and hidden from assistive technology.
test('the ratings strip pairs every value with text and shape', () => {
  assert.match(component, /class="ratings__meter" aria-hidden="true"/);
  assert.match(component, /\{platform\.rating\}/, 'the rating must render as text');
  assert.match(component, /\{platform\.reviewCount\} reviews/, 'the count must render as text');
  assert.match(component, /meterPercent\(platform, ratings\.summary\.scale\)/);
});

// Zero CLS again, for late data this time: the strip's band exists at its
// final height in the static shell, so the fetched values fill reserved
// space instead of pushing the page.
test('the ratings strip reserves its band before any data arrives', () => {
  assert.match(fallback, /<footer class="ratings" data-ratings-state="static"><\/footer>/);
  assert.match(component, /<footer class="ratings"/);
  assert.match(stylesCode, /--ratings-block-size:/);
  assert.match(stylesCode, /min-block-size:\s*var\(--ratings-block-size\)/);
  // The outbound links are the strip's touch targets and hold the floor.
  const anchorBlock = declarationBlocks(styles).find(
    (block) => block.selector === '.ratings__anchor',
  );
  assert.ok(anchorBlock, 'the ratings anchor rule is missing');
  assert.ok(
    declarations(anchorBlock.body).some(
      ({ property, value }) => property === 'min-block-size' && value === 'var(--tap-target)',
    ),
    'ratings links must hold the touch-target floor',
  );
});
