import { expect, test } from '@playwright/test';

/*
  Rendering lanes, stage 2 (issue #22).

  `tests/experience.test.mjs` proves the floors as SOURCE facts: it can read
  that the stylesheet asks for 44px, for 100svh behind an @supports guard, for
  a reduced-motion block. What it cannot do is find out whether three
  independent CSS engines agree, because reading a file is not rendering one.
  These lanes answer that half — and only that half — by driving the shipped
  Go binary in Chromium, WebKit, and Gecko at phone viewports and MEASURING
  what each engine computed.

  The division of labour is deliberate and stated per lane below, because
  neither half subsumes the other:

  - A property only source can pin: the unit actually written (`100svh` and
    not `100vh`). Headless browsers have no collapsing URL bar, so the two
    units compute identically here and a browser assertion could not tell
    them apart. The source ban stays the enforcement.
  - A property only a browser can pin: whether a declaration SURVIVED an
    engine's parser, what a control really measures after layout, whether a
    theme switch moved a box, and where the page actually sent requests.

  Nothing here asserts site copy. The lanes read structure, geometry, and
  computed values, so replacing the placeholder content changes none of them.
*/

// Every width the floors have to hold at, narrowest first. 320px is the
// contract's floor; the rest are the common phone widths this site is
// expected on. Held in one place so both geometry lanes walk the same set.
const PHONE_WIDTHS = [320, 360, 390, 412];

// The floors themselves, as numbers rather than prose.
const TOUCH_TARGET_PX = 44;
const CONTROL_FONT_PX = 16;
const SAFE_AREA_FALLBACK_PX = 20; // --space-md, 1.25rem at the 16px root

/* Seconds from a computed <time>. Engines disagree on the spelling of a very
   small duration — Chromium answers `1e-05s` where WebKit and Gecko answer
   `0.00001s` — and both are the same number, so the value is parsed rather
   than string-matched. A multi-property shorthand computes to a comma list;
   the slowest entry is the one a visitor perceives. */
function slowestSeconds(computed) {
  const parts = computed.split(',').map((part) => Number.parseFloat(part.trim()));
  for (const part of parts) expect(Number.isNaN(part), `unreadable duration ${computed}`).toBe(false);
  return Math.max(...parts);
}

/* The switcher is a disclosure: the reading modes do not exist in the DOM
   until it is opened, so every lane that measures them opens it first. */
async function openAppearanceMenu(page) {
  await page.locator('.theme-menu__trigger').click();
  await expect(page.locator('.theme-menu__popover')).toBeVisible();
}

/* The strip starts in `loading` and must reach a terminal answer. Waiting for
   that is what makes the geometry lanes measure the settled page rather than
   whichever frame they happened to catch. */
async function settle(page) {
  await expect(page.locator('.ratings')).not.toHaveAttribute('data-ratings-state', 'loading');
}

test.describe('rendering lanes', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
    await settle(page);
  });

  /*
    The viewport contract, measured on the document the ORIGIN serves — which
    is the Vite-built, Go-stamped shell, not the `index.html` the source test
    reads. A build step or a stamping bug that dropped the meta tag would be
    invisible to a source assertion and fatal on a phone.

    The padding assertion is the engine half of the safe-area floor:
    `max(var(--space-md), env(safe-area-inset-left))` is one declaration, so
    an engine that cannot parse `env()` inside `max()` drops the whole thing
    and the shell loses its gutters entirely. Emulated phones report zero
    insets, so the correct answer everywhere here is the --space-md fallback.
  */
  test('the served document carries the viewport contract', async ({ page }) => {
    const viewport = await page.getAttribute('meta[name=viewport]', 'content');
    expect(viewport).toContain('width=device-width');
    expect(viewport, 'safe-area insets need viewport-fit=cover').toContain('viewport-fit=cover');

    const padding = await page.evaluate(() => {
      const style = getComputedStyle(document.querySelector('.shell'));
      return {
        start: Number.parseFloat(style.paddingInlineStart),
        end: Number.parseFloat(style.paddingInlineEnd),
        blockEnd: Number.parseFloat(style.paddingBlockEnd),
      };
    });
    for (const [edge, value] of Object.entries(padding)) {
      expect(value, `the shell lost its ${edge} gutter; max(var(), env()) did not survive`)
        .toBeGreaterThanOrEqual(SAFE_AREA_FALLBACK_PX);
    }
  });

  /*
    The small-viewport lane. What a browser CAN answer here is which branch of
    the @supports guard won: the guarded `100svh` computes to a pixel length,
    while the unguarded `100%` fallback stays a percentage. So a stylesheet
    that lost its @supports block is red, and so is one whose small-viewport
    height stopped tracking the viewport.

    What a browser cannot answer is 100svh versus 100vh — headless has no
    collapsing URL bar, so they are the same number. That mutation is the
    source test's to kill, and it does.
  */
  test('the shell resolves the small-viewport height and fills the screen', async ({ page }) => {
    const measured = await page.evaluate(() => {
      const shell = document.querySelector('.shell');
      return {
        supportsSvh: CSS.supports('min-block-size', '100svh'),
        minBlockSize: getComputedStyle(shell).minBlockSize,
        height: shell.getBoundingClientRect().height,
        innerHeight: window.innerHeight,
      };
    });

    expect(measured.supportsSvh, 'this engine cannot resolve 100svh at all').toBe(true);
    expect(
      measured.minBlockSize,
      'the shell fell back to the percentage floor; the @supports branch did not apply',
    ).toMatch(/px$/);
    expect(Number.parseFloat(measured.minBlockSize)).toBeCloseTo(measured.innerHeight, 0);
    expect(measured.height).toBeGreaterThanOrEqual(measured.innerHeight - 1);
  });

  /*
    No horizontal body scroll at any supported width, with the disclosure both
    closed and open. The popover is the one element on this page that can
    reach past the viewport's end edge, so measuring only the closed state
    would measure the easy case.
  */
  test('nothing scrolls the body sideways from 320px up', async ({ page }) => {
    for (const width of PHONE_WIDTHS) {
      await page.setViewportSize({ width, height: 720 });
      await expect
        .poll(() => page.evaluate(() => document.scrollingElement.clientWidth))
        .toBe(width);

      const closed = await page.evaluate(() => ({
        scrollWidth: document.scrollingElement.scrollWidth,
        clientWidth: document.scrollingElement.clientWidth,
      }));
      expect(closed.scrollWidth, `body scrolls sideways at ${width}px`).toBeLessThanOrEqual(
        closed.clientWidth,
      );

      await openAppearanceMenu(page);
      const open = await page.evaluate(() => ({
        scrollWidth: document.scrollingElement.scrollWidth,
        clientWidth: document.scrollingElement.clientWidth,
        popoverRight: document.querySelector('.theme-menu__popover').getBoundingClientRect().right,
      }));
      expect(
        open.scrollWidth,
        `the open appearance menu scrolls the body sideways at ${width}px`,
      ).toBeLessThanOrEqual(open.clientWidth);
      expect(open.popoverRight).toBeLessThanOrEqual(open.clientWidth);
      await page.keyboard.press('Escape');
      await expect(page.locator('.theme-menu__popover')).toHaveCount(0);
    }
  });

  /*
    The touch and text floors, measured after layout instead of read off a
    token. A control can carry `min-block-size: var(--tap-target)` and still
    render short if something above it shrinks the box, and a font token can
    be overridden further down the cascade — neither is visible in source.

    The narrowest supported width is the hostile one: that is where a control
    gets squeezed. `.ratings__anchor` is measured too, because it is an <a>
    the moment a platform publishes a profile URL and its floor has to hold
    before that day, not after it.
  */
  test('every control holds the 44px touch floor and 16px text floor', async ({ page }) => {
    await page.setViewportSize({ width: PHONE_WIDTHS[0], height: 720 });
    await settle(page);
    await openAppearanceMenu(page);

    const controls = await page.evaluate(() => {
      const read = (node) => {
        const rect = node.getBoundingClientRect();
        return {
          name: node.className || node.tagName.toLowerCase(),
          width: rect.width,
          height: rect.height,
          fontSize: Number.parseFloat(getComputedStyle(node).fontSize),
          square: node.classList.contains('theme-menu__trigger'),
          text: node.textContent.trim().length > 0,
        };
      };
      const nodes = [
        ...document.querySelectorAll(
          'button, a[href], input, select, textarea, .ratings__anchor',
        ),
      ];
      return nodes.map(read);
    });

    // The measured set has to be the real one, not whatever happened to be in
    // the DOM. Six is the floor with the disclosure open and the strip
    // settled `ready` — the appearance trigger, the four reading modes, and
    // at least one ratings anchor. This binary always serves /api/ratings, so
    // `ready` is the state settle() reaches here; a build that answered
    // `unavailable` would render no anchors at all and fail this line, which
    // is the right outcome rather than a flake. The trigger is checked by
    // identity as well, because a disclosure that failed to open would still
    // leave five other nodes behind and a bare count would not notice.
    expect(controls.length, 'the page rendered too few controls to measure').toBeGreaterThanOrEqual(
      6,
    );
    expect(
      controls.filter((control) => control.square).length,
      'the appearance trigger was not among the measured controls; the disclosure never opened',
    ).toBe(1);
    for (const control of controls) {
      expect(control.height, `${control.name} is ${control.height}px tall`).toBeGreaterThanOrEqual(
        TOUCH_TARGET_PX,
      );
      if (control.square) {
        expect(control.width, `${control.name} is ${control.width}px wide`).toBeGreaterThanOrEqual(
          TOUCH_TARGET_PX,
        );
      }
      if (control.text) {
        // Below 16px iOS Safari zooms the page when the control takes focus.
        expect(
          control.fontSize,
          `${control.name} renders at ${control.fontSize}px`,
        ).toBeGreaterThanOrEqual(CONTROL_FONT_PX);
      }
    }
  });

  /*
    Reduced motion, observed in BOTH directions in the same lane. Asserting
    only the reduced side would pass against a stylesheet with no transitions
    at all, which respects nothing and proves nothing; asserting only the
    normal side would not notice the reduce block being deleted. The pair is
    what makes this a guard.
  */
  test('reduced motion is honoured, and motion still exists without it', async ({ page }) => {
    const optionTransition = () =>
      page.evaluate(
        () => getComputedStyle(document.querySelector('.theme-menu__option')).transitionDuration,
      );

    await page.emulateMedia({ reducedMotion: 'reduce' });
    await openAppearanceMenu(page);
    expect(
      await page.evaluate(() => window.matchMedia('(prefers-reduced-motion: reduce)').matches),
    ).toBe(true);
    const reduced = slowestSeconds(await optionTransition());
    expect(reduced, 'transitions still run under prefers-reduced-motion: reduce').toBeLessThanOrEqual(
      0.001,
    );

    await page.emulateMedia({ reducedMotion: 'no-preference' });
    const normal = slowestSeconds(await optionTransition());
    expect(
      normal,
      'the control has no transition at all, so respecting reduced motion proves nothing',
    ).toBeGreaterThan(0.05);
  });

  /*
    Zero layout shift across a reading-mode change, measured rather than
    reasoned about. The source test restricts theme blocks to custom
    properties, which is the mechanism; this is the outcome, in three engines,
    including the one that has to re-resolve `color-scheme` when the mode
    flips.
  */
  test('switching reading mode moves nothing', async ({ page }) => {
    const geometry = () =>
      page.evaluate(() =>
        ['.chrome', 'main', '.ratings'].map((selector) => {
          const { x, y, width, height } = document
            .querySelector(selector)
            .getBoundingClientRect();
          return { selector, x, y, width, height };
        }),
      );

    const before = await geometry();
    for (const mode of ['Light', 'Dark', 'Sepia', 'System']) {
      await openAppearanceMenu(page);
      await page.getByRole('button', { name: mode, exact: true }).click();
      await expect(page.locator('html')).toHaveAttribute('data-theme', mode.toLowerCase());
      expect(await geometry(), `choosing ${mode} moved the page`).toEqual(before);
    }
  });

  /*
    The origin lane. Requirement 1 says the frontend is local-origin-only, and
    the source test bans remote URLs as literals — but a literal ban cannot
    see a URL assembled at run time or fetched by a dependency. A real browser
    can, because every request it makes is observable.

    The same lane collects console errors and uncaught exceptions, which is
    how an engine-specific runtime failure (a syntax or API gap that only one
    of the three has) becomes a red build instead of a silent blank strip.
  */
  test('the page runs clean and speaks only to this origin', async ({ page, baseURL }) => {
    const consoleErrors = [];
    const pageErrors = [];
    const foreign = [];
    const expected = new URL(baseURL).origin;

    page.on('console', (message) => {
      if (message.type() === 'error') consoleErrors.push(message.text());
    });
    page.on('pageerror', (error) => pageErrors.push(String(error)));
    page.on('request', (request) => {
      const url = new URL(request.url());
      if (url.origin !== expected) foreign.push(request.url());
    });

    await page.reload();
    await settle(page);
    await openAppearanceMenu(page);
    await page.getByRole('button', { name: 'Dark', exact: true }).click();

    expect(foreign, 'the shell contacted an origin that is not this one').toEqual([]);
    expect(pageErrors).toEqual([]);
    expect(consoleErrors).toEqual([]);

    // Honest states: the strip must settle on a real answer, never sit in
    // `loading` and never invent numbers it did not receive.
    const state = await page.getAttribute('.ratings', 'data-ratings-state');
    expect(['ready', 'unavailable']).toContain(state);
  });
});
