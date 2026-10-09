/* Compliance floors (issue #173): what a first visit to the SHIPPED binary
 * contacts, stores, breaks and exposes, measured in every engine.
 *
 * `compliance.json` at the repository root is the site's own statement of
 * what it stores on a visitor's device, which third parties a page may
 * contact, and which legal pages exist; `scripts/ci/compliance_manifest.py`
 * validates it and judges the live site by it. This lane holds the BUILD to
 * the same statement before it ships. Each test refuses one behaviour and
 * none of them is an inventory: a new component, route or asset passes
 * untouched unless it contacts an undeclared origin, breaks the CSP, writes
 * to the visitor's device before they act, or drops a floor below.
 *
 * Lift: a refusal names the `compliance.json` entry that would admit it, and
 * every entry carries a written reason. That entry is also, deliberately, the
 * line a privacy notice has to mention.
 */
import { readFileSync } from 'node:fs';

import { expect, test } from '@playwright/test';

const manifest = JSON.parse(readFileSync(new URL('../../../compliance.json', import.meta.url), 'utf8'));
const declaredOrigins = new Set(manifest.thirdParties.map((entry) => entry.origin));
const publishedPages = manifest.legalPages.filter((entry) => entry.status === 'published');
const pendingPages = manifest.legalPages.filter((entry) => entry.status === 'pending');

/* Credential shapes with a fixed, distinctive prefix, so a hit in minified
 * code is a key and not a coincidence. The repository's secret scans read the
 * SOURCE; a value injected at build time exists only in these bytes. */
const credentialShapes = [
  ['cloud access key id', /AKIA[0-9A-Z]{16}/],
  ['forge token', /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})/],
  ['chat token', /\bxox[abprs]-[A-Za-z0-9-]{10,}/],
  ['payment secret key', /\b[rs]k_live_[A-Za-z0-9]{16,}/],
  ['browser API key', /\bAIza[0-9A-Za-z_-]{35}/],
  ['model API key', /\bsk-(?:ant|proj)-[A-Za-z0-9_-]{20,}/],
  ['private key block', /-----BEGIN [A-Z ]*PRIVATE KEY-----/],
  ['signed token', /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/],
];

/* One first visit: load, then walk to the end of the page so every lazy
 * image and late fetch has fired, recording every request, every same-origin
 * script and stylesheet body, and every CSP violation. The violation listener
 * is installed by the driver before any page script runs, so the CSP cannot
 * block it. */
async function firstVisit(page) {
  const requests = [];
  const violations = [];
  const shipped = [];
  page.on('request', (request) => requests.push(request.url()));
  page.on('console', (message) => {
    if (/content.security.policy/i.test(message.text())) violations.push(message.text());
  });
  page.on('response', (response) => {
    const type = response.request().resourceType();
    if (type === 'script' || type === 'stylesheet' || type === 'document') shipped.push(response);
  });
  await page.addInitScript(() => {
    window.__compliance = [];
    document.addEventListener('securitypolicyviolation', (event) => {
      window.__compliance.push(`${event.violatedDirective} ${event.blockedURI}`);
    });
  });
  await page.goto('/');
  await page.waitForLoadState('networkidle');
  await page.evaluate(async () => {
    for (let y = 0; y < document.documentElement.scrollHeight; y += window.innerHeight) {
      window.scrollTo(0, y);
      await new Promise((resolve) => setTimeout(resolve, 60));
    }
  });
  await page.waitForLoadState('networkidle');
  violations.push(...(await page.evaluate(() => window.__compliance)));
  return { requests, violations, shipped };
}

test('a first visit contacts no undeclared origin, breaks no CSP rule and stores nothing', async ({ page, context }) => {
  const { requests, violations } = await firstVisit(page);
  const own = new URL(page.url()).origin;

  const foreign = [...new Set(requests)]
    .filter((url) => /^https?:/.test(url))
    .map((url) => new URL(url).origin)
    .filter((origin) => origin !== own && !declaredOrigins.has(origin));
  expect(
    [...new Set(foreign)],
    'every request stays on this origin unless compliance.json declares it — lift: add ' +
      '{"origin": "<origin>", "purpose": "...", "consent": "not-required", "reason": "..."} to thirdParties',
  ).toEqual([]);

  expect(violations, 'the page asked for nothing its own CSP refuses').toEqual([]);

  const cookies = (await context.cookies()).map((cookie) => cookie.name);
  const stored = await page.evaluate(async () => ({
    local: Object.keys(window.localStorage),
    session: Object.keys(window.sessionStorage),
    databases:
      typeof indexedDB.databases === 'function' ? (await indexedDB.databases()).map((db) => db.name) : [],
  }));
  expect(
    { cookies, ...stored },
    'nothing is written to the visitor’s device before they act; storage[] admits only visitor-action writes',
  ).toEqual({ cookies: [], local: [], session: [], databases: [] });
});

test('the rendered page meets the WCAG 2.1 floors a browser can measure', async ({ page, browserName }) => {
  await page.goto('/');
  await page.waitForLoadState('networkidle');

  // 3.1.1 Language of Page.
  expect(await page.locator('html').getAttribute('lang'), 'the document declares its language').toMatch(/\S/);

  // 1.1.1 Non-text Content: every image says what it is, or says it is decoration (alt="").
  const unlabelledImages = await page.locator('img:not([alt])').evaluateAll((images) =>
    images.map((image) => image.currentSrc || image.getAttribute('src')),
  );
  expect(unlabelledImages, 'every <img> carries an alt attribute').toEqual([]);

  // 2.4.3 Focus Order: no positive tabindex reorders the page.
  const reordered = await page
    .locator('[tabindex]')
    .evaluateAll((elements) => elements.filter((element) => element.tabIndex > 0).map((element) => element.outerHTML.slice(0, 80)));
  expect(reordered, 'no element takes a positive tabindex').toEqual([]);

  // 4.1.2 Name, Role, Value and 1.3.1/3.3.2 labels: every control a visitor can see has a name.
  const controls = page.locator(
    'a[href], button, input:not([type="hidden"]), select, textarea, [role="button"], [role="link"], ' +
      '[role="checkbox"], [role="switch"], [role="tab"], [role="menuitem"], [role="menuitemradio"], [role="slider"]',
  );
  let named = 0;
  for (const control of await controls.all()) {
    if (!(await control.isVisible())) continue;
    const shape = await control.evaluate((element) => element.outerHTML.slice(0, 80));
    await expect(control, `${shape} has an accessible name`).toHaveAccessibleName(/\S/);
    named += 1;
  }
  expect(named, 'the page offers at least one control, so the sweep above measured something').toBeGreaterThan(0);

  // 2.4.7 Focus Visible: whatever the keyboard reaches shows where it is.
  const stops = [];
  for (let step = 0; step < 40; step += 1) {
    await page.keyboard.press('Tab');
    const stop = await page.evaluate(() => {
      const element = document.activeElement;
      if (!element || element === document.body) return null;
      const style = getComputedStyle(element);
      const outlined = style.outlineStyle !== 'none' && parseFloat(style.outlineWidth) > 0;
      return {
        key: `${element.tagName}:${element.getBoundingClientRect().x}:${element.getBoundingClientRect().y + window.scrollY}`,
        shape: element.outerHTML.slice(0, 80),
        visible: outlined || style.boxShadow !== 'none',
      };
    });
    if (stop === null || stops.some((seen) => seen.key === stop.key)) break;
    stops.push(stop);
  }
  // WebKit keeps Safari's default tab order, which skips links and buttons, so
  // only the engines that tab to every control are asked to reach one; what
  // WebKit does reach is still held to the ring below.
  if (browserName !== 'webkit') {
    expect(stops.length, 'the keyboard reaches at least one control').toBeGreaterThan(0);
  }
  expect(
    stops.filter((stop) => !stop.visible).map((stop) => stop.shape),
    'every keyboard stop shows a focus outline or ring',
  ).toEqual([]);
});

test('no credential-shaped literal ships in the document, a script or a stylesheet', async ({ page }) => {
  const { shipped } = await firstVisit(page);
  const own = new URL(page.url()).origin;
  const bodies = [];
  for (const response of shipped) {
    if (new URL(response.url()).origin !== own) continue;
    bodies.push([response.url(), await response.text()]);
  }
  expect(bodies.length, 'the visit served the document and its bundle').toBeGreaterThan(1);
  const hits = [];
  for (const [url, body] of bodies) {
    for (const [name, shape] of credentialShapes) {
      if (shape.test(body)) hits.push(`${name} in ${new URL(url).pathname}`);
    }
  }
  expect(hits, 'a value injected at build time is a published secret').toEqual([]);
});

test('every published legal page is linked from the page and served', async ({ page, request }) => {
  test.skip(
    publishedPages.length === 0,
    `no legal page is published yet: ${pendingPages.map((entry) => `${entry.id} (${entry.decision})`).join(', ')}`,
  );
  await page.goto('/');
  await page.waitForLoadState('networkidle');
  for (const entry of publishedPages) {
    await expect(page.locator(`a[href="${entry.path}"]`).first(), `the page links ${entry.path}`).toBeVisible();
    const answer = await request.get(entry.path);
    expect(answer.status(), `${entry.path} is served`).toBe(200);
    expect(answer.headers()['content-type'] ?? '', `${entry.path} is a page`).toMatch(/^text\/html/);
  }
});
