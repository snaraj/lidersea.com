import { defineConfig, devices } from '@playwright/test';

/*
  Rendering lanes, stage 2 (issue #22): the real-browser half of the floors
  `tests/experience.test.mjs` pins as source facts.

  What this configuration deliberately does NOT do is start a dev server. The
  lanes drive the SHIPPED artifact — the Go binary with the built Svelte bundle
  embedded in it — over real HTTP, because that is the only thing a visitor
  ever meets. A Vite dev server serves different bytes through different
  middleware and would report on something no release contains. So the binary
  path is required rather than defaulted: a smoke lane that silently invented a
  server is worse than no smoke lane.
*/
const binary = process.env.LIDERSEA_SMOKE_BINARY;
if (!binary) {
  throw new Error(
    'LIDERSEA_SMOKE_BINARY must point at a built ./cmd/server binary. Build it first ' +
      '(cd frontend && npm run build; then CGO_ENABLED=0 go build -o <path> ./cmd/server) — ' +
      'these lanes drive the shipped artifact, never a dev server.',
  );
}

/*
  A port derived from this checkout's own path, not a hardcoded one and not an
  ephemeral one.

  Several agent lanes work this machine at once, in sibling worktrees and in
  BOTH site repositories, and AGENTS.md names that contention as a real hazard
  rather than a theoretical one. A hardcoded smoke port is a collision waiting
  to happen across them: this configuration's first draft picked one and
  immediately met a server belonging to ANOTHER repository's lane already
  holding it.

  Asking the kernel for a free port looks like the fix and is not: Playwright
  re-evaluates this config inside every worker process, so a fresh ephemeral
  port there disagrees with the one the server actually bound in the main
  process, and every navigation is refused. Whatever decides the port has to be
  a pure function of inputs identical in all of them.

  Hashing the directory is exactly that. It is stable across processes and runs,
  and distinct per worktree and per repository — which is precisely the axis the
  collisions happen on. The range is chosen to sit above the registered
  well-knowns and below the ephemeral ranges Linux (32768+) and macOS (49152+)
  hand out, so it cannot be taken by an unrelated outbound socket either.
*/
function derivedPort(seed) {
  // FNV-1a, 32-bit. Any stable hash would do; this one is four lines and needs
  // no dependency, which is the standing preference in this repository.
  let hash = 0x811c9dc5;
  for (const character of seed) {
    hash ^= character.codePointAt(0);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return String(20000 + (hash % 10000));
}

const port = process.env.LIDERSEA_SMOKE_PORT ?? derivedPort(new URL('.', import.meta.url).pathname);
if (!/^[1-9][0-9]{3,4}$/.test(port)) {
  throw new Error(`LIDERSEA_SMOKE_PORT must be an unprivileged port number, not ${port}`);
}
const origin = `http://127.0.0.1:${port}`;

/*
  Three engines, one phone viewport each — the bound issue #22 sets, and no
  more. Chromium answers for Chrome and Edge, WebKit for Safari and every iOS
  browser (which are all WebKit by App Store policy), and Gecko for Firefox.

  Chromium and WebKit take Playwright's phone descriptors, so those lanes carry
  real touch input, device pixel ratio, and a mobile user agent. Gecko has no
  mobile emulation at all, so its lane pins the same narrow viewport explicitly
  rather than pretending to be a phone it cannot emulate — an honest desktop
  Gecko at phone width is a true statement; a fake Android Gecko is not.

  Widths below these are exercised INSIDE the no-horizontal-scroll lane, which
  walks down to the 320px contract floor. Giving each width its own project
  would multiply the entire battery to measure one property.
*/
export default defineConfig({
  testDir: './tests/browser',
  testMatch: '**/*.spec.mjs',
  outputDir: './test-results',
  fullyParallel: true,
  /*
    No retries, ever. These lanes ARE the cross-engine flake probe; a retry
    converts a real nondeterminism into a green run, which is the single
    outcome this suite exists to prevent. AGENTS.md says a contention flake is
    named and rerun, never hidden — and a rerun a human decides on is not the
    same thing as one the runner performs silently.
  */
  retries: 0,
  forbidOnly: Boolean(process.env.CI),
  workers: process.env.CI ? 2 : undefined,
  reporter: [['list']],
  timeout: 30_000,
  expect: { timeout: 5_000 },
  use: {
    baseURL: origin,
    /*
      Nothing is recorded. Traces, videos, and screenshots would put megabytes
      into an artifact store for no signal a failing assertion does not already
      carry in text, and this repository keeps CI storage — like everything
      else it touches — at zero.
    */
    trace: 'off',
    video: 'off',
    screenshot: 'off',
  },
  webServer: {
    command: binary,
    env: { PORT: port },
    /*
      Readiness is the origin's own truthful probe (requirement 8), not a
      sleep: /readyz answers only once the binary can really serve.
    */
    url: `${origin}/readyz`,
    /*
      Never adopt a server this run did not start. `true` here would let the
      lanes silently measure whatever already held the port — on this machine
      that was a DIFFERENT repository's binary — and report the wrong site as
      green. Refusing to start is the fail-closed answer.
    */
    reuseExistingServer: false,
    timeout: 30_000,
    stdout: 'pipe',
    stderr: 'pipe',
  },
  projects: [
    { name: 'chromium-phone', use: { ...devices['Pixel 7'] } },
    { name: 'webkit-phone', use: { ...devices['iPhone 14'] } },
    {
      name: 'firefox-phone',
      use: { ...devices['Desktop Firefox'], viewport: { width: 390, height: 844 } },
    },
  ],
});
