<script lang="ts">
  import { onMount } from 'svelte';

  /*
    Theme switching, client side. The origin already decided the theme for
    this document and stamped it on the root element, so this component
    never sets a theme at load: it READS the stamp, and only a visitor's
    click changes anything. That ordering is what keeps the first paint
    correct — there is no scripted correction to flash — and it keeps the
    origin free of cookie state, because the browser writes the preference
    the next navigation will be answered with.
  */
  const themeAttribute = 'data-theme';
  const themeCookie = 'lidersea_theme';
  const cookieMaxAgeSeconds = 31536000;

  const options = [
    { id: 'system', label: 'System' },
    { id: 'light', label: 'Light' },
    { id: 'dark', label: 'Dark' },
    { id: 'sepia', label: 'Sepia' },
  ];

  const stamped = document.documentElement.getAttribute(themeAttribute) ?? '';
  let active = $state(
    options.some((option) => option.id === stamped) ? stamped : options[0].id,
  );
  let open = $state(false);
  let menu = $state<HTMLElement | undefined>(undefined);

  const activeLabel = $derived(
    options.find((option) => option.id === active)?.label ?? options[0].label,
  );

  /*
    Dismissal has to survive two real browser behaviours. Safari does not
    focus a button when it is clicked, so closing on blur would leave the
    popover stuck open there; and a listener that outlives the open state
    would keep firing for nothing. So the pointer listener exists only while
    the menu is open, and Escape closes it from the keyboard.
  */
  $effect(() => {
    if (!open) return;
    const dismiss = (event: PointerEvent) => {
      if (!menu?.contains(event.target as Node)) open = false;
    };
    window.addEventListener('pointerdown', dismiss);
    return () => window.removeEventListener('pointerdown', dismiss);
  });

  function choose(id: string): void {
    active = id;
    open = false;
    document.documentElement.setAttribute(themeAttribute, id);
    /*
      A display preference and nothing else: no identifier, no session, and
      nothing the origin consults for any security decision. Lax keeps it
      off cross-site requests; Secure is added only where the page is
      already on TLS, so a local development page can still store one.
    */
    const attributes = [
      `${themeCookie}=${id}`,
      'Path=/',
      `Max-Age=${cookieMaxAgeSeconds}`,
      'SameSite=Lax',
    ];
    if (window.location.protocol === 'https:') {
      attributes.push('Secure');
    }
    document.cookie = attributes.join('; ');
  }

  /*
    The ratings strip. Every value it shows comes from this origin's own
    ratings surface — there is no third-party script, widget, iframe, or
    image anywhere in it, which is why the site's CSP can stay as strict as
    it is. Platform names render as our own text and the outbound links are
    plain anchors.

    The strip is honest about its own state rather than hiding an empty
    answer: it says when it is still loading, when the surface could not be
    read, and when a platform has no captured rating yet. It never invents
    a number.
  */
  const ratingsSurface = '/api/ratings';

  type RatingsPlatform = {
    id: string;
    name: string;
    state: string;
    profileUrl?: string;
    rating?: number;
    reviewCount?: number;
  };
  type RatingsSummary = { published: number; reviews: number; average?: number; scale: number };
  type RatingsData = { summary: RatingsSummary; platforms: RatingsPlatform[] };

  let ratingsState = $state<'loading' | 'ready' | 'unavailable'>('loading');
  let ratings = $state<RatingsData | undefined>(undefined);

  onMount(async () => {
    try {
      const response = await fetch(ratingsSurface, { headers: { accept: 'application/json' } });
      if (!response.ok) {
        ratingsState = 'unavailable';
        return;
      }
      const envelope = await response.json();
      ratings = envelope.data as RatingsData;
      ratingsState = 'ready';
    } catch {
      /* A surface that cannot be read is reported as unreadable, never as empty. */
      ratingsState = 'unavailable';
    }
  });

  /* Percentage of the scale, for the meter that pairs shape with the number. */
  function meterPercent(platform: RatingsPlatform, scale: number): number {
    return Math.round(((platform.rating ?? 0) / scale) * 100);
  }

  function linkLabel(platform: RatingsPlatform, scale: number): string {
    const value =
      platform.state === 'published'
        ? `rated ${platform.rating} out of ${scale} from ${platform.reviewCount} reviews`
        : 'no rating captured yet';
    return `${platform.name}: ${value}. Opens in a new tab.`;
  }
</script>

<svelte:head>
  <meta
    name="description"
    content="lidersea.com is getting ready. Please check back soon."
  />
</svelte:head>

<svelte:window
  onkeydown={(event) => {
    if (open && event.key === 'Escape') open = false;
  }}
/>

<div class="shell">
  <header class="chrome">
    <div class="theme-menu" bind:this={menu}>
      <button
        type="button"
        class="theme-menu__trigger"
        aria-haspopup="true"
        aria-expanded={open}
        aria-label="Appearance: {activeLabel}"
        onclick={() => (open = !open)}
      >
        <svg class="theme-menu__icon" viewBox="0 0 24 24" aria-hidden="true" focusable="false">
          <circle class="theme-menu__icon-ring" cx="12" cy="12" r="9" />
          <path class="theme-menu__icon-half" d="M12 3a9 9 0 0 1 0 18Z" />
        </svg>
      </button>

      {#if open}
        <div class="theme-menu__popover" role="group" aria-label="Appearance">
          {#each options as option (option.id)}
            <button
              type="button"
              class="theme-menu__option"
              aria-pressed={active === option.id}
              onclick={() => choose(option.id)}
            >
              <span class="theme-menu__swatch" data-swatch={option.id} aria-hidden="true"></span>
              <span>{option.label}</span>
              <span class="theme-menu__check" aria-hidden="true"
                >{active === option.id ? '✓' : ''}</span
              >
            </button>
          {/each}
        </div>
      {/if}
    </div>
  </header>

  <main aria-labelledby="page-title">
    <div class="message">
      <h1 id="page-title">Hello World!</h1>
      <p>Website coming soon!</p>
    </div>
  </main>

  <footer class="ratings" aria-labelledby="ratings-title" data-ratings-state={ratingsState}>
    <h2 class="ratings__title" id="ratings-title">Where clients rate us</h2>

    {#if ratingsState === 'loading'}
      <p class="ratings__note">Loading ratings…</p>
    {:else if ratingsState === 'unavailable' || !ratings}
      <p class="ratings__note">Ratings are unavailable right now.</p>
    {:else}
      {#if ratings.summary.published === 0}
        <p class="ratings__note">
          No ratings collected yet — these are the platforms we publish on.
        </p>
      {:else}
        <p class="ratings__note">
          {ratings.summary.average} out of {ratings.summary.scale} across
          {ratings.summary.reviews} reviews on {ratings.summary.published} platforms.
        </p>
      {/if}

      <ul class="ratings__list">
        {#each ratings.platforms as platform (platform.id)}
          <li class="ratings__platform">
            {#if platform.profileUrl}
              <a
                class="ratings__anchor"
                href={platform.profileUrl}
                target="_blank"
                rel="noopener noreferrer"
                aria-label={linkLabel(platform, ratings.summary.scale)}
              >
                {platform.name}
              </a>
            {:else}
              <span class="ratings__anchor ratings__anchor--inert">{platform.name}</span>
            {/if}

            {#if platform.state === 'published'}
              <!--
                The number carries the value; the meter repeats it as length
                and the count as text. No value on this site is ever encoded
                by colour alone.
              -->
              <span class="ratings__value">
                {platform.rating}<span class="ratings__scale">/{ratings.summary.scale}</span>
              </span>
              <span class="ratings__meter" aria-hidden="true">
                <span
                  class="ratings__meter-fill"
                  style="inline-size: {meterPercent(platform, ratings.summary.scale)}%"
                ></span>
              </span>
              <span class="ratings__count">{platform.reviewCount} reviews</span>
            {:else}
              <span class="ratings__value ratings__value--pending">Not rated yet</span>
            {/if}
          </li>
        {/each}
      </ul>
    {/if}
  </footer>
</div>
