<script lang="ts">
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
  ];

  const stamped = document.documentElement.getAttribute(themeAttribute) ?? '';
  let active = $state(
    options.some((option) => option.id === stamped) ? stamped : options[0].id,
  );

  function choose(id: string): void {
    active = id;
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
</script>

<svelte:head>
  <meta
    name="description"
    content="lidersea.com is getting ready. Please check back soon."
  />
</svelte:head>

<div class="shell">
  <header class="chrome">
    <div class="theme-switch" role="group" aria-label="Appearance">
      {#each options as option (option.id)}
        <button
          type="button"
          class="theme-switch__option"
          aria-pressed={active === option.id}
          onclick={() => choose(option.id)}
        >
          {option.label}
        </button>
      {/each}
    </div>
  </header>

  <main aria-labelledby="page-title">
    <div class="message">
      <h1 id="page-title">Hello World!</h1>
      <p>Website coming soon!</p>
    </div>
  </main>
</div>
