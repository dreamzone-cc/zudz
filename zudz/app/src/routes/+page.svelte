<script lang="ts">
  import { onMount } from 'svelte';
  import { locale, tr } from '$lib/i18n';
  import { api, type Meta, FALLBACK_META } from '$lib/api';
  import ExtractTab from '$lib/tabs/Extract.svelte';
  import RegionTab from '$lib/tabs/Region.svelte';
  import GponTab from '$lib/tabs/Gpon.svelte';
  import DecryptTab from '$lib/tabs/Decrypt.svelte';

  let tab: 'extract' | 'region' | 'gpon' | 'decrypt' = 'extract';
  const tabs = [
    { id: 'extract', key: 'nav.extract' },
    { id: 'region', key: 'nav.region' },
    { id: 'gpon', key: 'nav.gpon' },
    { id: 'decrypt', key: 'nav.decrypt' },
  ] as const;

  // معلومات المطوّر والترخيص — من الخادم عند توفّره، وإلا القيم الثابتة
  let meta: Meta = FALLBACK_META;
  onMount(async () => {
    try {
      meta = await api.version();
    } catch {
      meta = FALLBACK_META;
    }
  });

  let aboutOpen = false;
  function toggleAbout() {
    aboutOpen = !aboutOpen;
  }
</script>

<div class="app">
  <header class="top">
    <div class="logo"><img src="/zudz.svg" class="logo-img" alt="ZUDZ" /> ZUDZ</div>
    <div class="subtitle">{$tr('app.subtitle')}</div>
    <div class="spacer"></div>
    <button class="infobtn" on:click={toggleAbout} aria-label="about"
      title="{$tr('meta.about')}">ⓘ</button>
    <div class="lang" role="group" aria-label="language">
      {#each ['ar', 'fr', 'en'] as l}
        <button class="tab" style="margin:0;padding:6px 14px;font-size:.85rem"
          class:active={$locale === l}
          on:click={() => { locale.set(l as any); }}>
          {$tr(`lang.${l}`)}
        </button>
      {/each}
    </div>
  </header>

  <nav class="tabs">
    {#each tabs as tb (tb.id)}
      <button class="tab" class:active={tab === tb.id} on:click={() => (tab = tb.id)}>
        {$tr(tb.key)}
      </button>
    {/each}
  </nav>

  {#if tab === 'extract'}
    <ExtractTab />
  {:else if tab === 'region'}
    <RegionTab />
  {:else if tab === 'gpon'}
    <GponTab />
  {:else}
    <DecryptTab />
  {/if}

  {#if aboutOpen}
    <div class="modal-backdrop" on:click={toggleAbout}>
      <div class="modal" on:click|stopPropagation role="dialog" aria-modal="true">
        <div class="modal-head">
          <div class="logo"><img src="/zudz.svg" class="logo-img" alt="" /> {meta.name}</div>
          <button class="copybtn" on:click={toggleAbout}>{$tr('common.close')}</button>
        </div>
        <div class="modal-sub">{meta.tagline} — {$tr('meta.version')} {meta.version}</div>

        <div class="about-rows">
          <div class="kv"><span class="k">{$tr('meta.developer')}</span>
            <span class="v"><a href={meta.homepage} target="_blank" rel="noopener">{meta.author}</a></span></div>
          <div class="kv"><span class="k">{$tr('meta.github')}</span>
            <span class="v"><a href={meta.homepage} target="_blank" rel="noopener">{meta.homepage}</a></span></div>
          <div class="kv"><span class="k">{$tr('meta.discord')}</span>
            <span class="v">{meta.discord}</span></div>
          <div class="kv"><span class="k">{$tr('meta.license')}</span>
            <span class="v"><a href={meta.license_url} target="_blank" rel="noopener">{meta.license_name}</a>
              <span class="badge">{meta.license}</span></span></div>
          <div class="kv"><span class="k">{$tr('meta.purpose')}</span>
            <span class="vt">{meta.purpose}</span></div>
          <div class="kv"><span class="k">{$tr('meta.scope')}</span>
            <span class="vt">{meta.personal_only}</span></div>
        </div>

        <div class="warnbox">
          <strong>⚠️ {$tr('meta.noIllegal')}</strong>
        </div>

        <div class="about-links">
          <a href="https://github.com/dreamzone-cc" target="_blank" rel="noopener">{$tr('meta.disclaimer')} (DISCLAIMER.md) · {$tr('meta.report')} (REPORT.md) · LICENSE</a>
        </div>
      </div>
    </div>
  {/if}

  <footer>
    {meta.name} v{meta.version} — {$tr('app.subtitle')}<br />
    <span class="foot-dev">
      {$tr('meta.developer')}: <a href={meta.homepage} target="_blank" rel="noopener">{meta.author}</a>
      · {$tr('meta.discord')}: {meta.discord}
      · {$tr('meta.license')}: <a href={meta.license_url} target="_blank" rel="noopener">{meta.license}</a>
      · {$tr('meta.footerTag')}
    </span>
  </footer>
</div>
