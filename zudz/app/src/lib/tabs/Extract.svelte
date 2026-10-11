<script lang="ts">
  import { onDestroy } from 'svelte';
  import { tr, westernDigits } from '$lib/i18n';
  import { api, type Report } from '$lib/api';
  import Progress from '$lib/Progress.svelte';

  let host = '192.168.1.1';
  let user = 'admin';
  let password = 'admin';
  let out = 'zudz_extract_backup';
  let busy = false;
  let err = '';
  let report: Report | null = null;
  let saved: string[] = [];

  // مراحل السحب الحقيقية كما تُبلّغ من الخادم
  const STAGES = ['extract.stage.unlock', 'extract.stage.telnet', 'extract.stage.tagparams', 'extract.stage.pppd', 'extract.stage.cspd', 'extract.stage.web', 'extract.stage.report'];
  const STAGE_KEYS = ['unlock', 'telnet', 'tagparams', 'pppd', 'cspd', 'web', 'report', 'saving', 'done'];
  let activeStage = -1;
  let pct = 0;
  let pollTimer: ReturnType<typeof setInterval> | null = null;

  async function run() {
    busy = true; err = ''; report = null; saved = [];
    activeStage = 0; pct = 4;
    try {
      await api.extractStart({ host, user, password, out });
      pollTimer = setInterval(poll, 600);
    } catch (e: any) {
      err = String(e?.message || e);
      busy = false;
    }
  }

  async function poll() {
    try {
      const s = await api.extractStatus();
      const idx = STAGE_KEYS.indexOf(s.stage);
      activeStage = idx >= 0 ? Math.min(idx, STAGES.length - 1) : activeStage;
      // نسبة تقديرية: موضع المرحلة داخل السلسلة
      const frac = s.done ? 1 : ((idx >= 0 ? idx : 0) + 0.6) / STAGE_KEYS.length;
      pct = Math.max(pct, Math.min(96, Math.round(frac * 100)));
      if (s.error) { err = s.error; }
      if (s.done || s.error) {
        if (pollTimer) clearInterval(pollTimer);
        pollTimer = null;
        if (s.report) { report = s.report; saved = s.saved || []; pct = 100; }
        busy = false;
      }
    } catch (e: any) {
      if (pollTimer) clearInterval(pollTimer);
      pollTimer = null;
      err = String(e?.message || e);
      busy = false;
    }
  }

  onDestroy(() => { if (pollTimer) clearInterval(pollTimer); });

  function download() {
    if (!report) return;
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'zudz-report.json';
    a.click();
    URL.revokeObjectURL(a.href);
  }

  let copied = '';
  function copy(v: string) {
    navigator.clipboard?.writeText(v);
    copied = v;
    setTimeout(() => (copied = ''), 1200);
  }
</script>

<div class="card">
  <h2>{$tr('extract.title')}</h2>
  <div class="desc">{$tr('extract.desc')}</div>
  <div class="grid">
    <div>
      <label class="f">{$tr('common.host')}</label>
      <input type="text" class="mono" bind:value={host} />
    </div>
    <div>
      <label class="f">{$tr('common.user')}</label>
      <input type="text" class="mono" bind:value={user} />
    </div>
    <div>
      <label class="f">{$tr('common.password')}</label>
      <input type="password" class="mono" bind:value={password} />
    </div>
  </div>
  <div class="grid" style="margin-block-start:10px">
    <div style="grid-column: 1 / -1">
      <label class="f">{$tr('extract.out')}</label>
      <input type="text" class="mono" bind:value={out} placeholder="zudz_extract_backup" />
      <div class="hint">{$tr('extract.outHint')}</div>
    </div>
  </div>
  <button on:click={run} disabled={busy}>{busy ? $tr('common.running') : $tr('common.run')}</button>

  {#if busy}
    <Progress percent={pct} stages={STAGES} active={Math.max(0, activeStage)} done={false} />
  {/if}
  {#if err}<div class="msg err">{$tr('common.error')}: {westernDigits(err)}</div>{/if}
</div>

{#if report}
  <div class="card">
    <h2>{$tr('common.result')}
      <button class="copybtn sec" style="margin-inline-start:10px" on:click={download}>{$tr('common.download')}</button>
    </h2>
    <Progress percent={100} stages={STAGES} active={STAGES.length - 1} done={true} />
    {#if saved.length}
      <div class="msg ok">💾 {$tr('extract.saved')}:
        {#each saved as p, i}
          {#if i > 0}<span class="dim"> · </span>{/if}<span class="mono path">{westernDigits(p)}</span>
        {/each}
      </div>
    {/if}
    <div class="grid">
      <div>
        <h3 class="subh">{$tr('extract.gpon')}</h3>
        <div class="kv"><span class="k">{$tr('extract.gponSn')}</span>
          <span class="v">{westernDigits(report.gpon.full_sn)}
            <button class="copybtn" on:click={() => copy(report!.gpon.full_sn)}>{copied === report!.gpon.full_sn ? $tr('common.copied') : $tr('common.copy')}</button></span></div>
        <div class="kv"><span class="k">{$tr('extract.ploam')}</span>
          <span class="v">{westernDigits(report.gpon.ploam_password)}
            <button class="copybtn" on:click={() => copy(report!.gpon.ploam_password)}>{copied === report!.gpon.ploam_password ? $tr('common.copied') : $tr('common.copy')}</button></span></div>
        <div class="kv"><span class="k">{$tr('extract.mac')}</span><span class="v">{westernDigits(report.device.base_mac)}</span></div>
      </div>
      <div>
        <h3 class="subh">{$tr('extract.pppoe')}</h3>
        <div class="kv"><span class="k">{$tr('extract.pppoeUser')}</span><span class="v">{westernDigits(report.pppoe.username)}</span></div>
        <div class="kv"><span class="k">{$tr('extract.pppoePass')}</span>
          <span class="v">{westernDigits(report.pppoe.password)}
            <button class="copybtn" on:click={() => copy(report!.pppoe.password)}>{copied === report!.pppoe.password ? $tr('common.copied') : $tr('common.copy')}</button></span></div>
        <div class="kv"><span class="k">{$tr('extract.vlan')}</span><span class="v">{westernDigits(report.pppoe.vlan)}</span></div>
      </div>
      <div>
        <h3 class="subh">{$tr('extract.voip')}</h3>
        <div class="kv"><span class="k">{$tr('extract.sipUri')}</span><span class="v">{westernDigits(report.voip.sip_uri)}</span></div>
        <div class="kv"><span class="k">{$tr('extract.sipPass')}</span><span class="v">{westernDigits(report.voip.password)}</span></div>
        <div class="kv"><span class="k">{$tr('extract.registrar')}</span><span class="v">{report.voip.registrar}</span></div>
      </div>
      <div>
        <h3 class="subh">{$tr('extract.wifi')}</h3>
        <div class="kv"><span class="k">{$tr('extract.ssid24')}</span><span class="v">{report.wifi_defaults.ssid_24g}</span></div>
        <div class="kv"><span class="k">{$tr('extract.ssid5')}</span><span class="v">{report.wifi_defaults.ssid_5g}</span></div>
        <div class="kv"><span class="k">{$tr('extract.psk')}</span><span class="v">{report.wifi_defaults.psk}</span></div>
      </div>
    </div>
    <div class="sources">
      {$tr('extract.sources')}: {report.sources.join(' + ')}
    </div>
  </div>
{/if}
