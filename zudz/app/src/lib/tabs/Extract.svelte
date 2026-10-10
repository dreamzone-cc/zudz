<script lang="ts">
  import { tr,fmtBytes, westernDigits } from '$lib/i18n';
  import { api, type Report } from '$lib/api';

  let host = '192.168.1.1';
  let user = 'admin';
  let password = 'admin';
  let busy = false;
  let err = '';
  let report: Report | null = null;

  async function run() {
    busy = true; err = ''; report = null;
    try {
      const r = await api.extract({ host, user, password });
      report = r.report;
    } catch (e: any) {
      err = String(e?.message || e);
    } finally {
      busy = false;
    }
  }

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
  <button on:click={run} disabled={busy}>{busy ? $tr('common.running') : $tr('common.run')}</button>
  {#if err}<div class="msg err">{$tr('common.error')}: {westernDigits(err)}</div>{/if}
</div>

{#if report}
  <div class="card">
    <h2>{$tr('common.result')}
      <button class="copybtn sec" style="margin-inline-start:10px" on:click={download}>{$tr('common.download')}</button>
    </h2>
    <div class="grid">
      <div>
        <h3 style="font-size:.9rem;color:var(--dim)">{$tr('extract.gpon')}</h3>
        <div class="kv"><span class="k">{$tr('extract.gponSn')}</span>
          <span class="v">{westernDigits(report.gpon.full_sn)}
            <button class="copybtn" on:click={() => copy(report!.gpon.full_sn)}>{copied === report!.gpon.full_sn ? $tr('common.copied') : $tr('common.copy')}</button></span></div>
        <div class="kv"><span class="k">{$tr('extract.ploam')}</span><span class="v">{westernDigits(report.gpon.ploam_password)}</span></div>
        <div class="kv"><span class="k">{$tr('extract.mac')}</span><span class="v">{westernDigits(report.device.base_mac)}</span></div>
      </div>
      <div>
        <h3 style="font-size:.9rem;color:var(--dim)">{$tr('extract.pppoe')}</h3>
        <div class="kv"><span class="k">{$tr('extract.pppoeUser')}</span><span class="v">{westernDigits(report.pppoe.username)}</span></div>
        <div class="kv"><span class="k">{$tr('extract.pppoePass')}</span>
          <span class="v">{westernDigits(report.pppoe.password)}
            <button class="copybtn" on:click={() => copy(report!.pppoe.password)}>{copied === report!.pppoe.password ? $tr('common.copied') : $tr('common.copy')}</button></span></div>
        <div class="kv"><span class="k">{$tr('extract.vlan')}</span><span class="v">{fmtBytes(Number(report.pppoe.vlan) || 0) && westernDigits(report.pppoe.vlan)}</span></div>
      </div>
      <div>
        <h3 style="font-size:.9rem;color:var(--dim)">{$tr('extract.voip')}</h3>
        <div class="kv"><span class="k">{$tr('extract.sipUri')}</span><span class="v">{westernDigits(report.voip.sip_uri)}</span></div>
        <div class="kv"><span class="k">{$tr('extract.sipPass')}</span><span class="v">{westernDigits(report.voip.password)}</span></div>
        <div class="kv"><span class="k">{$tr('extract.registrar')}</span><span class="v">{report.voip.registrar}</span></div>
      </div>
      <div>
        <h3 style="font-size:.9rem;color:var(--dim)">{$tr('extract.wifi')}</h3>
        <div class="kv"><span class="k">{$tr('extract.ssid24')}</span><span class="v">{report.wifi_defaults.ssid_24g}</span></div>
        <div class="kv"><span class="k">{$tr('extract.ssid5')}</span><span class="v">{report.wifi_defaults.ssid_5g}</span></div>
        <div class="kv"><span class="k">{$tr('extract.psk')}</span><span class="v">{report.wifi_defaults.psk}</span></div>
      </div>
    </div>
    <div style="margin-block-start:10px;color:var(--dim);font-size:.8rem">
      {$tr('extract.sources')}: {report.sources.join(' + ')}
    </div>
  </div>
{/if}
