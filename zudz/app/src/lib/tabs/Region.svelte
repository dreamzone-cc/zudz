<script lang="ts">
  import { tr, westernDigits } from '$lib/i18n';
  import { api, type Region as RegionInfo, type Report } from '$lib/api';

  let host = '192.168.1.1';
  let user = 'admin';
  let password = 'admin';
  let regions: RegionInfo[] = [];
  let selected = 198;
  let custom = '';
  let useCustom = false;

  let prepBusy = false;
  let token = '';
  let summary: Report | null = null;

  let confirmed = false;
  let permTelnet = true;
  let changeBusy = false;
  let result: any = null;
  let err = '';

  api.regions().then((r) => (regions = r.regions)).catch(() => {});

  async function prepare() {
    prepBusy = true; err = ''; token = ''; summary = null; result = null;
    try {
      const r = await api.regionPrepare({ host, user, password });
      token = r.token;
      summary = r.summary;
    } catch (e: any) {
      err = String(e?.message || e);
    } finally {
      prepBusy = false;
    }
  }

  async function change() {
    changeBusy = true; err = ''; result = null;
    try {
      const code = useCustom ? Number(custom) || 0 : selected;
      const r = await api.regionChange({
        host, user, password, code, ack: token, perm_telnet: permTelnet,
        force_unknown: useCustom,
      });
      result = r.result;
      token = ''; // استُهلك
    } catch (e: any) {
      err = String(e?.message || e);
    } finally {
      changeBusy = false;
    }
  }

  $: canChange = token && confirmed && (useCustom ? !!custom : true);
</script>

<div class="card">
  <h2>{$tr('region.title')}</h2>
  <div class="desc">{$tr('region.desc')}</div>
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
</div>

<div class="card">
  <h2>{$tr('region.prepare')}</h2>
  <div class="desc">{$tr('region.prepareDesc')}</div>
  <button on:click={prepare} disabled={prepBusy}>{prepBusy ? $tr('common.running') : $tr('region.prepare')}</button>
  {#if summary}
    <div class="msg ok">
      PPPoE: {westernDigits(summary.pppoe.username)} / {westernDigits(summary.pppoe.password)} @ VLAN {westernDigits(summary.pppoe.vlan)}
      | SIP: {westernDigits(summary.voip.sip_uri)} / {westernDigits(summary.voip.password)}
      | GPON: {westernDigits(summary.gpon.full_sn)} / {westernDigits(summary.gpon.ploam_password)}
    </div>
    <div class="msg warn">{$tr('region.ackGenerated')}</div>
    <label class="f">{$tr('region.ack')}</label>
    <input type="text" class="mono" bind:value={token} readonly />
  {/if}
  {#if err}<div class="msg err">{westernDigits(err)}</div>{/if}
</div>

<div class="card">
  <h2>{$tr('region.change')}</h2>
  <div class="desc">{$tr('region.list')}</div>
  <table class="tbl">
    <thead>
      <tr><th>{$tr('region.code')}</th><th>{$tr('region.name')}</th><th></th><th></th></tr>
    </thead>
    <tbody>
      {#each regions as r (r.code)}
        <tr>
          <td class="v">{r.code}</td>
          <td>{r.name}</td>
          <td>{r.verified ? $tr('region.verified') : ''}</td>
          <td><input type="radio" name="region" value={r.code} checked={!useCustom && selected === r.code}
            on:change={() => { selected = r.code; useCustom = false; }} /></td>
        </tr>
      {/each}
      <tr>
        <td colspan="3">{$tr('region.custom')}</td>
        <td><input type="radio" name="region" checked={useCustom} on:change={() => (useCustom = true)} /></td>
      </tr>
    </tbody>
  </table>
  {#if useCustom}
    <label class="f">{$tr('region.custom')}</label>
    <input type="number" class="mono" bind:value={custom} />
  {/if}

  <div class="warnbox">
    <label style="display:flex;gap:10px;align-items:flex-start;cursor:pointer">
      <input type="checkbox" style="margin-block-start:4px" bind:checked={confirmed} />
      <span><strong>⚠️</strong> {$tr('region.confirmWarn')}</span>
    </label>
    <label style="display:flex;gap:10px;align-items:center;cursor:pointer;margin-block-start:8px">
      <input type="checkbox" bind:checked={permTelnet} />
      <span>{$tr('region.permTelnet')}</span>
    </label>
  </div>

  <button class="danger" on:click={change} disabled={!canChange || changeBusy}>
    {changeBusy ? $tr('common.running') : $tr('region.execute')}
  </button>
  {#if result}
    <div class="msg ok">✅ {$tr('region.done')} — {westernDigits(String(result.code))} {result.region_name}</div>
    <pre class="out">{westernDigits(result.raw_output)}</pre>
  {/if}
</div>
