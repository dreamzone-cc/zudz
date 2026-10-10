<script lang="ts">
  import { tr,westernDigits } from '$lib/i18n';
  import { api } from '$lib/api';

  let host = '192.168.1.1';
  let user = 'admin';
  let password = 'admin';
  let vid = 'ZTEG';
  let sn8 = '';
  let ploam = '';
  let busy = '';
  let err = '';
  let read: Record<string, string> | null = null;
  let cloneOut = '';
  let backupPath = '';

  async function doRead() {
    busy = 'read'; err = ''; read = null;
    try { const r = await api.gponRead({ host, user, password }); read = r.tags; }
    catch (e: any) { err = String(e?.message || e); }
    finally { busy = ''; }
  }
  async function doClone() {
    busy = 'clone'; err = ''; cloneOut = ''; backupPath = '';
    try {
      const r = await api.gponClone({ host, user, password });
      cloneOut = r.commands.join('\n') + '\n\n' + r.output;
      backupPath = r.backup?.report_path || '';
    }
    catch (e: any) { err = String(e?.message || e); }
    finally { busy = ''; }
  }
  async function doWrite() {
    busy = 'write'; err = ''; backupPath = '';
    try {
      const r = await api.gponWrite({ host, user, password, vid, sn8, ploam });
      cloneOut = r.commands.join('\n') + '\n\n' + r.output;
      backupPath = r.backup?.report_path || '';
    }
    catch (e: any) { err = String(e?.message || e); }
    finally { busy = ''; }
  }
</script>

<div class="card">
  <h2>{$tr('gpon.title')}</h2>
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
  <button on:click={doRead} disabled={!!busy}>{busy === 'read' ? $tr('common.running') : $tr('gpon.read')}</button>
  {#if read}
    <div class="grid" style="margin-block-start:12px">
      <div class="kv"><span class="k">VID</span><span class="v">{read['2176'] || ''}</span></div>
      <div class="kv"><span class="k">SN8</span><span class="v">{read['2177'] || ''}</span></div>
      <div class="kv"><span class="k">PLOAM</span><span class="v">{read['2178'] || ''}</span></div>
      <div class="kv"><span class="k">MAC</span><span class="v">{read['256'] || ''}</span></div>
    </div>
  {/if}
</div>

<div class="card">
  <h2>{$tr('gpon.clone')}</h2>
  <div class="desc">{$tr('gpon.cloneDesc')}</div>
  <div class="desc">🛡️ {$tr('region.autoBackup')}</div>
  <button class="sec" on:click={doClone} disabled={!!busy}>{busy === 'clone' ? $tr('common.running') : $tr('gpon.clone')}</button>
</div>

<div class="card">
  <h2>{$tr('gpon.write')}</h2>
  <div class="grid">
    <div><label class="f">{$tr('gpon.vid')}</label><input type="text" class="mono" bind:value={vid} /></div>
    <div><label class="f">{$tr('gpon.sn8')}</label><input type="text" class="mono" bind:value={sn8} /></div>
    <div><label class="f">{$tr('gpon.ploam')}</label><input type="text" class="mono" bind:value={ploam} /></div>
  </div>
  <div class="desc">🛡️ {$tr('region.autoBackup')}</div>
  <button on:click={doWrite} disabled={!!busy}>{busy === 'write' ? $tr('common.running') : $tr('gpon.write')}</button>
</div>

{#if err}<div class="card"><div class="msg err">{westernDigits(err)}</div></div>{/if}
{#if backupPath}<div class="card"><div class="msg ok">🛡️ {$tr('common.autoBackupAt')}: <span class="mono">{westernDigits(backupPath)}</span></div></div>{/if}
{#if cloneOut}<div class="card"><pre class="out">{westernDigits(cloneOut)}</pre></div>{/if}
