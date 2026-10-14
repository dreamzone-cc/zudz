<script lang="ts">
  import { tr, fmtBytes, westernDigits } from '$lib/i18n';
  import { api, type DiagRoute } from '$lib/api';
  import Progress from '$lib/Progress.svelte';
  import { parseZteXml, summarize, summaryToText, type ZteTable, type Summary } from '$lib/zte-xml';

  // ─── لوحة الاتصال بالجهاز ──────────────────────────────
  let chost = '192.168.1.1';
  let cuser = 'admin';
  let cpassword = 'admin';
  let connState: 'idle' | 'testing' | 'connected' | 'failed' = 'idle';
  let connPort = 0;
  let connLatency = 0;
  let connDetail = '';
  let diag: DiagRoute | null = null;

  // ─── مكان التخزين ───────────────────────────────────────
  let inputMode: 'browser' | 'path' = 'browser';
  let file: File | null = null;
  let path = '';
  let outMode: 'download' | 'device' = 'download';
  let outPath = 'zudz_backups/decrypted.xml';

  // ─── حالة التنفيذ والنتائج ───────────────────────────────
  let busy = '';
  let err = '';
  let inspectResult: { signature: string | null; payload_type: number | null; has_zte_header: boolean | null } | null = null;
  let decResult: { size: number; method: string; saved_to?: string } | null = null;
  let tables: ZteTable[] = [];
  let summary: Summary | null = null;
  let xmlText = '';

  // ─── تقدم العملية ───────────────────────────────────────
  let progActive = false;
  let progPercent = 0;
  let progStage = 0;
  let progStages: string[] = [];
  let progDone = false;
  let animTimer: ReturnType<typeof setInterval> | undefined;

  function setStages(stages: string[]) {
    progStages = stages; progStage = 0; progPercent = 0; progDone = false; progActive = true;
  }
  function stage(i: number, pct: number) { progStage = i; progPercent = pct; }
  function finishProgress() {
    progStage = progStages.length - 1; progPercent = 100; progDone = true;
    setTimeout(() => (progActive = false), 1500);
  }
  function startIndeterminate(cap: number) {
    stopAnim();
    animTimer = setInterval(() => {
      progPercent = Math.min(cap, progPercent + (cap - progPercent) * 0.07 + 0.8);
    }, 130);
  }
  function stopAnim() {
    if (animTimer) { clearInterval(animTimer); animTimer = undefined; }
  }

  // ─── أدوات ────────────────────────────────────────────────
  let copied = '__zudz_init__';
  function copy(v: string) {
    navigator.clipboard?.writeText(v);
    copied = v;
    setTimeout(() => (copied = '__zudz_init__'), 1200);
  }
  function bytesToB64(bytes: Uint8Array): string {
    let bin = '';
    const chunk = 0x8000;
    for (let i = 0; i < bytes.length; i += chunk) {
      bin += String.fromCharCode(...Array.from(bytes.subarray(i, i + chunk)));
    }
    return btoa(bin);
  }
  function downloadXml(xml: string) {
    const blob = new Blob([xml], { type: 'application/xml' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'zudz-decrypted.xml';
    a.click();
    URL.revokeObjectURL(a.href);
  }
  function onFilePicked(e: Event) {
    const t = e.target as HTMLInputElement;
    file = t.files?.[0] ?? null;
  }

  // ─── اختبار الاتصال ─────────────────────────────────────
  async function doPing() {
    setStages(['conn.testing', 'progress.done']);
    connState = 'testing'; connPort = 0; connLatency = 0; connDetail = '';
    try {
      stage(0, 40); startIndeterminate(85);
      const r = await api.devicePing({ host: chost, user: cuser, password: cpassword });
      stopAnim();
      if (r.connected) {
        connState = 'connected'; connPort = r.port; connLatency = r.latency_ms; connDetail = r.detail;
      } else {
        connState = 'failed'; connDetail = r.detail;
      }
      finishProgress();
    } catch (e: any) {
      stopAnim(); progActive = false;
      connState = 'failed'; connDetail = String(e?.message || e);
    }
  }

  // ─── المسار التشخيصي (MAC 00:07:29:55:35:57 — شرط فتح telnet) ──
  async function doDiagStatus() {
    try {
      diag = await api.diagRoute({ action: 'status', host: chost });
    } catch (e: any) {
      diag = { ok: false, status: 'no-route', note: String(e?.message || e) };
    }
  }

  // ─── قراءة الإدخال ────────────────────────────────────────
  async function readInput(): Promise<{ b64: string } | { machinePath: string }> {
    if (inputMode === 'browser') {
      if (!file) throw new Error('no file chosen');
      const buf = await file.arrayBuffer();
      return { b64: bytesToB64(new Uint8Array(buf)) };
    }
    if (!path.trim()) throw new Error('no path');
    return { machinePath: path.trim() };
  }

  // ─── فحص البنية ───────────────────────────────────────────
  async function doInspect() {
    busy = 'i'; err = ''; inspectResult = null; decResult = null;
    tables = []; summary = null; xmlText = '';
    setStages(['dec.stage.read', 'dec.stage.send', 'dec.stage.inspect', 'progress.done']);
    try {
      let info;
      if (inputMode === 'browser') {
        stage(0, 20);
        const r = await readInput();
        stage(1, 45); startIndeterminate(72);
        info = 'b64' in r
          ? await api.inspectContent({ content_b64: r.b64 })
          : await api.inspect({ path: r.machinePath });
        stopAnim();
      } else {
        stage(0, 30); startIndeterminate(72);
        info = await api.inspect({ path: path.trim() });
        stopAnim();
      }
      stage(2, 88);
      inspectResult = info;
      finishProgress();
    } catch (e: any) {
      stopAnim(); progActive = false;
      err = String(e?.message || e);
    } finally {
      busy = '';
    }
  }

  // ─── فك التشفير ─────────────────────────────────────────
  async function doDecrypt() {
    busy = 'd'; err = ''; inspectResult = null; decResult = null;
    tables = []; summary = null; xmlText = '';
    setStages(['dec.stage.read', 'dec.stage.send', 'dec.stage.decrypt', 'dec.stage.parse', 'progress.done']);
    try {
      let res;
      if (inputMode === 'browser') {
        stage(0, 20);
        const r = await readInput();
        stage(1, 40); startIndeterminate(75);
        if ('b64' in r) {
          res = await api.decryptContent({
            content_b64: r.b64,
            save: outMode === 'device',
            out: outMode === 'device' ? outPath.trim() : '',
          });
        } else {
          res = await api.decrypt({
            path: r.machinePath,
            out: outMode === 'device' ? outPath.trim() : '',
          });
        }
        stopAnim();
      } else {
        stage(0, 30); startIndeterminate(75);
        res = await api.decrypt({
          path: path.trim(),
          out: outMode === 'device' ? outPath.trim() : '',
        });
        stopAnim();
      }
      stage(2, 82);
      if (res.xml) {
        xmlText = res.xml;
        tables = parseZteXml(res.xml);
        summary = summarize(tables);
      }
      stage(3, 94);
      decResult = res;
      if (outMode === 'download' && res.xml) downloadXml(res.xml);
      finishProgress();
    } catch (e: any) {
      stopAnim(); progActive = false;
      err = String(e?.message || e);
    } finally {
      busy = '';
    }
  }

  function canRun(): boolean {
    if (busy) return false;
    return inputMode === 'browser' ? !!file : !!path.trim();
  }
</script>

<div class="card">
  <h2><img src="/zudz.svg" class="logo-img" alt="ZUDZ" /> {$tr('decrypt.title')}</h2>
  <div class="desc">{$tr('decrypt.desc')}</div>

  <!-- ─── لوحة الاتصال بالجهاز ─────────────────────────── -->
  <div class="sub-panel">
    <h3>{$tr('conn.title')}</h3>
    <div class="grid">
      <div>
        <label class="f">{$tr('common.host')}</label>
        <input type="text" class="mono" bind:value={chost} />
      </div>
      <div>
        <label class="f">{$tr('common.user')}</label>
        <input type="text" class="mono" bind:value={cuser} />
      </div>
      <div>
        <label class="f">{$tr('common.password')}</label>
        <input type="password" class="mono" bind:value={cpassword} />
      </div>
    </div>
    <button class="sec" on:click={doPing} disabled={busy !== '' || connState === 'testing'}>
      {connState === 'testing' ? $tr('conn.testing') : $tr('conn.test')}</button>
    <div class="conn-status s-{connState}">
      {#if connState === 'idle'}
        <span class="cdot"></span>{$tr('conn.notConnected')}
      {:else if connState === 'testing'}
        <span class="cdot spin"></span>{$tr('conn.testing')}
      {:else if connState === 'connected'}
        <span class="cdot ok"></span>{$tr('conn.connected')} — <span class="mono">{westernDigits(chost)}</span>
        <span class="dim">({$tr('conn.port')} {westernDigits(String(connPort))} · {$tr('conn.latency')} {westernDigits(String(connLatency))}ms)</span>
      {:else}
        <span class="cdot err"></span>{$tr('conn.failed')} — <span class="dim">{westernDigits(connDetail)}</span>
      {/if}
    </div>
    <div class="diag-row">
      <button class="sec" on:click={doDiagStatus} disabled={busy !== ''}>{$tr('diag.check')}</button>
      {#if diag}
        <span class="diag-chip s-{diag.status}">
          {#if diag.status === 'active'}
            ✅ {$tr('diag.active')}{#if diag.mode} — <span class="mono">{diag.mode}</span>{/if}
          {:else if diag.status === 'needs-setup'}
            ⚠️ {$tr('diag.needsSetup')} — <span class="mono">{diag.current_mac}</span> → <span class="mono">{diag.required_mac}</span>
            <span class="dim">{$tr('diag.autoNote')}</span>
          {:else}
            ❌ {diag.note ?? diag.status}
          {/if}
        </span>
      {/if}
    </div>
  </div>

  <!-- ─── مكان التخزين ──────────────────────────────────── -->
  <div class="sub-panel">
    <h3>{$tr('storage.title')}</h3>
    <div class="radio-row">
      <label class="radio">
        <input type="radio" bind:group={inputMode} value="browser" />
        {$tr('storage.fromBrowser')}
      </label>
      <label class="radio">
        <input type="radio" bind:group={inputMode} value="path" />
        {$tr('storage.fromPath')}
      </label>
    </div>
    {#if inputMode === 'browser'}
      <input type="file" class="filepick" on:change={onFilePicked}
        accept=".bin,.xml,.zip,.gz,.tar,.txt,application/octet-stream" />
      {#if file}
        <div class="msg ok">📄 {$tr('dec.fileChosen')}: <span class="mono">{file.name}</span>
          — {westernDigits(fmtBytes(file.size))}</div>
      {/if}
    {:else}
      <input type="text" class="mono" bind:value={path} placeholder="config.bin" />
    {/if}

    <div class="radio-row" style="margin-block-start:10px">
      <label class="radio">
        <input type="radio" bind:group={outMode} value="download" />
        {$tr('storage.download')}
      </label>
      <label class="radio">
        <input type="radio" bind:group={outMode} value="device" />
        {$tr('storage.saveDevice')}
      </label>
    </div>
    {#if outMode === 'device'}
      <input type="text" class="mono" bind:value={outPath} placeholder="zudz_backups/decrypted.xml" />
    {/if}
    <div class="dim small">{$tr('storage.backupDir')}: <span class="mono">zudz_region_backup/</span></div>
  </div>

  <!-- ─── التنفيذ ───────────────────────────────────────── -->
  <button class="sec" on:click={doInspect} disabled={!canRun()}>{$tr('decrypt.inspect')}</button>
  <button on:click={doDecrypt} disabled={!canRun()} style="margin-inline-start:8px">
    {busy === 'd' ? $tr('common.running') : $tr('decrypt.decrypt')}</button>

  {#if progActive}
    <Progress percent={progPercent} stages={progStages} active={progStage} done={progDone} />
  {/if}

  {#if inspectResult}
    <div class="msg ok">🔍 {$tr('dec.inspectResult')} — {$tr('decrypt.signature')}:
      <span class="mono">{inspectResult.signature ?? '—'}</span> |
      {$tr('decrypt.payloadType')}: <span class="mono">{westernDigits(String(inspectResult.payload_type ?? '—'))}</span>
      | ZTE header: <span class="mono">{inspectResult.has_zte_header ? 'yes' : 'no'}</span></div>
  {/if}

  {#if decResult && !summary}
    <div class="msg ok">✅ {westernDigits(fmtBytes(decResult.size))} — {$tr('decrypt.method')}:
      <span class="mono">{decResult.method}</span>{decResult.saved_to ? ` — {$tr('dec.savedTo')}: <span class="mono">{decResult.saved_to}</span>` : ''}</div>
  {/if}

  {#if err}<div class="msg err">{westernDigits(err)}</div>{/if}
</div>

<!-- ─── البيانات المفكوكة — عرض منظم ─────────────────────── -->
{#if summary}
  <div class="card">
    <div class="res-head">
      <h2>{$tr('dec.results')}</h2>
      <div class="res-actions">
        <button class="copybtn sec" on:click={() => copy(summaryToText(summary!, tables))}>{$tr('dec.copyAll')}</button>
        <button class="copybtn sec" on:click={() => downloadXml(xmlText)}>{$tr('dec.downloadXml')}</button>
      </div>
    </div>
    {#if decResult}
      <div class="msg ok">✅ {westernDigits(fmtBytes(decResult.size))} — {$tr('decrypt.method')}:
        <span class="mono">{decResult.method}</span>{decResult.saved_to ? ` — {$tr('dec.savedTo')}: <span class="mono">{decResult.saved_to}</span>` : ''}</div>
    {/if}

    <div class="sum-grid">
      <div class="sum-sec">
        <h3>{$tr('sum.device')}</h3>
        <div class="kv"><span class="k">{$tr('sum.version')}</span>
          <span class="v"><span class="val">{westernDigits(summary.device.config_label)}</span>
            <button class="copybtn" on:click={() => copy(summary.device.config_label)}>{copied === summary.device.config_label ? $tr('common.copied') : $tr('common.copy')}</button></span></div>
        <div class="kv"><span class="k">{$tr('sum.provCode')}</span>
          <span class="v"><span class="val">{westernDigits(summary.device.provisioning_code)}</span>
            <button class="copybtn" on:click={() => copy(summary.device.provisioning_code)}>{copied === summary.device.provisioning_code ? $tr('common.copied') : $tr('common.copy')}</button></span></div>
        <div class="kv"><span class="k">{$tr('sum.wifiMac')}</span>
          <span class="v"><span class="val">{westernDigits(summary.device.wifi_base_mac)}</span>
            <button class="copybtn" on:click={() => copy(summary.device.wifi_base_mac)}>{copied === summary.device.wifi_base_mac ? $tr('common.copied') : $tr('common.copy')}</button></span></div>
        <div class="kv"><span class="k">{$tr('sum.lan')}</span>
          <span class="v"><span class="val">{westernDigits(summary.device.lan_ip)} / {westernDigits(summary.device.lan_netmask)}</span>
            <button class="copybtn" on:click={() => copy(`${summary.device.lan_ip} / ${summary.device.lan_netmask}`)}>{copied === `${summary.device.lan_ip} / ${summary.device.lan_netmask}` ? $tr('common.copied') : $tr('common.copy')}</button></span></div>
      </div>

      <div class="sum-sec">
        <h3>{$tr('sum.wan')} <span class="badge">{westernDigits(String(summary.wan.length))}</span></h3>
        {#each summary.wan as w, i}
          <div class="sum-item">
            <div class="kv"><span class="k">{$tr('sum.name')}</span>
              <span class="v"><span class="val">{westernDigits(w.name)}</span>
                <button class="copybtn" on:click={() => copy(w.name)}>{copied === w.name ? $tr('common.copied') : $tr('common.copy')}</button></span></div>
            <div class="kv"><span class="k">{$tr('sum.kind')}</span>
              <span class="v"><span class="val">{westernDigits(w.kind)}</span>
                <button class="copybtn" on:click={() => copy(w.kind)}>{copied === w.kind ? $tr('common.copied') : $tr('common.copy')}</button></span></div>
            {#if w.vlan}
              <div class="kv"><span class="k">{$tr('sum.vlan')}</span>
                <span class="v"><span class="val">{westernDigits(w.vlan)}</span>
                  <button class="copybtn" on:click={() => copy(w.vlan)}>{copied === w.vlan ? $tr('common.copied') : $tr('common.copy')}</button></span></div>
            {/if}
            {#if w.pppoe_user || w.pppoe_password}
              <div class="kv"><span class="k">{$tr('sum.user')}</span>
                <span class="v"><span class="val">{westernDigits(w.pppoe_user)}</span>
                  <button class="copybtn" on:click={() => copy(w.pppoe_user)}>{copied === w.pppoe_user ? $tr('common.copied') : $tr('common.copy')}</button></span></div>
              <div class="kv"><span class="k">{$tr('sum.pass')}</span>
                <span class="v"><span class="val">{westernDigits(w.pppoe_password)}</span>
                  <button class="copybtn" on:click={() => copy(w.pppoe_password)}>{copied === w.pppoe_password ? $tr('common.copied') : $tr('common.copy')}</button></span></div>
            {/if}
          </div>
        {:else}
          <div class="dim small">{$tr('dec.empty')}</div>
        {/each}
      </div>

      <div class="sum-sec">
        <h3>{$tr('sum.wifi')} <span class="badge">{westernDigits(String(summary.wifi.length))}</span></h3>
        {#each summary.wifi as w}
          <div class="sum-item">
            <div class="kv"><span class="k">{$tr('sum.ssid')}</span>
              <span class="v"><span class="val">{westernDigits(w.ssid)}</span>
                <button class="copybtn" on:click={() => copy(w.ssid)}>{copied === w.ssid ? $tr('common.copied') : $tr('common.copy')}</button></span></div>
            <div class="kv"><span class="k">{$tr('sum.pass')}</span>
              <span class="v"><span class="val">{westernDigits(w.password)}</span>
                <button class="copybtn" on:click={() => copy(w.password)}>{copied === w.password ? $tr('common.copied') : $tr('common.copy')}</button></span></div>
            <div class="kv"><span class="k">{$tr('sum.interface')}</span>
              <span class="v"><span class="val">{westernDigits(w.interface)}</span>
                <button class="copybtn" on:click={() => copy(w.interface)}>{copied === w.interface ? $tr('common.copied') : $tr('common.copy')}</button></span></div>
            <div class="kv"><span class="k">—</span>
              <span class="v"><span class="val">{w.hidden ? $tr('sum.hidden') : ''}{w.hidden && w.enabled ? ' · ' : ''}{w.enabled ? $tr('sum.enabled') : $tr('sum.disabled')}</span></span></div>
          </div>
        {:else}
          <div class="dim small">{$tr('dec.empty')}</div>
        {/each}
      </div>

      <div class="sum-sec">
        <h3>{$tr('sum.voip')} <span class="badge">{westernDigits(String(summary.voip.length))}</span></h3>
        {#each summary.voip as v}
          <div class="sum-item">
            <div class="kv"><span class="k">{$tr('sum.number')}</span>
              <span class="v"><span class="val">{westernDigits(v.phone_number)}</span>
                <button class="copybtn" on:click={() => copy(v.phone_number)}>{copied === v.phone_number ? $tr('common.copied') : $tr('common.copy')}</button></span></div>
            <div class="kv"><span class="k">{$tr('sum.user')}</span>
              <span class="v"><span class="val">{westernDigits(v.auth_user)}</span>
                <button class="copybtn" on:click={() => copy(v.auth_user)}>{copied === v.auth_user ? $tr('common.copied') : $tr('common.copy')}</button></span></div>
            <div class="kv"><span class="k">{$tr('sum.pass')}</span>
              <span class="v"><span class="val">{westernDigits(v.auth_password)}</span>
                <button class="copybtn" on:click={() => copy(v.auth_password)}>{copied === v.auth_password ? $tr('common.copied') : $tr('common.copy')}</button></span></div>
            {#if v.sip_domain}
              <div class="kv"><span class="k">{$tr('sum.domain')}</span>
                <span class="v"><span class="val">{westernDigits(v.sip_domain)}</span>
                  <button class="copybtn" on:click={() => copy(v.sip_domain)}>{copied === v.sip_domain ? $tr('common.copied') : $tr('common.copy')}</button></span></div>
            {/if}
            {#if v.registrar}
              <div class="kv"><span class="k">{$tr('sum.registrar')}</span>
                <span class="v"><span class="val">{westernDigits(v.registrar)}</span>
                  <button class="copybtn" on:click={() => copy(v.registrar)}>{copied === v.registrar ? $tr('common.copied') : $tr('common.copy')}</button></span></div>
            {/if}
            {#if v.proxy}
              <div class="kv"><span class="k">{$tr('sum.proxy')}</span>
                <span class="v"><span class="val">{westernDigits(v.proxy)}</span>
                  <button class="copybtn" on:click={() => copy(v.proxy)}>{copied === v.proxy ? $tr('common.copied') : $tr('common.copy')}</button></span></div>
            {/if}
          </div>
        {:else}
          <div class="dim small">{$tr('dec.empty')}</div>
        {/each}
      </div>

      <div class="sum-sec">
        <h3>{$tr('sum.accounts')}</h3>
        {#each summary.accounts.web as a}
          <div class="sum-item">
            <div class="kv"><span class="k">{$tr('sum.web')} · {$tr('sum.level')} {westernDigits(a.level)}</span>
              <span class="v"><span class="val">{westernDigits(a.user)}</span>
                <button class="copybtn" on:click={() => copy(a.user)}>{copied === a.user ? $tr('common.copied') : $tr('common.copy')}</button></span></div>
            <div class="kv"><span class="k">{$tr('sum.pass')}</span>
              <span class="v"><span class="val">{westernDigits(a.password)}</span>
                <button class="copybtn" on:click={() => copy(a.password)}>{copied === a.password ? $tr('common.copied') : $tr('common.copy')}</button></span></div>
          </div>
        {/each}
        {#if summary.accounts.telnet_user || summary.accounts.telnet_password}
          <div class="sum-item">
            <div class="kv"><span class="k">{$tr('sum.telnet')} · {$tr('sum.user')}</span>
              <span class="v"><span class="val">{westernDigits(summary.accounts.telnet_user)}</span>
                <button class="copybtn" on:click={() => copy(summary.accounts.telnet_user)}>{copied === summary.accounts.telnet_user ? $tr('common.copied') : $tr('common.copy')}</button></span></div>
            <div class="kv"><span class="k">{$tr('sum.telnet')} · {$tr('sum.pass')}</span>
              <span class="v"><span class="val">{westernDigits(summary.accounts.telnet_password)}</span>
                <button class="copybtn" on:click={() => copy(summary.accounts.telnet_password)}>{copied === summary.accounts.telnet_password ? $tr('common.copied') : $tr('common.copy')}</button></span></div>
          </div>
        {/if}
        {#if !summary.accounts.web.length && !summary.accounts.telnet_user}
          <div class="dim small">{$tr('dec.empty')}</div>
        {/if}
      </div>

      {#if summary.tr069.length}
        <div class="sum-sec">
          <h3>{$tr('sum.tr069')} <span class="badge">{westernDigits(String(summary.tr069.length))}</span></h3>
          {#each summary.tr069 as t}
            <div class="kv"><span class="k">{westernDigits(t.key)}</span>
              <span class="v"><span class="val">{westernDigits(t.value)}</span>
                <button class="copybtn" on:click={() => copy(t.value)}>{copied === t.value ? $tr('common.copied') : $tr('common.copy')}</button></span></div>
          {/each}
        </div>
      {/if}
    </div>

    <!-- كل الجداول -->
    <details class="tables">
      <summary>{$tr('dec.allTables')} <span class="badge">{westernDigits(String(tables.length))}</span></summary>
      {#each tables as t}
        <details>
          <summary class="tname">{westernDigits(t.name)} <span class="badge">{westernDigits(String(t.rows.length))}</span></summary>
          {#each t.rows as r}
            <div class="tbl-row">
              {#each Object.entries(r) as [k, v]}
                <div class="kv"><span class="k">{westernDigits(k)}</span>
                  <span class="v"><span class="val">{westernDigits(v)}</span>
                    <button class="copybtn" on:click={() => copy(v)}>{copied === v ? $tr('common.copied') : $tr('common.copy')}</button></span></div>
              {/each}
            </div>
          {/each}
        </details>
      {/each}
    </details>
  </div>
{/if}

<style>
  h2 .logo-img { width: 26px; height: 26px; vertical-align: -5px; margin-inline-end: 8px; }

  .sub-panel { border: 1px solid var(--line); border-radius: 12px;
    padding: 14px 16px; margin-block-end: 14px; background: var(--card2); }
  .sub-panel h3 { margin: 0 0 10px; font-size: 0.9rem; color: var(--dim); }

  .radio-row { display: flex; gap: 16px; flex-wrap: wrap; margin-block: 8px; }
  .radio { display: inline-flex; align-items: center; gap: 7px;
    font-size: 0.85rem; cursor: pointer; color: var(--tx); }
  .radio input { accent-color: var(--acc); }
  .filepick { width: 100%; padding: 8px 10px; border-radius: 9px; border: 1px dashed var(--line);
    background: #0a0f1a; color: var(--tx); font: inherit; font-size: 0.85rem; }
  .filepick::file-selector-button { background: var(--card2); color: var(--tx);
    border: 1px solid var(--line); border-radius: 7px; padding: 5px 12px;
    margin-inline-end: 10px; cursor: pointer; font: inherit; font-size: 0.8rem; }

  .dim { color: var(--dim); }
  .small { font-size: 0.76rem; margin-block-start: 8px; }
  .mono { font-family: var(--mono); direction: ltr; text-align: start; unicode-bidi: isolate; }

  .conn-status { margin-block-start: 12px; padding: 10px 14px; border-radius: 9px;
    font-size: 0.88rem; display: flex; align-items: center; gap: 9px; }
  .conn-status.s-idle { background: rgba(143, 160, 189, 0.08); border: 1px solid var(--line); color: var(--dim); }
  .conn-status.s-testing { background: rgba(58, 166, 255, 0.08); border: 1px solid var(--acc); color: var(--acc); }
  .conn-status.s-connected { background: rgba(58, 210, 154, 0.1); border: 1px solid var(--ok); color: var(--ok); }
  .conn-status.s-failed { background: rgba(255, 107, 122, 0.1); border: 1px solid var(--err); color: var(--err); }
  .conn-status .dim { color: inherit; opacity: 0.75; }
  .cdot { width: 9px; height: 9px; border-radius: 50%; background: currentColor; flex: none; }
  .cdot.spin { animation: spin 1s linear infinite; border-radius: 2px; }
  .diag-row { margin-block-start: 8px; display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
  .diag-chip { padding: 6px 10px; border-radius: 8px; font-size: 0.9em; overflow-wrap: anywhere; }
  .diag-chip.s-active { background: rgba(58, 210, 154, 0.1); border: 1px solid var(--ok); color: var(--ok); }
  .diag-chip.s-needs-setup { background: rgba(255, 190, 60, 0.1); border: 1px solid var(--warn, #ffbe3c); color: var(--warn, #ffbe3c); }
  .diag-chip.s-no-route, .diag-chip.s-removed { background: rgba(255, 107, 122, 0.1); border: 1px solid var(--err); color: var(--err); }
  @keyframes spin { to { transform: rotate(360deg); } }

  .res-head { display: flex; align-items: center; justify-content: space-between; gap: 10px; flex-wrap: wrap; }
  .res-head h2 { margin: 0; }
  .res-actions { display: flex; gap: 8px; }
  .res-actions .copybtn { padding: 6px 14px; font-size: 0.78rem; }

  .sum-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 12px; }
  .sum-sec { border: 1px solid var(--line); border-radius: 12px; padding: 12px 14px; }
  .sum-sec h3 { margin: 0 0 8px; font-size: 0.88rem; color: var(--dim);
    display: flex; align-items: center; gap: 8px; }
  .sum-item { border-block-end: 1px dashed var(--line); padding-block: 6px; }
  .sum-item:last-child { border-block-end: 0; }
  .kv .val { font-family: var(--mono); direction: ltr; text-align: start; unicode-bidi: isolate; }
  .kv .v { display: inline-flex; align-items: center; gap: 8px; }

  .tables { margin-block-start: 14px; }
  .tables > summary { cursor: pointer; font-weight: 700; font-size: 0.9rem;
    padding: 8px 0; color: var(--tx); }
  .tables details { margin-inline-start: 10px; }
  .tables .tname { cursor: pointer; color: var(--acc); font-size: 0.85rem;
    font-family: var(--mono); padding: 4px 0; display: flex; align-items: center; gap: 8px; }
  .tbl-row { margin-inline-start: 14px; border-inline-start: 2px solid var(--line);
    padding-inline-start: 10px; margin-block: 4px; }
</style>
