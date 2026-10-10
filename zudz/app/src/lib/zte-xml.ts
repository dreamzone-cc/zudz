// محلل XML قاعدة بيانات ZTE — جانب العميل
// يبني عرضاً منظماً من البيانات المفكوكة (Tbl/Row/DM) مطابقاً لمنطق zudz-db

export interface ZteRow { [name: string]: string }
export interface ZteTable { name: string; rows: ZteRow[] }

/** يحلل نص XML إلى جداول — مرن مع الملفات غير الصالحة أحياناً */
export function parseZteXml(text: string): ZteTable[] {
  const tables: ZteTable[] = [];
  const doc = new DOMParser().parseFromString(text, 'text/xml');
  const parseError = doc.querySelector('parsererror');
  const roots = parseError ? null : doc.getElementsByTagName('Tbl');
  if (!roots || roots.length === 0) {
    // fallback نصي متسامح — نفس أسلوب zudz-db
    return parseFallback(text);
  }
  for (const tbl of Array.from(roots)) {
    const name = tbl.getAttribute('name') ?? '';
    if (!name) continue;
    const rows: ZteRow[] = [];
    for (const row of Array.from(tbl.getElementsByTagName('Row'))) {
      const r: ZteRow = {};
      for (const dm of Array.from(row.getElementsByTagName('DM'))) {
        const n = dm.getAttribute('name');
        const v = dm.getAttribute('val');
        if (n && v !== null) r[n] = decodeEntities(v);
      }
      if (Object.keys(r).length) rows.push(r);
    }
    if (rows.length) tables.push({ name, rows });
  }
  if (tables.length) return tables;
  return parseFallback(text);
}

function decodeEntities(s: string): string {
  return s.replace(/&lt;/g, '<').replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"').replace(/&apos;/g, "'")
    .replace(/&amp;/g, '&');
}

/** تحليل نصي متسامح للملفات التي لا تُحلل كـ XML صحيح */
function parseFallback(text: string): ZteTable[] {
  const tables: ZteTable[] = [];
  const tblRe = /<Tbl\s+name="([^"]*)"[^>]*>([\s\S]*?)<\/Tbl>/g;
  let m: RegExpExecArray | null;
  while ((m = tblRe.exec(text))) {
    const name = m[1];
    const body = m[2];
    const rows: ZteRow[] = [];
    const rowRe = /<Row[^>]*>([\s\S]*?)<\/Row>/g;
    let r: RegExpExecArray | null;
    while ((r = rowRe.exec(body))) {
      const row: ZteRow = {};
      const dmRe = /<DM\s+name="([^"]*)"\s+val="([^"]*)"/g;
      let d: RegExpExecArray | null;
      while ((d = dmRe.exec(r[1]))) row[d[1]] = decodeEntities(d[2]);
      if (Object.keys(row).length) rows.push(row);
    }
    if (rows.length) tables.push({ name, rows });
  }
  return tables;
}

function first(tables: ZteTable[], name: string): ZteRow {
  return tables.find((t) => t.name === name)?.rows[0] ?? {};
}
function table(tables: ZteTable[], name: string): ZteRow[] {
  return tables.find((t) => t.name === name)?.rows ?? [];
}
function pick(row: ZteRow, names: string[]): string {
  for (const n of names) if (row[n]) return row[n];
  return '';
}

// ─── الملخص المنظم — مطابق لخروجات zudz-db ─────────────────────

export interface SumDevice {
  config_label: string; provisioning_code: string;
  wifi_base_mac: string; lan_ip: string; lan_netmask: string;
}
export interface SumWan {
  name: string; kind: string; conn_type: string;
  vlan: string; pppoe_user: string; pppoe_password: string;
}
export interface SumWifi {
  ap: string; interface: string; enabled: boolean;
  ssid: string; hidden: boolean; password: string;
}
export interface SumVoip {
  line: string; enabled: boolean; phone_number: string;
  auth_user: string; auth_password: string; sip_domain: string;
  proxy: string; registrar: string;
}
export interface SumAccounts {
  web: { user: string; password: string; level: string }[];
  telnet_user: string; telnet_password: string; telnet_lan_enabled: boolean;
}
export interface Summary {
  device: SumDevice;
  wan: SumWan[];
  wifi: SumWifi[];
  voip: SumVoip[];
  accounts: SumAccounts;
  tr069: { key: string; value: string }[];
}

function addrLabel(v?: string): string {
  switch (v) {
    case '0': return 'DHCP';
    case '1': return 'Static';
    case '2': return 'PPPoE';
    case '3': return 'Auto';
    default: return v ?? '';
  }
}
function connLabel(v?: string): string {
  switch (v) {
    case '0': return 'Bridge';
    case '1': return 'IP_Routed';
    case '2': return 'IP_Bridged';
    case '4': return 'PPPoE';
    default: return v ?? '';
  }
}
function vlanOf(tables: ZteTable[], view: string): string {
  if (!view) return '';
  for (const t of ['EthVlan', 'VLAN', 'EthVlanCfg']) {
    for (const r of table(tables, t)) {
      if (r['ViewName'] === view) return r['VLANID'] ?? r['VlanId'] ?? '';
    }
  }
  const i = view.lastIndexOf('VLAN');
  return i >= 0 ? view.slice(i + 4) : '';
}

export function summarize(tables: ZteTable[]): Summary {
  const dev = first(tables, 'DevInfo');
  const ws = first(tables, 'WLANSetting');
  const lan = first(tables, 'LANIPCfg');
  const out: Summary = {
    device: {
      config_label: dev['CfgLable'] ?? '',
      provisioning_code: dev['ProvisioningCode'] ?? '',
      wifi_base_mac: ws['SpecMACAddr'] ?? '',
      lan_ip: lan['IP'] ?? '',
      lan_netmask: lan['NetMask'] ?? '',
    },
    wan: [], wifi: [], voip: [],
    accounts: { web: [], telnet_user: '', telnet_password: '', telnet_lan_enabled: false },
    tr069: [],
  };

  // WAN + PPPoE
  const pppif = table(tables, 'PPPIF');
  let consumed = 0;
  for (const r of table(tables, 'WANCIP')) {
    out.wan.push({
      name: r['WANCName'] ?? '', kind: addrLabel(r['AddressingType']),
      conn_type: connLabel(r['ConnType']),
      vlan: vlanOf(tables, r['EthVlan'] ?? ''),
      pppoe_user: '', pppoe_password: '',
    });
  }
  for (const r of table(tables, 'WANCPPP')) {
    const creds = pppif[consumed]; consumed += 1;
    const isPppoe = !!(r['PPPInterface'] && r['PPPInterface'].length) ||
      connLabel(r['ConnType']) === 'PPPoE' || pppif.length > 0;
    out.wan.push({
      name: r['WANCName'] ?? '',
      kind: isPppoe ? 'PPPoE' : connLabel(r['ConnType']),
      conn_type: r['ConnType'] ?? '',
      vlan: vlanOf(tables, r['EthVlan'] ?? ''),
      pppoe_user: creds ? pick(creds, ['Username', 'User', 'PPPUsername']) : '',
      pppoe_password: creds ? pick(creds, ['Password', 'Pass', 'PPPPassword']) : '',
    });
  }
  for (const c of pppif.slice(consumed)) {
    out.wan.push({
      name: 'PPPoE', kind: 'PPPoE', conn_type: '',
      vlan: '', pppoe_user: pick(c, ['Username', 'User']),
      pppoe_password: pick(c, ['Password', 'Pass']),
    });
  }

  // WiFi
  const psk: Record<string, string> = {};
  for (const r of table(tables, 'WLANPSK')) {
    const k = r['WLANViewName'] ?? '';
    if (k) psk[k] = pick(r, ['KeyPassphrase', 'PreSharedKey']);
  }
  for (const r of table(tables, 'WLANCfg')) {
    const ap = r['ViewName'] ?? '';
    out.wifi.push({
      ap, interface: r['IfName'] ?? '', enabled: r['Enable'] === '1',
      ssid: r['ESSID'] ?? '', hidden: r['ESSIDHideEnable'] === '1',
      password: psk[ap] ?? '',
    });
  }

  // VoIP
  const sipMain = first(tables, 'VoIPSIP');
  const servers = table(tables, 'VoIPSIPServer');
  const vpl = table(tables, 'VoIPVPLine');
  table(tables, 'VoIPSIPLine').forEach((r, i) => {
    const srv = servers[i] ?? {};
    const v = vpl[i] ?? {};
    out.voip.push({
      line: r['ViewName'] ?? `line${i + 1}`, enabled: r['Enable'] === '1',
      phone_number: v['DirectoryNumber'] ?? '',
      auth_user: r['AuthUserName'] ?? '', auth_password: r['AuthPassword'] ?? '',
      sip_domain: sipMain['UserAgentDoimain'] ?? sipMain['UserAgentDomain'] ?? '',
      proxy: pick(srv, ['ProxyServer1', 'ProxyServer2']),
      registrar: pick(srv, ['RegistrarServer1', 'RegistrarServer2']),
    });
  });

  // الحسابات
  for (const r of table(tables, 'DevAuthInfo')) {
    out.accounts.web.push({
      user: r['User'] ?? '', password: r['Pass'] ?? '', level: r['Level'] ?? '',
    });
  }
  const tel = first(tables, 'TelnetCfg');
  out.accounts.telnet_user = tel['TS_UName'] ?? '';
  out.accounts.telnet_password = tel['TS_UPwd'] ?? tel['TSLan_UPwd'] ?? '';
  out.accounts.telnet_lan_enabled = tel['Lan_Enable'] === '1';

  // TR-069
  for (const t of tables) {
    const tl = t.name.toLowerCase();
    if (tl.includes('tr069') || tl.includes('cwmp')) {
      for (const r of t.rows) {
        for (const [k, v] of Object.entries(r)) {
          const kl = k.toLowerCase();
          if (v && (kl.includes('url') || kl.includes('acs') || kl.includes('server') ||
            kl.includes('user') || kl.includes('pass') || kl.includes('pwd') ||
            kl.includes('period') || kl.includes('enable'))) {
            out.tr069.push({ key: `${t.name}.${k}`, value: v });
          }
        }
      }
    }
  }

  return out;
}

/** نسخ كل البيانات كنص منظم */
export function summaryToText(s: Summary, tables: ZteTable[]): string {
  const L: string[] = ['# ZUDZ — البيانات المفكوكة', ''];
  L.push('## الجهاز');
  L.push(`- الإصدار: ${s.device.config_label}`);
  L.push(`- كود التهيئة: ${s.device.provisioning_code}`);
  L.push(`- MAC WiFi: ${s.device.wifi_base_mac}`);
  L.push(`- LAN: ${s.device.lan_ip} / ${s.device.lan_netmask}`);
  L.push('');
  L.push('## WAN / PPPoE');
  s.wan.forEach((w, i) => L.push(`${i + 1}. ${w.name || 'WAN'} [${w.kind}] ${w.conn_type ? 'type=' + w.conn_type : ''} ${w.vlan ? 'VLAN=' + w.vlan : ''} ${w.pppoe_user ? `user=${w.pppoe_user}` : ''} ${w.pppoe_password ? `pass=${w.pppoe_password}` : ''}`));
  L.push('');
  L.push('## WiFi');
  s.wifi.forEach((w) => L.push(`- ${w.ssid || w.ap} [${w.interface}] ${w.hidden ? 'hidden' : ''} psk=${w.password}`));
  L.push('');
  L.push('## VoIP');
  s.voip.forEach((v) => L.push(`- ${v.phone_number || v.line} user=${v.auth_user} pass=${v.auth_password} domain=${v.sip_domain} registrar=${v.registrar}`));
  L.push('');
  L.push('## الحسابات');
  s.accounts.web.forEach((a) => L.push(`- web: ${a.user} / ${a.password} (level ${a.level})`));
  L.push(`- telnet: ${s.accounts.telnet_user} / ${s.accounts.telnet_password}${s.accounts.telnet_lan_enabled ? ' (LAN enabled)' : ''}`);
  if (s.tr069.length) {
    L.push('', '## TR-069');
    s.tr069.forEach((t) => L.push(`- ${t.key}: ${t.value}`));
  }
  return L.join('\n');
}
