// عميل API — يواجه zudz-server (نفس الأصل أو وكيل التطوير)

export interface Report {
  host: string;
  device: { model: string; serial_label: string; hardware: string; software: string; boot: string; base_mac: string };
  gpon: { vid: string; sn8: string; full_sn: string; ploam_password: string };
  pppoe: { username: string; password: string; vlan: string; mtu: string };
  voip: { sip_uri: string; phone_number: string; password: string; registrar: string; p_cscf: string; proxy1: string; proxy2: string };
  wifi_defaults: { ssid_24g: string; ssid_5g: string; psk: string };
  sources: string[];
}

export interface Region {
  code: number;
  name: string;
  verified: boolean;
  source: string;
}

/// معلومات المشروع من الخادم (/api/version)
export interface Meta {
  name: string;
  version: string;
  tagline: string;
  author: string;
  homepage: string;
  discord: string;
  license: string;
  license_name: string;
  license_url: string;
  purpose: string;
  personal_only: string;
  no_illegal: string;
  disclaimer: string;
}

/// قيم احتياطية ثابتة (عندما لا يعمل الخادم) — مطابقة لـ zudz-meta
export const FALLBACK_META: Meta = {
  name: 'ZUDZ',
  version: '0.2.0',
  tagline: 'ZTE Unlock, Decrypt & Zone-changer',
  author: 'dreamzone-cc',
  homepage: 'https://github.com/dreamzone-cc',
  discord: 'yuuyu_gg',
  license: 'AGPL-3.0-or-later',
  license_name: 'GNU Affero General Public License v3.0',
  license_url: 'https://www.gnu.org/licenses/agpl-3.0.html',
  purpose: 'Maintenance tool for personal ZTE GPON devices',
  personal_only: 'For personal devices only — devices you own or hold explicit written authorization to manage',
  no_illegal: 'Unlawful use is strictly prohibited — the user bears full responsibility',
  disclaimer: 'DISCLAIMER.md',
};

/// نتيجة فحص بنية ملف
export interface InspectResult {
  signature: string | null;
  payload_type: number | null;
  has_zte_header: boolean | null;
}

/// نتيجة فك التشفير — xml: النص المفكوك (للعرض المنظم)
export interface DecryptResult {
  ok: boolean;
  size: number;
  method: string;
  xml?: string;
  saved_to?: string;
}

/// نتيجة اختبار الاتصال بالجهاز
export interface DevicePing {
  ok: boolean;
  connected: boolean;
  host: string;
  port: number;
  latency_ms: number;
  detail: string;
}

/// نسخة احتياطية سُحبت تلقائياً قبل عملية خطيرة (تغيير منطقة / كتابة GPON)
export interface BackupInfo {
  dir: string;
  report_path: string;
  reason: string;
}

async function call<T>(path: string, body?: unknown): Promise<T> {
  const res = await fetch(path, {
    method: body === undefined ? 'GET' : 'POST',
    headers: body === undefined ? {} : { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const j = (await res.json()) as T & { ok?: boolean; error?: string };
  if (j && j.ok === false) throw new Error(j.error || 'API error');
  return j;
}

export const api = {
  version: () => call<Meta>('/api/version'),
  regions: () => call<{ regions: Region[] }>('/api/regions'),
  extract: (p: { host: string; user: string; password: string }) =>
    call<{ ok: boolean; report: Report }>('/api/extract', p),
  regionPrepare: (p: { host: string; user: string; password: string }) =>
    call<{ ok: boolean; token: string; summary: Report }>('/api/region/prepare', p),
  regionChange: (p: { host: string; user: string; password: string; code: number; ack: string; perm_telnet: boolean; force_unknown?: boolean }) =>
    call<{ ok: boolean; auto_backup: boolean; result: { code: number; region_name: string; raw_output: string; note: string; backup: BackupInfo | null } }>('/api/region/change', p),
  gponRead: (p: { host: string; user: string; password: string }) =>
    call<{ ok: boolean; tags: Record<string, string> }>('/api/gpon/read', p),
  gponClone: (p: { host: string; user: string; password: string }) =>
    call<{ ok: boolean; commands: string[]; output: string; backup: BackupInfo | null }>('/api/gpon/clone', p),
  gponWrite: (p: { host: string; user: string; password: string; vid: string; sn8: string; ploam: string }) =>
    call<{ ok: boolean; commands: string[]; output: string; backup: BackupInfo | null }>('/api/gpon/write', p),
  inspect: (p: { path: string }) =>
    call<{ ok: boolean; signature: string | null; payload_type: number | null; has_zte_header: boolean | null }>('/api/inspect', p),
  inspectContent: (p: { content_b64: string }) =>
    call<InspectResult>('/api/inspect-content', p),
  decrypt: (p: { path: string; out: string }) =>
    call<DecryptResult>('/api/decrypt', p),
  decryptContent: (p: { content_b64: string; save: boolean; out: string }) =>
    call<DecryptResult>('/api/decrypt-content', p),
  devicePing: (p: { host: string; user: string; password: string }) =>
    call<DevicePing>('/api/device/ping', p),
};
