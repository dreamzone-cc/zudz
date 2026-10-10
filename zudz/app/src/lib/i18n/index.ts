// نظام i18n المركزي — تبديل فوري، RTL تلقائي، أرقام غربية 0-9 حصراً
import { writable, derived, get } from 'svelte/store';
import ar from './messages/ar';
import fr from './messages/fr';
import en from './messages/en';

export type Locale = 'ar' | 'fr' | 'en';

const dicts: Record<Locale, Record<string, string>> = { ar, fr, en };

export const locale = writable<Locale>(((): Locale => {
  const saved = typeof localStorage !== 'undefined' ? localStorage.getItem('zudz-locale') : null;
  return saved === 'ar' || saved === 'fr' || saved === 'en' ? saved : 'ar';
})());

locale.subscribe((l) => {
  if (typeof localStorage !== 'undefined') localStorage.setItem('zudz-locale', l);
  if (typeof document !== 'undefined') {
    document.documentElement.lang = l;
    document.documentElement.dir = l === 'ar' ? 'rtl' : 'ltr';
  }
});

/** اتجاه الواجهة — مشتق من اللغة (تلقائي بلا تدخل) */
export const dir = derived(locale, (l) => (l === 'ar' ? 'rtl' : 'ltr'));

/** الترجمة: مفاتيح مركزية مع سقوط احتياطي en ثم المفتاح نفسه */
export function t(key: string, args?: Record<string, string | number>): string {
  const l = get(locale);
  let s = dicts[l][key] ?? dicts.en[key] ?? key;
  if (args) {
    for (const [k, v] of Object.entries(args)) {
      s = s.replaceAll(`{${k}}`, String(v));
    }
  }
  return s;
}

/** النسخة التفاعلية للقوالب: استخدم $tr('key') — يتحدّث فورياً مع اللغة */
export const tr = derived(locale, (l) => (key: string, args?: Record<string, string | number>) => {
  let s = dicts[l][key] ?? dicts.en[key] ?? key;
  if (args) {
    for (const [k, v] of Object.entries(args)) {
      s = s.replaceAll(`{${k}}`, String(v));
    }
  }
  return s;
});

// ─── سياسة الأرقام: 0-9 غربية حصراً في كل اللغات (ar-u-nu-latn) ───────
export function fmtNum(n: number): string {
  const l = get(locale);
  return new Intl.NumberFormat(`${l}-u-nu-latn`).format(n);
}

export function fmtBytes(n: number): string {
  if (n >= 1048576) return `${fmtNum(Math.round(n / 10485.76) / 100)} MB`;
  if (n >= 1024) return `${fmtNum(Math.round(n / 10.24) / 100)} KB`;
  return `${fmtNum(n)} B`;
}

/** تحويل أي أرقام شرقية/فارسية واردة إلى غربية (تعقيم البيانات الواردة) */
export function westernDigits(s: string): string {
  const map: Record<string, string> = {
    '٠': '0', '١': '1', '٢': '2', '٣': '3', '٤': '4',
    '٥': '5', '٦': '6', '٧': '7', '٨': '8', '٩': '9',
    '۰': '0', '۱': '1', '۲': '2', '۳': '3', '۴': '4',
    '۵': '5', '۶': '6', '۷': '7', '۸': '8', '۹': '9',
  };
  return s.replace(/[٠-٩۰-۹]/g, (c) => map[c] ?? c);
}
