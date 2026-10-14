#!/usr/bin/env bash
# ============================================================
#  ZUDZ — مشغّل بضغطة زر / One-click launcher
#  يبني الأداة تلقائياً عند أول تشغيل (إن لزم) ثم يفتح الواجهة
#  في المتصفح. لا يحتاج أي أوامر يدوية.
# ============================================================
set -u

ROOT="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
WS="$ROOT/zudz"
BIN="$WS/target/release/zudz-server"
UI="$WS/app/build/index.html"
PORT="${ZUDZ_PORT:-8790}"
URL="http://127.0.0.1:$PORT"
LOG_DIR="${XDG_STATE_HOME:-$HOME/.local/state}/zudz"
LOG="$LOG_DIR/launcher.log"

# أدوات GUI اختيارية للإشعارات (تعمل بدونها أيضاً)
notify() {
    command -v notify-send >/dev/null 2>&1 && notify-send -a ZUDZ "$1" "$2" 2>/dev/null
    echo "[$(date '+%H:%M:%S')] $1: $2" >> "$LOG"
}

# توسيع PATH لبيئة سطح المكتب (حيث لا يُحمَّل profile المستخدم)
export PATH="$HOME/.bun/bin:$HOME/.cargo/bin:/usr/local/bin:$PATH"

mkdir -p "$LOG_DIR"
: >> "$LOG"
echo "=== ZUDZ launcher — $(date) ===" >> "$LOG"

# ---------- 1) النواة (Rust) ----------
if [ ! -x "$BIN" ]; then
    notify "ZUDZ" "أول تشغيل: جاري بناء النواة (Rust)… قد يستغرق دقائق / First run: building core…"
    command -v cargo >/dev/null 2>&1 || { notify "ZUDZ" "خطأ: Rust غير مثبت — ثبّته من rustup.rs"; exit 1; }
    (cd "$WS" && cargo build --release) >> "$LOG" 2>&1
    [ -x "$BIN" ] || { notify "ZUDZ" "فشل بناء النواة — راجع $LOG"; exit 1; }
fi

# ---------- 2) الواجهة (SvelteKit) ----------
if [ ! -f "$UI" ]; then
    notify "ZUDZ" "أول تشغيل: جاري بناء الواجهة… / First run: building UI…"
    command -v bun >/dev/null 2>&1 || { notify "ZUDZ" "خطأ: Bun غير مثبت — ثبّته من bun.sh"; exit 1; }
    (cd "$WS/app" && bun install && bun run build) >> "$LOG" 2>&1
    [ -f "$UI" ] || { notify "ZUDZ" "فشل بناء الواجهة — راجع $LOG"; exit 1; }
fi

# ---------- 3) إيقاف نسخة سابقة إن كانت حية ----------
if pgrep -x zudz-server >/dev/null 2>&1; then
    pkill -x zudz-server 2>/dev/null
    sleep 1
fi

# ---------- 4) تشغيل الخادم وفتح المتصفح ----------
# عمليات telnet تحتاج CAP_NET_ADMIN (root) لإنشاء واجهة macvlan عبر netlink
# المدمج. نرفع صلاحية الخادم عند الإمكان (pkexec بواجهة رسومية، أو sudo)،
# مع الرجوع للتشغيل العادي إن تعذّر الرفع (تعمل عندها مسارات الويب/فك التشفير).
notify "ZUDZ" "جاري التشغيل… / Starting…"

start_server() {
    ( cd "$WS" && nohup "$@" </dev/null >> "$LOG" 2>&1 & )
}
wait_ready() {
    for _ in $(seq 1 30); do
        curl -sf -o /dev/null "$URL" 2>/dev/null && return 0
        sleep 0.5
    done
    return 1
}

if [ "$(id -u)" = "0" ]; then
    start_server "$BIN" "$PORT" app/build
elif command -v pkexec >/dev/null 2>&1; then
    start_server pkexec "$BIN" "$PORT" app/build
    wait_ready || { pkill -x zudz-server 2>/dev/null; start_server "$BIN" "$PORT" app/build; }
else
    start_server "$BIN" "$PORT" app/build
fi

# انتظار جاهزية الخادم (حتى 15 ثانية)
wait_ready

if curl -sf -o /dev/null "$URL" 2>/dev/null; then
    notify "ZUDZ" "الأداة جاهزة — يجري فتح المتصفح / Ready — opening browser"
    xdg-open "$URL" >/dev/null 2>&1 || firefox "$URL" >/dev/null 2>&1 || true
else
    notify "ZUDZ" "تعذر بدء الخادم — راجع $LOG"
    exit 1
fi
