#!/usr/bin/env bash
# ============================================================
#  ZUDZ — تثبيت أيقونة التشغيل في قائمة التطبيقات
#  بعد التشغيل مرة واحدة ستظهر "ZUDZ" في قائمة تطبيقاتك
#  ويمكن تشغيل الأداة بضغطة واحدة دون أي سطر أوامر.
# ============================================================
set -eu

ROOT="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
LAUNCHER="$ROOT/run-zudz.sh"
APP_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/applications"
ICON_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/icons/hicolor"

mkdir -p "$APP_DIR" "$ICON_DIR/128x128/apps" "$ICON_DIR/64x64/apps" "$ICON_DIR/48x48/apps" "$ICON_DIR/32x32/apps"

# تحويل اللوجو SVG إلى أيقونات PNG بجميع المقاسات
if command -v rsvg-convert >/dev/null 2>&1; then
    for size in 32 48 64 128; do
        rsvg-convert -w "$size" -h "$size" -o "$ICON_DIR/${size}x${size}/apps/zudz.png" "$ROOT/zudz.svg" 2>/dev/null || true
    done
    ICON="zudz"
elif command -v convert >/dev/null 2>&1; then
    convert -background none "$ROOT/zudz.svg" -resize 128x128 "$ICON_DIR/128x128/apps/zudz.png"
    ICON="zudz"
else
    ICON="$ROOT/zudz.svg"
fi

cat > "$APP_DIR/zudz.desktop" <<EOF
[Desktop Entry]
Type=Application
Version=1.0
Name=ZUDZ
GenericName=ZTE Unlock, Decrypt & Zone-changer
Comment=صيانة أجهزة ZTE GPON الشخصية — تشغيل بضغطة واحدة
Comment[en]=Maintenance tool for personal ZTE GPON devices — one click
Exec=$LAUNCHER
Icon=$ICON
Terminal=false
Categories=Network;Utility;System;
Keywords=zudz;zte;gpon;ont;router;فك تشفير;
StartupNotify=true
EOF

chmod +x "$LAUNCHER"
update-desktop-database "$APP_DIR" 2>/dev/null || true

echo "✅ تم التثبيت — ستجد ZUDZ في قائمة التطبيقات (ابحث عن ZUDZ)"
echo "✅ Installed — find ZUDZ in your applications menu"
