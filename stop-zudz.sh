#!/usr/bin/env bash
# ZUDZ — إيقاف الخادم المحلي / stop the local server
pkill -x zudz-server 2>/dev/null && echo "تم إيقاف ZUDZ / ZUDZ stopped" || echo "ZUDZ غير يعمل حالياً / not running"
