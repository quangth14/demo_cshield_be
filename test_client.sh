#!/usr/bin/env bash
# Reference client cho CSI-LOGSIG-v1. Dùng để test e2e và làm mẫu ký cho client Android.
set -u
BASE="${BASE:-http://localhost:8080}"
KID="${KID:-k_local}"
# SECRET = hex của 32 raw bytes; dùng làm HMAC key qua -macopt hexkey (KHÔNG dùng chuỗi hex làm key)
SECRET="${SECRET:-8e3bd70259f4a16c11bd4790e2357acf6418ab53de0972f12c864fba0d9763e8}"
PATH_SIG="/v1/log_detection:batch"
LABEL="CSI-LOGSIG-v1"

pass=0; fail=0
check() { # $1=desc $2=expected_http $3=got_http $4=body
  if [ "$2" = "$3" ]; then echo "  PASS [$1] http=$3 $4"; pass=$((pass+1));
  else echo "  FAIL [$1] expected=$2 got=$3 $4"; fail=$((fail+1)); fi
}

body_hash() { shasum -a 256 | awk '{print $1}'; }
sign() { # stdin=string-to-sign -> base64(hmac); key = hex-decode(SECRET)
  openssl dgst -sha256 -mac HMAC -macopt hexkey:"$SECRET" -binary | base64
}
now_ms() { echo $(( $(date +%s) * 1000 )); }
rand_nonce() { openssl rand -hex 16; }

# gửi 1 request; export SIG_TS/SIG_NONCE để test replay
send() { # $1=body $2=ts $3=nonce $4=signature -> "HTTP<code>\n<body>"
  curl -s -o /tmp/csi_resp.json -w "%{http_code}" \
    -H "Content-Type: application/json; charset=utf-8" \
    -H "X-CSI-Key-Id: $KID" \
    -H "X-CSI-Timestamp: $2" \
    -H "X-CSI-Nonce: $3" \
    -H "X-CSI-Signature: $4" \
    --data-binary "$1" "$BASE$PATH_SIG"
}

sts_for() { # $1=ts $2=nonce $3=bodyhash
  printf '%s\n%s\n%s\n%s\n%s\n%s' "$LABEL" "POST" "$PATH_SIG" "$1" "$2" "$3"
}

BODY='{"sdk":{"name":"cshield-android","version":"1.4.0","type":"injection"},"app":{"package":"com.example.app"},"device":{"os":"android"},"sent_ts":1731123999000,"events":[{"event_id":"11111111-1111-4111-8111-111111111111","seq":1024,"name":"threat_detected","ts":1731123456789,"params":{"threat":"FRIDA","killed":true}}]}'
BH=$(printf '%s' "$BODY" | body_hash)

echo "== 1) Valid request =="
TS=$(now_ms); NC=$(rand_nonce); SIG=$(sts_for "$TS" "$NC" "$BH" | sign)
CODE=$(send "$BODY" "$TS" "$NC" "$SIG"); check "valid->accepted" 200 "$CODE" "$(cat /tmp/csi_resp.json)"

echo "== 2) Same event_id, nonce+ts mới -> duplicated =="
TS=$(now_ms); NC=$(rand_nonce); SIG=$(sts_for "$TS" "$NC" "$BH" | sign)
CODE=$(send "$BODY" "$TS" "$NC" "$SIG"); check "dup->duplicated" 200 "$CODE" "$(cat /tmp/csi_resp.json)"

echo "== 3) Replay (nonce+ts+sig cũ lặp lại) -> 401 replay =="
CODE=$(send "$BODY" "$TS" "$NC" "$SIG"); check "replay" 401 "$CODE" "$(cat /tmp/csi_resp.json)"

echo "== 4) Bad signature -> 401 bad_sig =="
TS=$(now_ms); NC=$(rand_nonce)
CODE=$(send "$BODY" "$TS" "$NC" "AAAAbadsig=="); check "bad_sig" 401 "$CODE" "$(cat /tmp/csi_resp.json)"

echo "== 5) Missing header -> 401 missing_header =="
CODE=$(curl -s -o /tmp/csi_resp.json -w "%{http_code}" -H "Content-Type: application/json" --data-binary "$BODY" "$BASE$PATH_SIG")
check "missing_header" 401 "$CODE" "$(cat /tmp/csi_resp.json)"

echo "== 6) Skew (ts quá cũ) -> 401 skew =="
TS=$(( $(now_ms) - 600000 )); NC=$(rand_nonce); SIG=$(sts_for "$TS" "$NC" "$BH" | sign)
CODE=$(send "$BODY" "$TS" "$NC" "$SIG"); check "skew" 401 "$CODE" "$(cat /tmp/csi_resp.json)"

echo "== 7) Unknown key_id -> 401 unknown_key =="
TS=$(now_ms); NC=$(rand_nonce); SIG=$(sts_for "$TS" "$NC" "$BH" | sign)
CODE=$(curl -s -o /tmp/csi_resp.json -w "%{http_code}" \
  -H "Content-Type: application/json" -H "X-CSI-Key-Id: nope" \
  -H "X-CSI-Timestamp: $TS" -H "X-CSI-Nonce: $NC" -H "X-CSI-Signature: $SIG" \
  --data-binary "$BODY" "$BASE$PATH_SIG")
check "unknown_key" 401 "$CODE" "$(cat /tmp/csi_resp.json)"

echo "== Test vector (cho client verify byte-for-byte) =="
echo "  body_sha256_hex = $BH"
FTS=1731123999000; FNC=00112233445566778899aabbccddeeff
echo "  fixed ts        = $FTS"
echo "  fixed nonce     = $FNC"
echo "  signature       = $(sts_for "$FTS" "$FNC" "$BH" | sign)"

echo ""
echo "RESULT: pass=$pass fail=$fail"
