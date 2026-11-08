#!/bin/bash
# 在 Linux/WSL 上对树莓派侧交付物做静态检查。
#
# 为什么需要它：开发机是 Windows，没有 bash / 没有 Suricata，
# 所以 shell 语法和行尾问题只能借 Linux 环境检查。
# 行尾检查尤其重要：CRLF 的 .sh 在树莓派上会报
#   bad interpreter: /bin/bash^M
# 而 CRLF 的 .service / .network / .conf 会让 systemd / networkd / redis 直接解析失败，
# 且**不报明显错误**（服务就是起不来）——属于最难查的一类问题。
set -u
cd "$(dirname "$0")/.." || exit 1

# --fix：把 CRLF 就地改成 LF。
# 为什么需要：Windows 上编辑时，编辑器可能按扩展名决定行尾 ——
# .sh 是 LF，但 .conf / .service / .network / 无扩展名文件会被写成 CRLF。
# 后果不会报错，而是“服务就是起不来”，白掉一半时间。
FIX=0
[ "${1:-}" = "--fix" ] && FIX=1
fail=0

echo "== shell 语法 =="
for f in install_pi.sh verify_pi.sh net/ids-capture-tuning.sh mirrors/setup_mirrors.sh tests/syntax_check.sh; do
  printf '  %-36s ' "$f"
  if bash -n "$f" 2>/tmp/ids-syntax-err; then
    echo "OK"
  else
    echo "语法错误"
    sed 's/^/      /' /tmp/ids-syntax-err
    fail=1
  fi
done

echo "== python 语法 =="
for f in suricata_redis_producer.py tune_suricata.py; do
  printf '  %-36s ' "$f"
  if python3 -m py_compile "$f" 2>/tmp/ids-py-err; then
    echo "OK"
  else
    echo "语法错误"
    sed 's/^/      /' /tmp/ids-py-err
    fail=1
  fi
done

echo "== CRLF 检查（应为空）=="
while IFS= read -r f; do
  case "$f" in
    *.gguf|*.bin|*.png) continue ;;
  esac
  if grep -qU $'\r' "$f" 2>/dev/null; then
    if [ "$FIX" = 1 ]; then
      sed -i 's/\r$//' "$f"
      echo "  已修正: $f"
    else
      echo "  CRLF: $f"
      fail=1
    fi
  fi
done < <(find . -type f \
  \( -name '*.sh' -o -name '*.py' -o -name '*.service' -o -name '*.yaml' \
     -o -name '*.yml' -o -name '*.conf' -o -name '*.network' -o -name '*.md' \) \
  -not -path './__pycache__/*')

echo "== systemd unit 关键字段 =="
for u in systemd/*.service; do
  printf '  %-36s ' "$u"
  if ! grep -q '^\[Unit\]' "$u" || ! grep -q '^\[Service\]' "$u"; then
    echo "缺少 [Unit]/[Service]"
    fail=1
  elif ! grep -qE '^\[Install\]' "$u"; then
    echo "缺少 [Install]（无法 enable）"
    fail=1
  else
    echo "OK"
  fi
done

rm -rf __pycache__ 2>/dev/null || true

if [ "$fail" = 0 ]; then
  echo
  echo "全部通过。注意：这只验证了语法/格式，Suricata 配置的**语义**正确性"
  echo "必须在真机上用 'suricata -T' 验证（install_pi.sh 会自动做）。"
else
  echo
  echo "有检查项不通过。"
fi
exit $fail
