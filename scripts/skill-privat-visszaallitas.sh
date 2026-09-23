#!/usr/bin/env bash
# VISSZAALLITAS, ha a .channels-config/skills valodi mappakent NEM mukodik.
#
# 2026-09-23, Laci dontese (Telegram 1418): a fo agens privat skilljei az
# IZOLALT CONFIG-GYOKERBE kerulnek, mert a projekt-gyoker .claude/skills
# mappajat a sub-agensek is latjak (az o munkakonyvtaruk osе az).
# A megoldas NEM volt igazolhato ujrainditas nelkul: a skill-lista induláskor
# toltodik be. Ha a kovetkezo indulas utan a 20 privat skill NEM latszik,
# futtasd ezt: mindent visszatesz oda, ahol ma delelott volt.
set -euo pipefail
ROOT=/home/bobeklajos/marveen
REAL="$ROOT/.channels-config/skills.real"
GYOKER="$ROOT/.claude/skills"

echo "1. a symlink visszaallitasa a kozos globalisra"
ln -sfn /home/bobeklajos/.claude/skills "$ROOT/.channels-config/skills"

echo "2. a 20 privat skill vissza a projekt-gyokerbe"
n=0
for d in "$REAL"/*/; do
  [ -L "${d%/}" ] && continue          # a globalisra mutato symlinkeket nem mozgatjuk
  name=$(basename "$d")
  mv "$d" "$GYOKER/$name" && n=$((n+1))
done
echo "   visszamozgatva: $n"

echo "3. index ujragenerálás"
bash "$ROOT/scripts/skill-index.sh" >/dev/null 2>&1 || true
bash "$ROOT/scripts/skill-index.sh" "$ROOT" >/dev/null 2>&1 || true
echo "KESZ. A flotta ujra latja oket -- ez a REGI, nem-privat allapot."
