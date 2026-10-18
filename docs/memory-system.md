# Memória-rendszer

> Az asszisztens nem felejt két üzenet között. Réteges memória hibrid kereséssel, ami magától priorizál és felejt, mint az emberi emlékezet.

---

## 🎯 Mit tud / miért érdekes

A nyelvi modellek alapból "amnéziásak": minden munkamenet üres lappal indul. Marveen ezt egy **réteges, öntisztító memóriával** oldja meg, ami az emberi emlékezetet utánozza:

- **hot** — ami MOST történik (aktív feladatok, függő döntések)
- **warm** — stabil tudás (preferenciák, konfiguráció, projekt-kontextus)
- **cold** — hosszútávú tanulságok, történeti döntések, archívum
- **shared** — más ügynököknek is releváns infó

A memóriák **salience decay**-en mennek át: ami sokáig nincs használva, halványul; ami gyakran előkerül, az "elöl" marad. A keresés **hibrid** (kulcsszó + jelentés szerint egyszerre), és minden este készül egy **napi napló** — emberi összefoglaló arról, mi történt aznap.

**Kuriózum:** az ügynök nem "adatbázist kérdez le" — ugyanúgy olvassa a memória-bejegyzéseket, mint bármi mást a kontextusában. Ettől az élmény természetes: valódi emlékezés, nem keresés. Minden adat helyi (SQLite + helyi embedding), nincs felhő-függőség, és munkamenet-újraindítást is túléli — amit az ügynök megtanult, megmarad. A dashboardon Obsidian-stílusú kapcsolati gráfban is böngészhető.

---

## 🛠 Hogyan működik

### Tárolás és tier-ek

SQLite (`store/`), FTS5 indexszel. Minden emlék: tartalom + tier + kulcsszavak + időbélyegek + opcionális 768-dimenziós embedding.

| Tier | Mikor | Példa |
|------|-------|-------|
| **hot** | aktív feladat, függő döntés | "folyamatban lévő kutatás" |
| **warm** | stabil konfig, preferencia | "tömör válaszokat kér" |
| **cold** | tanulság, történeti döntés | "a cache TTL 5 perc volt optimális" |
| **shared** | más ügynöknek is kell | "az X API kulcs a vaultban van" |

Réteg-választás automatikus: feladat kész → hot-ból törlés + napi naplóba; preferencia → warm; tanulság → cold; több ügynöknek → shared.

### Hibrid keresés (FTS5 + Vektor + RRF)

A keresés két párhuzamos csatornán fut, majd fúzionál:

- **FTS5** — SQLite natív full-text, pontos szóegyezés, gyors.
- **Vektor** — minden emlék mentéskor kap egy 768-dim embedding-et (Ollama `nomic-embed-text`); cosine similarity rangsorol, a jelentést érti, nem csak a szavakat.
- **RRF (Reciprocal Rank Fusion, k=60)** — a két lista összefésülése: `score(d) = Σ 1/(k + rank)`. Előnye: nem kell a pontszámokat normalizálni, csak a rangsor számít.

Az Ollama opcionális — nélküle is megy, csak FTS5-tel.

### Salience decay

- Első **7 nap**: nincs decay.
- 7 nap után: **0,5%/nap** csökkenés (`salience * 0.995`).
- Minimum **0,01** — sosem törlődik, csak háttérbe kerül.
- Hozzáféréskor **+0,1 boost** (max 5,0) — amit gyakran keresnek, releváns marad.

A "gentle decay": a régi emlékek nem zavarják a keresést, de mindig visszakereshetők. Az éjszakai [dream-engine](dream-engine.md) mozgatja az elavult hot tételeket cold-ba (sosem törlés).

### Napi napló

Append-only, ágensenként: automatikus bejegyzések napközben + 23:00-kor napi összefoglaló. Nem módosul — kronológiai archívum, ez kerül reggel a napindítóba.

### PreCompact hook (automatikus mentés)

Mielőtt a Claude Code kontextusablaka tömörítődik, a `PreCompact` hook átnézi a beszélgetést, kiemeli a fontos döntéseket/preferenciákat/tanulságokat, elmenti a megfelelő tierbe, és napi napló bejegyzést ír — így a tömörítéskor semmi fontos nem vész el.

### Gráf nézet + embedding backfill

A dashboard memória-oldalán force-directed (HTML5 Canvas) gráf: zoom/pan, keresés-highlight, kattintásra kibontható panel, a kulcsszó-kapcsolatokat mutatja ágensek közt. A régi, embedding nélküli emlékek automatikusan (és `POST /api/memories/backfill`-lel manuálisan) kapnak vektort.

### Szerkesztés (PUT/PATCH `/api/memories/<id>`)

- **Beágyazás:** a szövegváltoztatás eldobja a régi vektort (az a régi szövegből készült), és a szerver azonnal, a válasz megvárása nélkül (fire-and-forget) újraszámolja, mint a POST. Ha a beágyazó szolgáltatás nem elérhető, a sor vektor nélkül marad, és az éjszakai backfill pótolja. A vektor MINDEN író útján (POST, `saveMemory`, a PATCH utáni újraszámolás, a backfill) csak akkor íródik be, ha a sor még pontosan azt a szöveget és kulcsszót tartalmazza, amiből a vektor készült; egy lassan visszatérő POST- vagy backfill-beágyazás tehát nem ír régi szöveg vektort új szövegre. A csak kategóriát mozgató kérés a vektort nem érinti.
- **Homoglyph:** a PUT/PATCH válasza `homoglyph_warning` mezőt kap, ha a szerkesztés cirill vagy görög betűből többet hoz be, mint amennyi a tárolt szövegben volt (a figyelmeztetés csak jelez, a szöveg mentve marad). Aki egy jelölt emléket javít (kevesebb ilyen betű), vagy egy jogos cirill sort érintetlenül újraküld (a dashboard minden mentésnél elküldi a tartalmat), azt nem figyelmezteti; egy betű cseréje egy másik hasonmásra igen. A figyelmeztetés kódpontonként a darabszámot veti össze, nem a helyet: ha egy szerkesztés ugyanazt a hasonmás-betűt (ugyanaz a kódpont, ugyanannyi darab) csak másik szóba viszi át, az csendes marad, és a napló sem ír róla, mert a sor addig is jelölt volt. Az adatbázis egy `homoglyph_findings` sort is ír (`src_table = 'memories'`), ha a szerkesztés egy addig tiszta sorba hoz be ilyen betűt, akkor is, ha az írás nem az API-n át történt. **A napló hatóköre szűkebb, mint a figyelmeztetésé:** a kanban-triggerekkel azonos, mért 16 kisbetűs cirill karaktert nézi (`TRIGGER_CHARS`); a nagybetűs cirill (például U+0410, U+0420) és a görög (például U+03BF) a válaszban figyelmeztet, de a naplóba nem kerül, mert az SQLite `LIKE` a nem-ASCII betűknél kis- és nagybetű-érzékeny. Amelyik sorban már van ilyen betű, azt nem naplózza újra minden szerkesztésnél. Az INSERT-et (POST, `saveAgentMemory`) a napló nem fedi, ott csak a POST válasza figyelmeztet.

### API

```bash
POST /api/memories                       # mentés (agent_id, content, tier, keywords)
GET  /api/memories?agent=&q=&tier=        # keresés (kulcsszó)
GET  /api/memories/search?agent=&q=&hybrid=true   # hibrid (FTS5 + vektor)
POST /api/daily-log                       # napi napló (append-only)
POST /api/memories/backfill               # embedding backfill
```

Zero-config: az SQLite automatikusan létrejön, az embedding mentéskor generálódik.
