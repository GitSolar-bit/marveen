#!/usr/bin/env python3
"""destructive-gate.py -- PreToolUse kapu a valoban visszafordithatatlan muveletekre.

MIERT LETEZIK (2026-09-08): az agensek atalltak engedelylistas (strict) modrol
permissive modra, mert az engedelylista sosem lehet teljes -- egy nap alatt haromszor
NEM a jogosultsag bukott el, hanem a HIVAS ALAKJA (relativ ut, cd-prefix, heredoc), es
hetbol negy agens allt egyszerre jovahagyasi kepernyon trivialis dolgokon (python3, cd,
tmux list-sessions, a sajat konyvtara olvasasa).

DE: a permissive mod a `--dangerously-skip-permissions` kapcsoloval indul, ami a
settings.json DENY listajat is hatalytalanitja. Ott pedig olyan tiltasok alltak, amelyek
TUDATOS dontesek voltak, nem veletlenek:
  - Istvan dontese 2026-09-07: a sub-agensek NEM kapnak mv/rm jogot. Indok: aznap a
    duplikacio MENTETTE MEG az adatot, tehat a torles ara bizonyitottan magas.
  - Hitelesito adatok olvasasanak tiltasa.
  - A kozos repoba valo push: kifele mutato, visszafordithatatlan.

KET SZABALY AZOTA SZUKULT (PR #1357 review, Szabolcs; Istvan mind az ot pontot
jovahagyta). Nem enyhites, hanem a hatar athelyezese oda, ahol a kockazat tenylegesen
van -- ugyanaz az indok, ami 2026-09-14-en a szovegkornyezet-erzekenyseget kikenyszeritette:

  - TORLES: a munkakonyvtar (PROJECT_ROOT) ALATT engedett. Kivul, valamint a vedett
    utvonalakon (.git, store/, scripts/hooks/, backups/) tovabbra sem. Az agens a sajat
    munkaterulete szemetet takaritja; a verziotortenetet es az eles allapotot nem. Ami
    nem eldontheto (behelyettesites, csovezetekbol jovo lista, cwd nelkuli relativ ut),
    az tovabbra is BLOKK. ES: ez az egesz engedely csak ELDOBHATO masolatban (worktree,
    CI-klon) all -- ELES telepites gyokeren nem, lasd _live_install() (be8ef9f1).
  - PUSH: a sajat munkaagra valo push engedett. Tiltott marad az eroltetett push
    (--force es tarsai, '+' refspec), a tavoli ag torlese, a --all, es a vedett agakra
    (main/master) iranyulo push. Cel-ag nelkuli `git push` szinten blokk: az upstream
    nem latszik a parancsbol, tehat nem eldontheto, hova menne.

  Miert nem maradt a szigorubb alak: egy tiltas, amit a mindennapi munka naponta
  beleutkozik, nem kockazatot csokkent, hanem megkerulest tanit -- ezt a kapu sajat
  merese mar egyszer kimutatta (lasd lentebb). A dontes az operatore: a kapu egeszet
  a biztonsagi profil kapcsolja be (`destructiveGate`), es alapbol KI van kapcsolva.

A HOOK a permission-modtol FUGGETLENUL fut. Ezert ami tenyleg tilos, az ide kerul, nem a
deny listara. A deny lista permissive modban disz; a hook nem az.

Ez a kapu SZANDEKOSAN SZUK. Nem azt sorolja fel, mi szabad (az volt a regi, elbukott
modell), hanem azt a nehany dolgot, amit nem szabad.

MIERT LETT SZOVEGKORNYEZET-ERZEKENY (2026-09-14, kartya ba856d56, lean-chief dontese):
A kapu eredetileg a parancs TELJES SZOVEGEBEN keresett mintat. Meres 3365 egyedi, valos
parancson: 109 blokk, ebbol 31 HAMIS POZITIV (28,4%) -- a minta heredoc-torzsben,
karakterlanc-literalban vagy kommentben allt, a muvelet SOHA nem hajtodott vegre. A
merest vegzo agens maga hatszor akadt el rajta egyetlen feladat kozben, es harom esetben
epp a hamis pozitivok DOKUMENTALASA, JELENTESE, illetve MAGA EZ A JAVITAS volt a
blokkolt muvelet. Ez nem kenyelmi kerdes: amig az atfogalmazas olcsobb, mint a jelentes,
a kapu nem kockazatot csokkent, hanem egyre ugyesebb megkeruleseket tanit.

A javitas NEM lazitja a szabalyokat (a lean-chief kifejezetten elvetette a "jelzes
blokkolas helyett" iranyt). Csak azt valtoztatja meg, HOL keres:
  1. a shell- es kod-KOMMENTSOROK nem futnak le -> kimaradnak;
  2. az ADAT-heredoc torzse ("cat > fajl <<EOF") fajlba megy -> kimarad;
  3. az ERTELMEZONEK adott heredoc torzse ("python3 - <<PY") FUT -> BENNE MARAD.
     Ez a kulonbsegtetel kotelezo elem volt: a mereskor ket VALODI hitelesito-fajl-
     olvasas allt ilyen torzsben, es egy naiv "heredoc kihagyasa" elengedte volna oket;
  4. a szokozt tartalmazo idezojeles szoveg proza vagy adat (uzenet-torzs, JSON-payload,
     regex-minta, teszt-eset), nem utvonal -> kimarad. A szokoz NELKULI idezojeles
     szoveg lehet utvonal, ezert az BENNE MARAD. Ugyanez all a beagyazott kodra: egy
     utvonal-literal szokoz nelkuli, egy magyarazo mondat nem az;
  5. a szegmensekre bontas es a parancsnev-felismeres IDEZOJEL-TUDATOS lett: egy '|'
     vagy ';' egy idezett grep-mintan belul nem vag uj szegmenst, es egy szokozt
     tartalmazo idezett szoveg (peldaul egy teszteset leirasa) nem parancsnev.

ISMERT, TUDATOSAN VALLALT KORLAT: ha egy utvonal SZOKOZT tartalmaz es idezojelben all,
a Bash-ag nem veszi eszre. A fajl-eszkoz ag (Read/Edit/Write) viszont igen, es azon a
meres 0 hamis pozitivot mutatott, ezert ott nem valtozott semmi.

Meres es reprodukcio: docs/destruktiv-kapu-hamis-pozitiv-meres.md
Regresszios teszt: scripts/__tests__/destructive-gate.test.py

Blokkolas: exit 2 + indoklas a stderr-re (a Claude Code ezt visszaadja az agensnek).
"""
import fnmatch, functools, json, os, re, sys

# Parancsok, amelyeket nem az agens dont el. Nem stilus-kerdes: mindegyik adatot vagy
# allapotot semmisit meg visszafordithatatlanul.
BANNED_CMDS = {'rm', 'mv', 'shred', 'sudo', 'mkfs', 'dd'}
# 'rm' a listan marad, de NEM feltetel nelkul: sajat, szukebb szabalya van lentebb
# (_rm_allowed). A halmazban azert all, hogy egy jovobeli szerkesztes ne felejtse el:
# ez tovabbra is destruktiv parancs, csak nem mindig tiltott.

# GATEGAPS1003 (kartya e2059d3c): az `rm` csaladja. Az `unlink` ugyanazt a visszafordithatatlan
# torlest vegzi, es a v4 elo meresen (HEX, 2026-10-03) atment, mert a kapu csak az `rm` nevet ismerte.
# Ugyanazt a szabalyt kapja (_rm_allowed), nem sajatot: a sajat munkateruleten belul szabad, azon
# kivul nem, es ami nem eldontheto, az BLOKK.
# AZ `rmdir` SZANDEKOSAN NINCS ITT. Csak URES konyvtarat torol (a kernel megtagadja a nem uresét),
# adatot nem semmisit meg, es a teszt-keszlet NEGATIV kontrollja ("rmdir /tmp/ures" -- artalmatlan
# hetkoznapi parancs, a #1357 review-bol) kifejezetten atengedettnek rogzitette. Felvetele ennek a
# kontrollnak a megfordítasa, vagyis tulajdonosi dontes: ha kell, ide kerul ('rmdir'), es a kontroll
# is atiratik. Nem irtam at a bukott tesztet, hogy atmenjen.
RM_FAMILY = ('rm', 'unlink')

# PONDERNODELETE1004 (HEX 2483, a terv: a gazda vazlata + Sam): az agensek, akiknek NINCS torlesi joguk, a
# sajat munkateruletuk alatt sem. Mas agensnel a sajat <nev> alatti torles szabad (FLEETOWNDIR1003), itt
# nem. MERT A KAPUBAN, es nem a settings.json deny-listajaban: a scaffold az elso inditaskor a profilbol
# ujraepiti a deny-t (merve: 33 -> 29 szabaly, a negy kezzel beirt torles-tiltas eltunt), es egy
# `Bash(rm:*)`-szeru minta csak a parancs elejet latja, a kapu pedig az rm/unlink/find -delete/eval/
# \rm/X=rm; $X/osszetett sor alakokat mar iteli. Ket kulonbseg az altalanos szabalyhoz kepest:
#   1. a sajat munkaterulet NEM kivetel (_rm_allowed, _check_find_delete);
#   2. az `rmdir` is torles (check_bash): mindenki masnak szabad (RM_FAMILY megjegyzese), nekik nem.
# Az azonositas a transcript-utbol jon (OWN_AGENT), tehat ugyanaz a megbizhatosagi szint, mint a sajat
# terulet jogaknal: ismeretlen hivo ugyis a teljes tiltas alatt all. Uj nev felvetele ide, tesztelve.
NO_DELETE_AGENTS = frozenset({'ponder'})

# A telepites gyokere. A sajat helyzetebol szarmazik -- <ROOT>/scripts/hooks/ezafajl --,
# nem konfigbol: egy kapunak nem lehet olyan bemenete, amit a vizsgalt fel is at tud irni.
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
# A munkakonyvtar alatt is vedett alkonyvtarak. A 'rm' engedelye a MUNKARA szol, nem a
# verziotortenetre es nem a futo allapotra: a .git ujrairhatatlan, a store/ pedig az
# eles adatbazist, a tokent es a vault-ot tartalmazza -- pont az, aminek az elvesztese
# 2026-09-07-en a tiltast egyaltalan indokolta.
# Utvonal-ELOTAGOK, komponensekre bontva. Az illeszkedes MINDKET iranyban szamit:
# a 'scripts' torlese ugyanugy megoli a kaput, mint a 'scripts/hooks'-e, ezert ha a
# torlendo ut egy vedett elotag OSE, az is blokk. (Merve 2026-09-25, be8ef9f1: elotte
# az `rm -rf <root>/scripts/hooks` -- maga a kapu -- ATMENT.)
RM_PROTECTED = (
    ('.git',),                # ujrairhatatlan verziotortenet
    ('store',),               # eles DB, token, vault
    ('scripts', 'hooks'),     # MAGA EZ A KAPU. Enelkul a kapu megkerulese egy rm.
    ('backups',),             # a mentesek; a torlesuk pont akkor derul ki, amikor mar kellenenek
)


def _live_install(root):
    """Eles telepites-e ez a gyoker, vagy eldobhato masolat (worktree, CI-klon)?

    Miert kell (be8ef9f1): a PROJECT_ROOT a FAJL helyebol szarmazik, tehat ugyanez a
    szabaly mast jelent minden peldanyban. Amig a fajl egy worktree-ben ul, a
    munkakonyvtar alatti torles egy eldobhato masolatot erint. Amint a PR beolvad es a
    fajl az ELES gyokerbe kerul, PONTOSAN UGYANAZ a szabaly az eles telepitesre
    vonatkozik -- ez nem uj kockazat bevezetese, hanem egy meglevo szabaly athelyezese
    oda, ahova nem szantak.

    A jelolo a store/ ket, TELEPITESKOR keletkezo allomanya. A store/ gitignore-olt
    (.gitignore:17), tehat sem CI-klonban, sem worktree-ben nincs meg -- merve
    2026-09-25-en mindharom helyen. Ezert a PR sajat tesztjei (amelyek a munkakonyvtar
    alatti torlest ENGEDETTNEK varjak) valtozatlanul zoldek maradnak, mikozben az eles
    gyokeren a szabaly nem alkalmazhato.

    A nem-eldontheto eset itt a SZIGORU fele esik: ha a jelolot nem tudjuk megnezni
    (jogosultsag, I/O), eles telepitesnek vesszuk.
    """
    for marker in ('claudeclaw.db', '.dashboard-token'):
        try:
            if os.path.exists(os.path.join(root, 'store', marker)):
                return True
        except OSError:
            return True
    return False


def _main_agent_id():
    """A fo agens neve a blokk-uzenetben (FLEETOWNDIR1003): MAIN_AGENT_ID az env-bol, utana a
    telepites .env-jebol, utana a szallitott alapertek. Korabban az uzenet egy olyan
    szereplore mutatott, aki ebben a telepitesben nem letezik, tehat aki elakadt, annak
    nem volt kihez fordulnia. Soha nem dobhat: a block() ezt hivja."""
    v = os.environ.get('MAIN_AGENT_ID')
    if v and v.strip():
        return v.strip()
    try:
        with open(os.path.join(PROJECT_ROOT, '.env'), encoding='utf-8') as f:
            for line in f:
                if line.startswith('MAIN_AGENT_ID='):
                    got = line.split('=', 1)[1].strip().strip('"\'')
                    if got:
                        return got
    except Exception:
        pass
    return 'marveen'

# Ki az az agens, akinek a hivasat vizsgaljuk. A main() tolti ki a hook-esemeny
# transcript_path mezojebol -- NEM a cwd-bol: a cwd egy `cd`-vel a session kozben
# valtozik, a transcript utja viszont a session sajat config-konyvtarabol szarmazik,
# es vegig ugyanaz marad (ugyanez az oka, amiert a ledger_lib.agent_id_from_payload
# is ezt veszi eloszor, LEDGERCWD828). A cwd-bol szarmaztatott identitassal egy
# `cd ../masik-agens` a MASIK agens munkaterulet-jogat adna. None = ismeretlen, es az
# ismeretlen a SZIGORU fele esik: nincs sajat munkaterulet, marad a teljes tiltas.
OWN_AGENT = None
_AGENT_ID_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_-]*$')

# A SAJAT munkaterulet, ahol egy al-agens torolhet az ELES telepiteseken is
# (FLEETOWNDIR1003). MERVE 2026-10-03, egy al-agens esete: a sajat atmeneti fajljanak
# (<HOME>/agents_munka/<nev>/tmp.json) torlese BLOKKOLODOTT, mert a
# kapu az eles telepiteseken MINDEN torlest megallit. A munkamappa NEM az agents/<nev>
# volt, hanem a telepiteson KIVULI ~/agents_munka/<nev>: az operator 2026-09-23-i
# rendezese szerint az agensek MUNKAJA ott gyulik, az agents/<nev> alatt csak a rendszer-fajlok
# maradnak (CLAUDE.md, SOUL.md, agent-config.json, memory/, avatar) -- lasd
# ~/agents_munka/README.md, 4. szabaly: "Torolni csak a sajat mappadbol szabad".
# Ezert az agents/<nev> SZANDEKOSAN NEM kap torlesi jogot: ott a konfig, a hook-bekotes
# (.claude*) es a szemelyiseg ul, es a megmert eset sem kerte.
#
# Mit ad es mit NEM ad ez a jog:
#   - csak a SAJAT <nev> alatt: a masik agens mappaja, a kozos/ es a fo agens mappaja, az
#     agents/ fa, a store/, a scripts/hooks/ (maga a kapu), a .git es a telepites
#     tobbi resze tovabbra is tiltott;
#   - a terulet GYOKERE maga nem torolheto (_under: a gyoker nem szamit bele);
#   - symlink: a gyoker maga nem lehet symlink (_area_root), es a torlendo ut
#     SZULOJET _resolve feloldja (a '..'-ot is fizikailag), tehat egy kifele mutato
#     link-konyvtaron at nem lehet torolni; a link maga (`rm link`) csak magat a
#     linket viszi.
AGENTS_MUNKA_ROOT = os.path.join(os.path.expanduser('~'), 'agents_munka')


def _agent_from_transcript(path):
    """<install>/agents/<nev>/.claude-config/... transcript-utbol <nev>, kulonben None.

    Szandekosan szigoru: csak a sub-agens SAJAT, izolalt config-gyokere alatti ut
    ad identitast. A fo agens (a telepites mas pontjan, vagy ~/.claude alatt) nem
    kap ilyen jogot -- az o torlesei eles gyokeren tovabbra is a teljes tiltas ala
    esnek, es ezen ez a javitas nem valtoztat.
    """
    if not isinstance(path, str) or not path.strip():
        return None
    path = os.path.normpath(path.strip())
    agents_root = os.path.join(PROJECT_ROOT, 'agents') + os.sep
    if not path.startswith(agents_root):
        return None
    parts = path[len(agents_root):].split(os.sep)
    if len(parts) < 3 or parts[1] != '.claude-config' or not _AGENT_ID_RE.match(parts[0]):
        return None
    return parts[0]


def _area_root(path):
    """A terulet gyokere, ha az maga nem symlink es nem megy at symlinken; kulonben None.

    Miert: ha az ~/agents_munka/<nev> egy symlink lenne a store/-ra, a realpath a store/-t
    adna gyokerkent, es onnantol a store/ torlese "sajat munkaterulet" volna. A gyoker
    ezert csak akkor ervenyes, ha a SZULOJE feloldott alakjan a neve maga a gyoker.
    """
    parent, name = os.path.split(os.path.normpath(path))
    try:
        expect = os.path.join(os.path.realpath(parent), name)
        if os.path.realpath(path) != expect:
            return None
    except OSError:
        return None
    return expect


def _own_area(agent):
    """Az agens sajat munkateruletenek gyokere, vagy None ha ismeretlen / nem hiteles."""
    if not agent or not _AGENT_ID_RE.match(agent):
        return None
    return _area_root(os.path.join(AGENTS_MUNKA_ROOT, agent))


_GLOB_CHARS = '*?[()'


def _area_literal_ok(raw):
    """(ok, indoklas): a sajat-terulet jog CSAK ilyen argumentumra szol (FLEETOWNDIR1003).

    A jog nem a cwd-re es nem a shell allapotara epul, mert azok a kapu szamara nem
    kovethetok vegig. MERVE 2026-10-03 (felulvizsgalo meres): `cd -P`, `set -P`, `pushd`,
    `env -C`, CDPATH -- hat alakbol hat atment, mert a kapu a sajat teruletet hitte
    cwd-nek, a bash kozben mashol allt. A foltozas vegtelen lista, ezert a szabaly maga
    fuggetlen a cwd-tol: az argumentum
      - LITERAL ABSZOLUT ut ('/'-rel kezdodik; a '~' a $HOME-bol szarmazik, ami egy
        `HOME=... ;` sorral atirhato, a '~+' pedig a cwd), es nincs benne visszaper
        (egy visszaperrel vedett perjel a shellben sima perjel, a kapu viszont mast
        latna: a zaro perjel dereferalasa elbujna);
      - a glob/minta KIZAROLAG az utolso komponensben allhat, zaro perjel nelkul. A
        konyvtar-komponens literal, tehat fizikailag feloldhato; az utolso komponens
        pedig csak BEJEGYZESEKET nevez meg (egy link torlese csak a linket viszi), es a
        shell opcioi (dotglob, GLOBIGNORE, extglob) sem vihetik ki a literal konyvtarbol.
    Relativ argumentumnal a teljes tiltas marad.
    """
    if not raw.startswith('/'):
        return False, ('relativ vagy ~-os ut: a sajat munkaterulet-jog csak literal ABSZOLUT '
                       'utra szol (a cwd-kovetes nem megbizhato). Add meg abszolutan: %s' % raw[:60])
    if '\\' in raw:
        return False, 'visszaper az utban: a shell mast ertene rajta, mint a kapu'
    comps = raw.rstrip('/').split('/')
    for comp in comps[:-1]:
        if any(c in comp for c in _GLOB_CHARS):
            return False, ('glob/minta a KONYVTAR-komponensben: a shell kibontasa a link '
                           'celjaba is vihet, ezt a kapu nem koveti: %s' % raw[:60])
    if raw.endswith('/') and any(c in comps[-1] for c in _GLOB_CHARS):
        return False, 'glob zaro perjellel: a shell linkekre is kibontja, es dereferal: %s' % raw[:60]
    return True, ''


# Feloldhatatlan alakok egy torlendo utvonalban. A '*' es a '?' NEM szerepel: a shell
# glob nem lep at '/'-en, tehat egy munkakonyvtar alatti minta a munkakonyvtar alatt
# marad. A behelyettesites viszont barmive kiertekelodhet, azt nem latjuk elore.
#
# FIGYELEM, es ezt 2026-09-25-ig rosszul olvastuk (9e34a3b7): a fenti mondat a
# GYOKERBOL VALO KILEPESRE igaz, es CSAK arra. A vedett lista (RM_PROTECTED)
# viszont nem a gyokerbol kilepest tiltja, hanem a gyokeron BELULI neveket vedi --
# es oda a '*' nagyon is elerhet, mert a shell a kapu verdiktje UTAN terjeszti ki.
# Ezert a vedett-lista illesztese fnmatch-csel megy (_rm_allowed), nem '=='-vel.
# Ha valaki ujra azt merlegeli, hogy a '*' bekeruljon-e ebbe a listaba: az ITT
# helyes indoklas a kilepes, a vedett nevekre mar van valasz.
RM_UNRESOLVABLE = ('$', '`', '{', '}')
# Push-kapcsolok, amelyek a tavoli tortenetet irjak ujra vagy toroltetnek refet.
PUSH_FORCE_FLAGS = {'-f', '--force', '--force-with-lease', '--force-if-includes', '--mirror'}
PUSH_DELETE_FLAGS = {'-d', '--delete'}
# Ertekuket KULON szoban hozo push-kapcsolok (kulonben a szomszedjuk refspecnek latszik).
PUSH_VALUE_FLAGS = {'-o', '--push-option', '--receive-pack', '--exec', '--repo'}
# A vedett agak: ide kezzel, review-val megy valami, nem egy agens push-abol.
PROTECTED_BRANCHES = {'main', 'master'}
# Ut-elotagok, amelyek hitelesito adatot tartalmaznak.
PROTECTED_READ = ('.ssh', '.aws', '.gnupg', '.gmail-mcp')
# A hataroloval egyutt illesztunk: a puszta minta ELENGEDTE a zaro perjel nelkuli alakot,
# pedig pont az volt az eles eset 2026-09-08-an. A hatarolo azert kell, hogy a
# hasonlo kezdetu, de mas nevu konyvtar NE illeszkedjen.
PROTECTED_RE = re.compile(r'/\.(ssh|aws|gnupg|gmail-mcp)(?=/|\s|$|["\'])')
ENV_RE = re.compile(r'(?:^|[\s=:])(?:[^\s"\']*/)?\.env(?=$|[\s"\'`,;)\]}])')

# Amelyik parancs a heredoc-torzset VEGREHAJTJA, nem fajlba irja. Csak ezeknel marad
# bent a torzs a vizsgalt szovegben.
INTERPRETERS = {'python', 'python3', 'bash', 'sh', 'zsh', 'node', 'bun', 'perl', 'ruby', 'php'}
# INTERPFLAG1004: a verzioszamos alak (python3.11, perl5.38.2, node22, php8.2, ruby3.2) UGYANAZ az
# ertelmezo; a kapu eddig csak a pontos neveket ismerte, es `python3.11 -c "<torles>"` atment.
_INTERP_FAMILY_RE = re.compile(r'^(python|bash|sh|zsh|node|bun|perl|ruby|php)[\d.]*$')


def _interp_family(word):
    """A szo (utvonal-elotaggal vagy anelkul) ertelmezo-csaladja (`python3.11` -> `python`), vagy None."""
    m = _INTERP_FAMILY_RE.match(os.path.basename(word))
    return m.group(1) if m else None
SCRIPT_FLAGS = {'-c', '-e', '-E', '-p', '--command', '--eval'}
# -p is node's print-eval and -E is perl's feature-enabled -e. They are in the
# set only so the argument after them counts as CODE rather than prose. A flag
# that does not actually take a script (perl -pe, bash -p) is harmless here:
# _script_arg_ranges only records a range when a QUOTE follows the flag.

HOME = os.path.expanduser('~')

DELIMS = ('&&', '||', '$(', ';', '|', '\n', '`')


def block(msg):
    sys.stderr.write(
        'DESTRUKTIV-KAPU: BLOKKOLVA.\n' + msg +
        '\n\nEz nem jogosultsagi hiba, es nem is kell hozza jovahagyast kerned: '
        'ez a muvelet a fo agens (%s) dontese. Ha tenyleg szukseges, ird meg '
        'NEKI, hogy MIT es MIERT akarsz, es o elvegzi vagy engedelyezi.\n'
        % _main_agent_id())
    sys.exit(2)


def _quote_map(text):
    """Minden karakterhez: idezojelen belul van-e (0=nem, 1=aposztrof, 2=idezojel). Card 798c3c24: where the shell reader (_shell_scan)
    can read the text with certainty, ITS map is the map (a quote inside a `$(..)` inside double quotes, a comment, `$$'`, a
    continuation are read as bash reads them); only where it cannot is the old two-state toggle (_toggle_quote_map) used, and
    check_bash refuses a whole command in that state before any step stands on the toggle."""
    return list(_quote_map_cached(text))


@functools.lru_cache(maxsize=256)
def _quote_map_cached(text):
    try:
        qs = [0] * len(text)
        _shell_scan(text, (), qs)
        return tuple(qs)
    except _ScanUnsure:
        return tuple(_toggle_quote_map(text))


@functools.lru_cache(maxsize=256)
def _ansi_strings(text):
    """{offset of the `$`: (start, end)} of every `$'..'` at command level, or None where the shell reader cannot read the text."""
    try:
        found = []
        _shell_scan(text, (), None, ansis=found)
        return {d: (a, b) for d, a, b in found}
    except _ScanUnsure:
        return None


_ANSI_SIMPLE = {'a': 7, 'b': 8, 'e': 27, 'E': 27, 'f': 12, 'n': 10, 'r': 13, 't': 9, 'v': 11, '\\': 92, "'": 39, '"': 34, '?': 63}


def _utf8_any(cp):
    """UTF-8 of a code point the way bash writes it for `\\u` / `\\U`: the old scheme up to six bytes, a surrogate or a value past U+10FFFF
    included (bash does not refuse them)."""
    if cp < 0x80:
        return bytes([cp])
    for nbytes, limit, lead in ((2, 0x800, 0xC0), (3, 0x10000, 0xE0), (4, 0x200000, 0xF0), (5, 0x4000000, 0xF8), (6, 0x80000000, 0xFC)):
        if cp < limit:
            out = bytearray()
            for _ in range(nbytes - 1):
                out.insert(0, 0x80 | (cp & 0x3F))
                cp >>= 6
            out.insert(0, lead | cp)
            return bytes(out)
    return b''


def _ansi_decode(body, printf=False):
    """What bash makes of the inside of `$'..'`: the escapes expanded, the bytes read as UTF-8; the word ends at a NUL byte. Equal to the
    real bash on a byte-level differential (card 4b42b6b0 round 2: `\\c?` is 0x7f, `\\c\\\\` is ONE control-backslash that eats both
    backslashes, `\\u` / `\\U` write any value as bash does). `printf=True` is the reading of a printf format or `echo -e`, where `\\c`
    ends the output instead of making a control character."""
    out = bytearray()
    i, n = 0, len(body)
    while i < n:
        ch = body[i]
        if ch != '\\' or i + 1 >= n:
            out += ch.encode('utf-8', 'surrogateescape')
            i += 1
            continue
        c = body[i + 1]
        if c in _ANSI_SIMPLE:
            out.append(_ANSI_SIMPLE[c])
            i += 2
        elif c in '01234567':
            j = i + 1
            while j < n and j < i + 4 and body[j] in '01234567':
                j += 1
            out.append(int(body[i + 1:j], 8) & 255)
            i = j
        elif c in 'xuU':
            width = {'x': 2, 'u': 4, 'U': 8}[c]
            j = i + 2
            while j < n and j < i + 2 + width and body[j] in '0123456789abcdefABCDEF':
                j += 1
            if j == i + 2:
                out += ('\\' + c).encode()
            elif c == 'x':
                out.append(int(body[i + 2:j], 16))
            else:
                cp = int(body[i + 2:j], 16)
                out += _utf8_any(cp) if cp < 0x80000000 else body[i:j].encode('utf-8', 'surrogateescape')
                if cp == 0:
                    out.append(0)
            i = j
        elif c == 'c' and i + 2 < n:
            if printf:
                break                                   # printf / echo -e: \c ends the output
            x = body[i + 2]
            if x == '\\':
                out.append(0x1C)
                i += 4 if body[i + 3:i + 4] == '\\' else 3
            else:
                out.append(0x7F if x == '?' else ord(x) & 0x1F)
                i += 3
        else:
            out += ('\\' + c).encode('utf-8', 'surrogateescape')
            i += 2
    cut = out.find(0)
    if cut >= 0:
        out = out[:cut]
    return out.decode('utf-8', 'surrogateescape')


def _toggle_quote_map(text):
    """The old reader: a two-state toggle, the fallback of _quote_map.

    Toleransan kezeli a parositatlan idezojelet is: nem dob hibat, csak allapotot valt.
    Az ANSI-C `$'...'` szoveg 1-es allapotot kap (literalis, mint az aposztrof), DE benne a
    backslash escape-el: `$'a\\'b'` egy szo. Az aposztrof-modell ezt ketfele vagta, a hatralevo
    szoveg (a kovetkezo sor rm-je is) idezettnek latszott (f8acbcb4).
    """
    state = [0] * len(text)
    q = 0                           # 3 = ANSI-C `$'...'`: reported as 1, but a backslash escapes there (f8acbcb4)
    dollars = 0                     # unescaped `$` characters right before this one
    i = 0
    while i < len(text):
        ch = text[i]
        if ch == '\\' and q != 1 and i + 1 < len(text):
            state[i] = 1 if q == 3 else q
            state[i + 1] = state[i]
            dollars = 0
            i += 2
            continue
        if q == 0 and ch in ("'", '"'):
            # `$'` opens an ANSI-C string only when the `$` is not the second half of `$$` (the PID parameter).
            q = 3 if (ch == "'" and dollars % 2 == 1) else (1 if ch == "'" else 2)
            state[i] = 0            # maga a nyito jel nincs "belul"
            dollars = 0
            i += 1
            continue
        if (q in (1, 3) and ch == "'") or (q == 2 and ch == '"'):
            state[i] = 0            # a zaro jel sincs
            q = 0
            dollars = 0
            i += 1
            continue
        state[i] = 1 if q == 3 else q
        dollars = dollars + 1 if (q == 0 and ch == '$') else 0
        i += 1
    return state


def _blank_ranges(text, ranges):
    """A megadott tartomanyokat szokozre cvereli, a sortoreseket megtartva.
    Az offsetek igy valtozatlanok maradnak, ami a hibakeresest is olvashatova teszi."""
    if not ranges:
        return text
    out = list(text)
    for a, b in ranges:
        for i in range(max(0, a), min(len(out), b)):
            if out[i] != '\n':
                out[i] = ' '
    return ''.join(out)


def _heredoc_opener_runs_body(head):
    """A `<<` ELOTTI resz alapjan: a torzs PROGRAM lesz, vagy egy program BEMENETE?

    A kulonbseg nem az, hogy szerepel-e ertelmezo-nev a soron, hanem az, hogy az
    ertelmezo HONNAN veszi a programjat (79d8b59c):
      bash <<SH            -> nincs megnevezve program, marad a stdin  -> PROGRAM
      bash -s <<SH         -> a -s kifejezetten stdin                  -> PROGRAM
      python3 - <<PY       -> a '-' kifejezetten stdin                 -> PROGRAM
      bash szkript.sh <<EOF-> a program a FAJL, a torzs annak bemenete -> ADAT
      python3 -c "..." <<PY-> a program a -c utani szoveg              -> ADAT
      cat > fajl <<EOF     -> nem is ertelmezo                         -> ADAT

    A regi valtozat azt kerdezte, hogy a soron BARHOL all-e ertelmezo-nev. Ez minden
    `bash <valami>.sh <<EOF` alakra igaz, ezert egy tiltott parancs MEGEMLITESE egy
    uzenet-torzsben ugyanugy blokkolodott, mint a vegrehajtasa. 2026-09-24-en harom
    eles esetben akasztotta meg a csapat sajat dokumentaciojat, egyszer epp ennek a
    hibanak a jelenteset.
    """
    if re.search(r'(?:[})]|\b(?:fi|done|esac))\s*$', head):
        # A redirection on a COMPOUND command (`{ sh; } <<EOF`, `if ...; fi <<EOF`) feeds every command inside it: whichever
        # interpreter family word stands in the group reads the body (card 6a6191f4). Unprovable otherwise, so it is code.
        if any(_interp_family(t.strip('"\'')) is not None for t in re.split(r'[\s;&|(){}]+', head) if t):
            return True
    seg = re.split(r'\|\||&&|[;|&]', head)[-1]
    toks = [t for t in re.split(r'\s+', seg.strip()) if t]
    k = 0
    while k < len(toks) and (re.match(r'^[A-Za-z_][A-Za-z0-9_]*=', toks[k])
                             or os.path.basename(toks[k].strip('"\'')) in _TRANSPARENT):
        k += 1
    if k >= len(toks):
        return False
    base = os.path.basename(toks[k].strip('"\''))
    if base in ('.', 'source') and any(t.strip('"\'') in _STDIN_PATHS or t.startswith('<(') for t in toks[k + 1:]):
        return True                # `. /dev/stdin <<EOF`, `source <(cat <<EOF`: the shell sources its own stdin / the substitution (6a6191f4)
    if _interp_family(base) is None:
        # Ismeretlen burkolo mogott allo ertelmezo (timeout, strace, ...) ugyanugy
        # lefuttatja a torzset. A burkolo argumentum-alakjat nem talalgatjuk: marad
        # a regi, szelesebb olvasat. Igy ez a javitas SZIGORUAN szukebb valtozas --
        # csak a fenti, egyertelmu eset fordul at.
        return any(_interp_family(t.strip('"\'')) is not None for t in toks[k:])
    for t in toks[k + 1:]:
        if t in ('-', '-s') or t.strip('"\'') in _STDIN_PATHS:
            return True                # `-`, `-s`, or the stdin device named as the program file (`bash /dev/stdin <<EOF`)
        if t in SCRIPT_FLAGS:
            return False
        if t.startswith('-'):
            continue
        if t.startswith('<('):
            return True            # `sh <(cat <<EOF`: the program file is a process substitution that prints the body (6a6191f4)
        return False               # egy program-FAJL: a torzs annak a bemenete
    return True


_HEREDOC_OPEN = re.compile(r'<<-?\s*([\'"]?)([A-Za-z_][A-Za-z0-9_]*)\1')


_CMD_CTX = frozenset(('top', 'sub', 'bt', 'par'))


def _in_command_context(text, pos):
    """True only when the character at `pos` of `text` stands where bash reads COMMANDS: the top level, or inside `$( )`, a backtick pair
    or a `( )` group. Everything else is a WORD context where `<<` is plain text: a double quote, a single quote, `$'...'`, `${ }`,
    `$(( ))`, `$[ ]`, a `#` comment, and a character after a backslash. The contexts nest (`"$(echo "<<EOF")"` is a double quote inside a
    substitution inside a double quote: the innermost context decides), so a stack walks the text from the start instead of counting
    brackets on the line (card f4649c5d round 3, Sam 1762: the counting version took `echo "$(echo "<<EOF")"`, `echo \\<<EOF`,
    `echo $[1<<EOF]` and `echo ${x:-<<EOF}` for heredoc openers). Where the walk cannot tell, the answer is False."""
    stack = ['top']
    i, n = 0, min(pos, len(text))
    while i < n:
        k, c = stack[-1], text[i]
        if c == '\\':
            if i + 1 >= n:
                return False                                        # the character at `pos` is escaped
            i += 2
            continue
        if k == 'dq':
            if c == '"':
                stack.pop()
                i += 1
                continue
        elif k == 'arith' or k == 'aparen':
            if c == '(':
                stack.append('aparen')
                i += 1
                continue
            if c == ')' and k == 'aparen':
                stack.pop()
                i += 1
                continue
            if c == ')' and text[i + 1:i + 2] == ')':
                stack.pop()
                i += 2
                continue
        elif k == 'arithb':
            if c == ']':
                stack.pop()
                i += 1
                continue
        elif k == 'brace':
            if c == '}':
                stack.pop()
                i += 1
                continue
        if k in _CMD_CTX:
            if c == '#' and (i == 0 or text[i - 1] in ' \t\n;&|()<>`'):
                j = text.find('\n', i)
                if j < 0 or j >= n:
                    return False                                    # `pos` is inside a comment
                i = j
                continue
            if c == '(':
                stack.append('par')
                i += 1
                continue
            if c == ')':
                if k in ('sub', 'par'):
                    stack.pop()
                i += 1
                continue
        if k != 'dq' and c == "'":                                  # a single quote is literal inside double quotes only
            j = text.find("'", i + 1)
            if j < 0 or j >= n:
                return False                                        # `pos` is inside a single-quoted string
            i = j + 1
            continue
        if c == '"' and k != 'dq':
            stack.append('dq')
            i += 1
            continue
        if c == '`':
            if k == 'bt':
                stack.pop()
            else:
                stack.append('bt')
            i += 1
            continue
        if c == '$' and i + 1 < len(text):
            d = text[i + 1]
            if d == '(':
                if text[i + 2:i + 3] == '(':
                    stack.append('arith')
                    i += 3
                else:
                    stack.append('sub')
                    i += 2
                continue
            if d == '{':
                stack.append('brace')
                i += 2
                continue
            if d == '[':
                stack.append('arithb')
                i += 2
                continue
            if d == "'" and k != 'dq':                               # ANSI-C quoting: backslash escapes inside
                j = i + 2
                while j < len(text) and text[j] != "'":
                    j += 2 if text[j] == '\\' else 1
                if j >= n:
                    return False
                i = j + 1
                continue
        i += 1
    return stack[-1] in _CMD_CTX


def _opener_is_real(work, pos):
    """Is the `<<WORD` at offset `pos` of `work` (the command with the bodies of earlier heredocs blanked) a heredoc to bash?
    Inverted proof (card f4649c5d, Sam 4152 / 1762): only an opener that is PROVABLY one counts; anything the lexer cannot tell from text
    is NOT an opener, and the lines after it are commands that go through the gate like any other (stricter, never cut out). It is one
    only in a COMMAND context (see _in_command_context: not in a quote, `${ }`, `$(( ))`, `$[ ]`, a comment, behind a backslash), not as
    a here-string `<<<`, not as a shift inside `(( ))`. An opener inside `$( )` or a backtick pair that sits inside double quotes
    (`-m "$(cat <<'EOF'`) IS in a command context and stays real: that is the legitimate commit-message form."""
    lo = work.rfind('\n', 0, pos) + 1
    pre = work[lo:pos]
    if not pre.endswith('<') and not pre.count('((') > pre.count('))') and _in_command_context(work, pos):
        return True
    # a second opinion (card 798c3c24 round 2): the shell reader places the operator at command level where the walk above gave up (Zola's
    # `python3 -c "...print(('[index'..."; ...; python3 - <<'EOF'`: a multi-line double-quoted program in front, whose `((` the line-prefix
    # count above takes for an arithmetic command). The `((` guard is kept, but it counts only the parentheses that are not quoted.
    st = _quote_map(work)
    pu = ''.join(work[k] for k in range(lo, pos) if st[k] == 0)
    return pos in _heredoc_ops(work) and not pu.endswith('<') and pu.count('((') <= pu.count('))')


@functools.lru_cache(maxsize=64)
def _heredoc_ops(work):
    try:
        ops = []
        _shell_scan(work, (), None, False, ops)
        return frozenset(ops)
    except _ScanUnsure:
        return frozenset()


def _heredoc_end_line(lines, k, delim, dash, quoted):
    """Index of the physical line where the TERMINATOR of a heredoc starts, scanning from line k; len(lines) when there is none. The way bash reads it
    (card 798c3c24 round 3, Sam 1885): the line must be EXACTLY the delimiter (with `<<-` leading TABS are dropped, nothing else: not a space, not a
    trailing space, not a carriage return), and with an UNQUOTED delimiter a backslash-newline in the body is removed first, so `foo\\<NL>E` is the line
    `fooE` and `E\\<NL>` followed by a blank line IS the terminator. The old test (`line.strip() == delim`) ended the body early at `E ` or `<TAB>E`,
    and what followed was lexed as commands while bash still read data (or the other way round)."""
    while k < len(lines):
        start, logical = k, lines[k]
        while not quoted and k + 1 < len(lines) and (len(logical) - len(logical.rstrip('\\'))) % 2 == 1:
            logical = logical[:-1] + lines[k + 1]
            k += 1
        if (logical.lstrip('\t') if dash else logical) == delim:
            return start
        k += 1
    return len(lines)


_HD_WORD_BOUND = ' \t\n;&|<>()'


def _hd_word(text, i):
    """The heredoc operator at text[i:i+2] read from the TEXT (not from the gate's regex): (delimiter, dash, quoted), or None when the word is anything
    but a plain identifier, bare or in one pair of quotes, followed by a word boundary (`<<\\E`, `<<"E"x`, `<<$'E'`, `<<E)`: not modelled)."""
    n = len(text)
    j = i + 2
    dash = j < n and text[j] == '-'
    j += dash
    while j < n and text[j] in ' \t':
        j += 1
    q = text[j] if j < n and text[j] in '\'"' else ''
    j += bool(q)
    mt = re.compile(r'[A-Za-z_][A-Za-z0-9_]*').match(text, j)
    if not mt:
        return None
    j = mt.end()
    if q:
        if j >= n or text[j] != q:
            return None
        j += 1
    if j < n and text[j] not in _HD_WORD_BOUND:
        return None
    return mt.group(0), dash, bool(q)


def _heredocs(cmd):
    """[(i, j, m, a, b)] for every real heredoc: opener line i and its match m, terminator line j (len(lines) when missing), body
    range (a, b). The quote map is recomputed with each body blanked, so an apostrophe in a data body does not move the quote state of
    what follows."""
    lines = cmd.split('\n')
    offs, pos = [], 0
    for ln in lines:
        offs.append(pos)
        pos += len(ln) + 1
    work = cmd
    out, i = [], 0
    while i < len(lines):
        m = None
        for cand in _HEREDOC_OPEN.finditer(lines[i]):
            if cand.end() < len(lines[i]) and lines[i][cand.end()] not in ' \t;&|<>()':
                continue    # `<<E\x`, `<<"E"x`, `<<'E'x`: the delimiter word goes on past what the pattern read (the delimiter is `Ex`); not read
            if _opener_is_real(work, offs[i] + cand.start()):
                m = cand
                break
        if m:
            delim = m.group(2)
            j = _heredoc_end_line(lines, i + 1, delim, m.group(0).startswith('<<-'), bool(m.group(1)))
            if j > i:
                a = offs[i] + len(lines[i]) + 1
                b = offs[j] if j < len(lines) else len(cmd)
                out.append((i, j, m, a, b))
                work = _blank_ranges(work, [(a, b)])
            i = j
        i += 1
    return out


def _heredoc_body_ranges(cmd):
    """(adat-torzsek, ertelmezo-torzsek) karaktertartomanyai.

    A kulonbseg az, hogy a nyito sor parancsa VEGREHAJTJA-e a torzset:
      cat > fajl <<EOF   -> adat      (fajlba megy, semmi nem futtatja)
      python3 - <<PY     -> ertelmezo (a python lefuttatja)
    Csak VALODI nyitas szamit (lasd _opener_is_real): idezetben, kommentben, here-stringben allo `<<WORD` utani sorok parancsok.
    """
    lines = cmd.split('\n')
    data, code = [], []
    for i, j, m, a, b in _heredocs(cmd):
        runs = (_heredoc_opener_runs_body(lines[i][:m.start()]) or _heredoc_piped_to_program(lines, i, j, m)
                or _heredoc_fd_read(lines, i, j, m))
        (code if runs else data).append((a, b))
    return data, code


def _heredoc_fd_read(lines, i, j, m):
    """True when the heredoc is bound to a NUMBERED descriptor (`3<<EOF`) that a shell or an interpreter reads as its program (card 6a6191f4
    round 2): `bash /dev/fd/3 3<<EOF`, `exec 3<<EOF` ... `sh <&3`, `. /dev/fd/4`. A reader that is not an interpreter (`cat <&3`) leaves the
    body data. The reader is looked for on the opener line and on every line after the terminator."""
    fd = re.search(r'(?:^|[\s;&|({])(\d+)$', lines[i][:m.start()])
    if not fd or fd.group(1) == '0':
        return False
    num = fd.group(1)
    pat = re.compile(r'[<>]&%s(?!\d)|/dev/fd/%s(?!\d)|/proc/self/fd/%s(?!\d)' % (num, num, num))
    scope = lines[i] + '\n' + '\n'.join(lines[j + 1:])
    for seg in re.split(r'\|\||&&|[;|\n]|(?<![<>])&(?![<>])', scope):
        if pat.search(seg) and any(_interp_family(os.path.basename(t.strip('\'"'))) is not None or t in ('.', 'source') for t in seg.split()):
            return True
    return False


def _heredoc_piped_to_program(lines, i, j, m):
    """True when the heredoc body is handed on, through a pipe, to a shell or an interpreter that takes its PROGRAM from stdin
    (card 6a6191f4, Sam 4218): `cat <<EOF | sh`, `cat <<'EOF' | bash -s`, `cat <<EOF | tr a b | sh`, `{ cat <<EOF; } | sh`, and the pipe
    that ends the opener line with the reader on the line after the terminator. The opener command (`cat`) only copies the body, so
    _heredoc_opener_runs_body calls it data, but a LATER stage of the same pipeline runs it, exactly like `echo 'rm ...' | sh`, which the gate
    denied only while the shell word was bare (round 2 of this card closes the redirected, quoted and escaped forms). Inverted direction of the f4649c5d reading: any later stage that is a stdin-program site (`_stdin_program_sites`: no
    named program file, no `-c` code) makes the body a program, whatever filters stand in between. A stage that names a program FILE
    (`sh x.sh`) or carries its code in `-c` reads the body as data, and stays data."""
    tail = lines[i][m.end():]
    state = _quote_map(tail)
    bars = [k for k in range(len(tail)) if tail[k] == '|' and not state[k]
            and not tail.startswith('||', k) and not (k and tail[k - 1] == '|')]
    stages = []
    if bars:
        edges = bars + [len(tail)]
        stages = [tail[edges[n] + 1:edges[n + 1]] for n in range(len(bars))]
    ends_with_pipe = bool(bars) and not tail[bars[-1] + 1:].strip()
    k = j + 1
    if not bars:
        # `( cat <<EOF` / body / `EOF` / `) | sh` and the same with braces: the group closes on a later line and the pipe follows its closer
        g = k
        while g < len(lines) and not lines[g].strip():
            g += 1
        if g < len(lines) and lines[g].lstrip()[:1] in (')', '}'):
            rest = lines[g].lstrip()[1:]
            rs = _quote_map(rest)
            rbars = [x for x in range(len(rest)) if rest[x] == '|' and not rs[x]
                     and not rest.startswith('||', x) and not (x and rest[x - 1] == '|')]
            if rbars:
                redges = rbars + [len(rest)]
                stages += [rest[redges[q] + 1:redges[q + 1]] for q in range(len(rbars))]
                ends_with_pipe = not rest[rbars[-1] + 1:].strip()
                k = g + 1
    while ends_with_pipe and k < len(lines):           # `cat <<EOF |` + newline: the next command after the terminator is the reader
        stage = lines[k]
        stages.append(stage)
        ends_with_pipe = stage.rstrip().endswith('|') and not stage.rstrip().endswith('||')
        k += 1
    return any(_stdin_program_sites(st) for st in stages if st.strip())


class _ScanUnsure(Exception):
    """A shell construct the proof reader does not model (card 798c3c24). Nothing is claimed about the text then."""


_SCAN_BOUNDARY = ' \t\n;&|()<>'     # a `#` right after one of these (or at the very start) begins a comment


def _shell_scan(text, skips=(), qs=None, strict=False, hdops=None, ansis=None):
    """Read `text` the way bash splits it into words, for the subset of the grammar modelled below, and PROVE what it can (card 798c3c24).

    Returns (comments, conts, top): the (start, end) ranges of real comments (a `#` that begins a word, outside every quote; it runs to
    the newline, a backslash-newline inside it does NOT continue it), the offsets of the backslashes of real line continuations (a
    backslash-newline bash REMOVES: outside single quotes and comments, and not itself escaped), and the offsets the shell reads as COMMAND
    text (outside every quote, comment and heredoc body; inside `$(...)` / backticks too, unless a double quote encloses them).
    `skips` are the (start, end) ranges the shell reads as heredoc bodies: not lexed. `strict` (only with the complete list of heredoc bodies of
    the text, data and interpreter ones) makes every `<<` operator whose body is not in that list a `_ScanUnsure`. `hdops`, a list, receives the
    offset of every `<<` heredoc operator met at command level (a here-string and a shift inside `$(( ))` are not among them). `qs`, a list of zeros as long as `text`, is filled
    with the quote map: 1 inside single quotes and `$'..'`, 2 inside double quotes (the substitutions in them included), 0 elsewhere
    (the quote characters themselves too). `ansis`, a list, receives (dollar, start, end) of every `$'..'` word part met at command level:
    the offset of the `$`, the first character after the opening quote, the offset of the closing quote.

    The old reader (_quote_map) is a two-state toggle. It knows neither comments nor continuations nor `$'..'` nor `$(..)`, so a quote
    character in a comment, an escaped backslash before a newline, or a `$` split by a continuation shifted its state and the NEXT LINE
    was read as quoted data (the live hole of 798c3c24). This reader is the independent second opinion: it raises _ScanUnsure the moment
    it meets anything it does not model (a quote or backslash inside `${..}` / backticks / `$((..))`, a `case` inside `$(..)`, an unclosed
    quote), and the caller treats that as a deny. It is not a full bash parser, and it does not claim to be."""
    n = len(text)
    comments, conts, top = [], set(), set()
    skip_at = {a: b for a, b in skips if b > a}
    body_starts = {a for a, b in skips}          # (an EMPTY body, the terminator on the very next line, is a heredoc the gate found too)
    armed, ctx = {}, [0]
    body_end = {a: b for a, b in skips}
    seen_ops = set()

    def unsure(why):
        raise _ScanUnsure(why)

    def nxt(i):
        """First index at or after i that does not start a backslash-newline pair (the pairs are recorded)."""
        while text.startswith('\\\n', i):
            conts.add(i)
            i += 2
        return i

    def fill(a, b, v):
        if qs is not None:
            for k in range(a, min(b, n)):
                qs[k] = v

    def ansi(i, mk):
        # i is just after `$'`; a backslash escapes the next character, the first other `'` closes
        start = i
        while i < n:
            if text[i] == '\\':
                i += 2
                continue
            if text[i] == "'":
                if mk:
                    top.add(i)
                fill(start, i, 1)
                return i + 1
            i += 1
        unsure("unclosed $'...' quote")

    def dq(i, mk):
        # i is just after the opening double quote; command substitutions inside are command text for bash but never `top` here
        start = i
        while i < n:
            ch = text[i]
            if ch == '\\':
                if text.startswith('\\\n', i):
                    conts.add(i)
                    i += 2
                else:
                    i += 2 if (i + 1 < n and text[i + 1] in '$`"\\') else 1
                continue
            if ch == '"':
                if mk:
                    top.add(i)
                fill(start, i, 2)
                return i + 1
            if ch == '`':
                i = bt(i + 1, False)
                continue
            if ch == '$':
                j = nxt(i + 1)
                nx = text[j] if j < n else ''
                if nx == '(':
                    i = sub(j + 1, False)
                    continue
                if nx == '{':
                    i = brace(j + 1, False)
                    continue
            i += 1
        unsure('unclosed double quote')

    def brace(i, mk):
        # i is just after `${`; the content is not lexed: anything that could hide a closing brace is not claimed
        depth = 1
        while i < n:
            ch = text[i]
            if ch in '\'"`':
                unsure('a quote or backtick inside ${...}')
            if ch == '\\':
                if mk:
                    top.update((i, i + 1))
                i += 2
                continue
            if ch == '$' and text.startswith('$(', i):
                if mk:
                    top.update((i, i + 1))
                i = sub(i + 2, mk)
                continue
            if mk:
                top.add(i)
            if ch == '{':
                depth += 1
            elif ch == '}':
                depth -= 1
                if depth == 0:
                    return i + 1
            i += 1
        unsure('unclosed ${')

    def arith(i, mk):
        # i is just after `$((`; arithmetic only when the construct closes with an adjacent `))`, else it could be a subshell
        depth = 2
        while i < n:
            ch = text[i]
            if ch in '\'"`\\':
                unsure('a quote or backslash inside $((...))')
            if ch == '$' and text.startswith('$(', i):
                if mk:
                    top.update((i, i + 1))
                i = sub(i + 2, mk)
                continue
            if mk:
                top.add(i)
            if ch == '(':
                depth += 1
            elif ch == ')':
                depth -= 1
                if depth == 0:
                    if text[i - 1] != ')':
                        unsure('$((...) that does not end in ))')
                    return i + 1
            i += 1
        unsure('unclosed $((')

    def bt(i, mk):
        """A backtick substitution; i is just after the opening backtick. Bash ends it at the first unescaped backtick, quotes or no quotes,
        and parses what stands between as a program of its own (card 798c3c24, round 2: `echo `'`; <cmd> # '` hid the command behind an
        apostrophe pair that the inner walk paired ACROSS the closing backtick). The inner walk must therefore end exactly there."""
        e = text.find('`', i)
        if e < 0:
            unsure('unclosed backtick')
        r = walk(i, '`', mk)
        if r != e + 1:
            unsure('a quote inside backticks reaches past the closing backtick')
        return r

    def sub(i, mk):
        # i is just after `$(`
        if i < n and text[i] == '(':
            if mk:
                top.add(i)
            return arith(i + 1, mk)
        return walk(i, ')', mk)

    def walk(i, close, mk):
        """Lex command text from i. close: None (the top level), ')' (inside `$(`) or '`' (inside backticks). Returns the index after the closer."""
        prev_b, depth = True, 0
        ctx[0] += 1
        me = ctx[0]
        while i < n:
            if i in skip_at:
                # a heredoc body is skipped only when its opener was lexed in THIS very context: an opener inside backticks that were
                # closed on its own line reads its body from the backtick text, so the lines after it are commands again
                if armed.get(i) != me:
                    unsure('a heredoc body that does not belong to an opener of this context')
                i, prev_b = skip_at[i], True
                continue
            ch = text[i]
            if ch == '\\':
                if close == '`' and (i + 1 >= n or text[i + 1] in '\\$`\n'):
                    unsure('a backslash that escapes inside backticks')
                if text.startswith('\\\n', i):
                    conts.add(i)
                    i += 2                                  # the pair is removed: the word state before it carries on
                    continue
                if mk:
                    top.update((i, i + 1))
                i, prev_b = i + 2, False
                continue
            if ch == "'":
                j = text.find("'", i + 1)
                if j < 0:
                    unsure('unclosed single quote')
                if mk:
                    top.update((i, j))
                fill(i + 1, j, 1)
                i, prev_b = j + 1, False
                continue
            if ch == '"':
                if mk:
                    top.add(i)
                i, prev_b = dq(i + 1, mk), False
                continue
            if ch == '`':
                if close == '`':
                    if mk:
                        top.add(i)
                    return i + 1
                if mk:
                    top.add(i)
                i, prev_b = bt(i + 1, mk), False
                continue
            if ch == '$':
                j = nxt(i + 1)
                nx = text[j] if j < n else ''
                if nx == "'":
                    if mk:
                        top.update((i, j))
                    e = ansi(j + 1, mk)
                    if ansis is not None and mk:
                        ansis.append((i, j + 1, e - 1))
                    i, prev_b = e, False
                elif nx == '"':
                    if mk:
                        top.update((i, j))
                    i, prev_b = dq(j + 1, mk), False
                elif nx == '$':
                    if mk:
                        top.update((i, j))
                    i, prev_b = j + 1, False                  # `$$`, the PID: the next quote is a plain one
                elif nx == '(':
                    if mk:
                        top.update((i, j))
                    i, prev_b = sub(j + 1, mk), False
                elif nx == '{':
                    if mk:
                        top.update((i, j))
                    i, prev_b = brace(j + 1, mk), False
                else:
                    if mk:
                        top.add(i)
                    i, prev_b = i + 1, False
                continue
            if ch == '<' and text.startswith('<<<', i):
                if mk:
                    top.update((i, i + 1, i + 2))
                i, prev_b = i + 3, True
                continue
            if ch == '<' and text.startswith('<<', i):
                if hdops is not None:
                    hdops.append(i)
                e = text.find('\n', i)
                if strict:
                    # Second reader of the BODY (card 798c3c24 round 3): one operator per line (the bodies of two operators follow each other, the gate
                    # reads one), the delimiter word read from the text, and the end of the body recomputed the way bash finds it; the gate's range
                    # must be the same one.
                    if e in seen_ops:
                        unsure('two heredoc operators on one line')
                    seen_ops.add(e)
                    hw = _hd_word(text, i)
                    if hw is None:
                        unsure('a heredoc delimiter word that is not a plain identifier')
                    if e >= 0 and e + 1 in body_starts:
                        rest = text[e + 1:].split('\n')
                        k = _heredoc_end_line(rest, 0, hw[0], hw[1], hw[2])
                        mine = e + 1 + sum(len(x) + 1 for x in rest[:k]) if k < len(rest) else n
                        if mine != body_end.get(e + 1):
                            unsure('the end of a heredoc body that the gate and the shell reader place differently')
                if e >= 0 and e + 1 in body_starts:
                    armed[e + 1] = me
                elif strict:
                    # `<<\E`, `<<-\E`, `<<"E"x`, `<<$'E'` ...: the shell reads a heredoc here and the gate found no body for it, so the lines
                    # after it would be lexed as commands while bash takes them as data (or the other way round). Silent only on proof.
                    unsure('a heredoc operator whose body the gate did not find')
            if ch == '#' and prev_b:
                if close == '`':
                    unsure('a comment inside backticks')
                j = text.find('\n', i)
                j = n if j < 0 else j
                comments.append((i, j))
                i = j
                continue
            if ch == '(':
                depth += 1
            elif ch == ')':
                if close == ')' and depth == 0:
                    if mk:
                        top.add(i)
                    return i + 1
                depth = max(0, depth - 1)
            elif prev_b and close == ')' and text.startswith('case', i) and (i + 4 >= n or text[i + 4] in ' \t\n'):
                unsure('a case statement inside $(...)')
            if mk:
                top.add(i)
            prev_b = ch in _SCAN_BOUNDARY
            i += 1
        if close is not None:
            unsure('unclosed $(' if close == ')' else 'unclosed backtick')
        return n

    walk(0, None, True)
    return comments, conts, {i for i in top if 0 <= i < n}


def _normalize_continuations(cmd):
    """The command with every REAL backslash-newline removed, as bash does before it reads a word (card 798c3c24). The old gate replaced
    every `\\<newline>` pair by two spaces, which is wrong three ways: `r\\<NL>m -rf x` runs rm but read `r  m`; `echo \\\\<NL>rm -rf x`
    (an escaped backslash, then a real newline) was joined into one line; and a pair inside a comment or single quotes is not a
    continuation at all. Blocks when the text cannot be read with certainty."""
    if '\\\n' not in cmd:
        return cmd
    data, code = _heredoc_body_ranges(cmd)
    try:
        _comments, conts, _top = _shell_scan(cmd, data + code, None, True)
    except _ScanUnsure as exc:
        _scan_block(exc)
    if not conts:
        return cmd
    drop = set()
    for k in conts:
        drop.update((k, k + 1))
    out = ''.join(c for i, c in enumerate(cmd) if i not in drop)
    # a second reading of the result: nothing may be left that the first reading would have removed
    data2, code2 = _heredoc_body_ranges(out)
    try:
        _c2, conts2, _t2 = _shell_scan(out, data2 + code2, None, True)
    except _ScanUnsure as exc:
        _scan_block(exc)
    if conts2:
        _scan_block('a line continuation that is still there after it was removed')
    return out


def _scan_block(why):
    block('A parancs szerkezetet (idezojelek, kommentek, sortoresek) a kapu nem tudja biztosan ugyanugy olvasni, mint a shell (%s): ha egy '
          'idezojel, komment vagy sortores masként olvasodik, a kovetkezo sor parancsa idezett adatnak latszana, es atmenne. Bizonyitas '
          'nelkul nem engedem at. Nem az ugynok dontese.' % why)


def _comment_ranges(text, code=()):
    """The comments of `text` (card 798c3c24): every `#` that begins a word outside every quote, to the end of its line, which the shell
    never runs; plus, INSIDE the interpreter heredoc bodies `code` (not shell text, never lexed), every line that starts with a hash: the
    comment of that language. The old rule blanked every line that merely STARTS with a hash, quoted or not, and a blanked line inside a
    multi-line quote took its quote characters with it (a `# it's` line in a single-quoted string moved the quote state of everything
    after it); the comment lines of the text a `-c` string holds are blanked on their own, after the payload is cut out:
    _strip_comment_lines. A text the reader cannot prove falls back to the whole-line rule; check_bash has refused such a command by then."""
    full, pos = [], 0
    for ln in text.split('\n'):
        if ln.lstrip().startswith('#'):
            full.append((pos, pos + len(ln)))
        pos += len(ln) + 1
    try:
        comments, _conts, _top = _shell_scan(text, code)
    except _ScanUnsure:
        return full
    return comments + [(a, b) for a, b in full if any(ca <= a < cb for ca, cb in code)]


def _strip_comment_lines(payload):
    """A payload (the text an interpreter runs) with every line that starts with a hash blanked: a comment of Python, Ruby, the shell."""
    return '\n'.join(' ' * len(ln) if ln.lstrip().startswith('#') else ln for ln in payload.split('\n'))


def _prose_quote_ranges(text, keep_ranges, code_ranges=()):
    """Szokozt tartalmazo idezojeles szovegek tartomanyai -- ezek proza vagy adat
    (uzenet-torzs, JSON-payload, regex-minta, teszt-eset), nem utvonal.

    A szokoz NELKULI idezett szoveg utvonal lehet, ezert marad. A `keep_ranges` az
    ertelmezonek atadott szkript-argumentum: annak a tartalma FUT, nem proza.
    """
    state = _quote_map(text)
    out = []
    i = 0
    while i < len(text):
        if state[i]:
            j = i
            while j < len(text) and state[j] == state[i]:
                j += 1
            span = text[i:j]
            inside_keep = any(a <= i < b for a, b in keep_ranges)
            # Parancs-behelyettesites idezojelen belul VEGREHAJTODIK -- a shell ott
            # visszalep parancs-kontextusba. Ezt sosem tekintjuk prozanak, kulonben
            # a mereskor 6 VALODI blokk veszett volna el (PORT="$(sed ... )" alak).
            # Az ertelmezo-heredoc TORZSEBEN a backtick es a $( nem parancs-
            # behelyettesites, hanem sima karakter egy Python/Node szovegben. A
            # kivetel ezert csak shell-kontextusban ervenyes.
            in_code_body = any(a <= i < b for a, b in code_ranges)
            runs_code = (not in_code_body) and ('$(' in span or chr(96) in span)
            if not inside_keep and not runs_code and re.search(r'\s', span):
                out.append((i, j))
            i = j
        else:
            i += 1
    return out


# INTERPFLAG1004: az ertelmezo opcioi a -c/-e ELOTT. A regi regex a kapcsolot csak akkor latta,
# ha KOZVETLENUL az ertelmezo neve utan allt, ezert `python3 -B -c "..."`, `bash -lc "..."`,
# `perl -w -e "..."`, `node --no-warnings -e "..."` payloadja prozanak latszott, es a
# prozaszuro kifeherítette: a benne allo torles atment (merve 2026-10-04, a 4a8c6fc-alapon is).
# Opciokat ertekvaroval egyutt kell atlepni, kulonben `python3 -W ignore -c` vagy
# `node -r ./a.js -e` megint kicsuszik. Ertelmezonkent mas az alak, ezert tablazat:
#   code  - az a betu a csomagolt (-lc, -we, -Bc) kapcsolo-csoportban, amely utan a KOD jon
#   val   - az a betu, amelynek erteke a kovetkezo szo (vagy ha a csoportban folytatodik, az maga)
#   att   - az a betu, amely a csoport maradekat ERTEKkent eszi meg (perl -MFile::Path, -i.bak)
#   dig   - az a betu, amely utan csak szamjegy jon (perl -l, -0777)
_INTERP_SPECS = {
    'python': dict(code='c', val='WX', att='', dig=''),
    'perl': dict(code='eE', val='I', att='MmFCdDxiV', dig='l0'),
    'ruby': dict(code='e', val='rICE', att='xKTFiWS', dig='0'),
    'bash': dict(code='c', val='oO', att='', dig=''),
    # php -r "<kod>": a -r a kod, -d key=val / -c path / -z ext erteket var.
    # v2 (HEX 2512): a -B/-R/-E is KOD (begin / per-line / end), a -F fajl.
    'php': dict(code='rBRE', val='dczF', att='', dig=''),
    # A node nem csomagol: minden opcio onallo szo.
    'node': dict(code='', val='', att='', dig='', exact=True,
                 code_words=('-e', '-p', '-pe', '-ep', '--eval', '--print'),
                 val_words=('-r', '-C', '--require', '--import', '--loader', '--experimental-loader',
                            '--input-type', '--conditions', '--title')),
}
# bun: ugyanaz az alak, mint a node-e (bun -e / --eval / -p / --print); a `bun run x` nem opcio, tehat nem kod.
_INTERP_SPECS['bun'] = dict(code='', val='', att='', dig='', exact=True,
                            code_words=('-e', '-p', '--eval', '--print'),
                            val_words=('-r', '--preload', '--require', '--import', '--cwd', '--config', '-c',
                                       '--env-file', '--define', '-d', '--tsconfig-override', '--port',
                                       '--install', '--origin'))
_INTERP_SPECS['sh'] = _INTERP_SPECS['zsh'] = _INTERP_SPECS['bash']
_INTERP_LONG_CODE = ('--command', '--eval', '--print')
_INTERP_LONG_VAL = ('--check-hash-based-pycs', '--rcfile', '--init-file')
_INTERP_WORD_END = ' \t\n;&|<>()'


def _interp_word_end(text, state, k):
    """A (idezojel-tudatos) szo vege: az elso idezojelen KIVULI elvalaszto."""
    n = len(text)
    while k < n and (state[k] or text[k] not in _INTERP_WORD_END):
        k += 1
    return k


_FD_REDIRECT = re.compile(r'(?:\d+|\{[A-Za-z_]\w*\})?(&>>|&>|>>|>\||>&|>|<&|<<<|<<-?|<>|<)')


def _interp_opts_scan(text, state, name, k):
    """Az ertelmezo-opciok atlepese az elso nem-opcio szoig vagy a -c/-e-ig. (fajta, pozicio):
      ('code', p)  a kod-kapcsolo UTANI pozicio (-c, -e, -r, --eval ...)
      ('arg', p)   az elso nem-opcio szo kezdete (program-fajl, `-`, idezett szo, `--` utani szo, `+`)
      ('end', p)   a parancs vege vagy atiranyitas (`<`, `|`, `;`...): nincs megnevezve program
    Ismeretlen hosszu opciot ertek nelkulinek veszunk: ha tevedunk, a kovetkezo szo programfajlnak
    latszik, vagyis a regi (szukebb) viselkedes marad."""
    spec = _INTERP_SPECS.get(name)
    if spec is None:
        return ('arg', k)
    n = len(text)
    dd = False                                       # after `--` every word is an argument, redirections still are not
    for _ in range(64):
        while k < n and text[k] in ' \t':
            k += 1
        if k >= n:
            return ('end', k)
        rd = None if state[k] else _FD_REDIRECT.match(text, k)
        if rd:
            # A redirection is not the program (card 6a6191f4 round 2: `| sh 2>&1`, `| bash 0<&0` read `2>&1` as a program FILE). An
            # output redirection (`>`, `2>&1`, `&>f`) is skipped with its target word; one that re-points stdin (`<`, `0<&0`, `<<`) ends the
            # scan: the program then comes from somewhere the gate does not read, which is a site, like a bare `<`.
            if '<' in rd.group(1):
                return ('end', k)
            k2 = _skip_ws(text, rd.end())
            e2 = _interp_word_end(text, state, k2)
            if e2 <= k2:
                return ('end', k)
            k = e2
            continue
        if not state[k] and text[k] in ';&|\n<>)':
            return ('end', k)
        if dd or text[k] not in '-+' or state[k]:
            return ('arg', k)
        e = _interp_word_end(text, state, k)
        tok = text[k:e]
        if tok == '--':
            dd = True
            k = e
            continue
        if tok in ('-', '+'):
            return ('arg', k)
        name_part, eq, _v = tok.partition('=')
        if tok.startswith('--'):
            if name_part in _INTERP_LONG_CODE:
                return ('code', k + len(name_part) + (1 if eq else 0))
            k = _interp_word_end(text, state, _skip_ws(text, e)) if name_part in _INTERP_LONG_VAL \
                or (spec.get('exact') and name_part in spec['val_words'] and not eq) else e
            continue
        if spec.get('exact'):
            if tok in spec['code_words']:
                return ('code', e)
            k = _interp_word_end(text, state, _skip_ws(text, e)) if tok in spec['val_words'] else e
            continue
        i, take_next = 1, False
        while i < len(tok):
            ch = tok[i]
            if ch in spec['code']:
                return ('code', k + i + 1)
            if ch in spec['val']:
                take_next = i + 1 == len(tok)
                break
            if ch in spec['att']:
                break
            if ch in spec['dig']:
                i += 1
                while i < len(tok) and tok[i].isdigit():
                    i += 1
                continue
            i += 1
        k = _interp_word_end(text, state, _skip_ws(text, e)) if take_next else e
    return ('arg', k)


def _interp_code_flag_end(text, state, name, k):
    """A -c/-e kapcsolo UTANI pozicio, vagy None (program-fajl, `-`, idezett szo, `--`, nincs kod)."""
    kind, pos = _interp_opts_scan(text, state, name, k)
    return pos if kind == 'code' else None


def _skip_ws(text, k):
    while k < len(text) and text[k] in ' \t':
        k += 1
    return k


# Ezeknel TOBB kod-kapcsolo is lehet egy hivasban (perl -e A -e B), es MINDEGYIK fut. A python -c / bash -c
# masodik pelldanya mar argumentum, nem kod, ezeket nem vesszuk ide.
_MULTI_CODE_FAMILIES = ('perl', 'ruby', 'php', 'node', 'bun')
_INTERP_WORD_RE = re.compile(r'(?<![\w-])((?:python|bash|sh|zsh|node|bun|perl|ruby|php)[\d.]*)(?=\s)')

# awk-szeru nyelvek: a program egy idezett argumentum, benne system() / "parancs" | getline / print | "parancs"
# FUTTAT. A -f fajl nem lathato, azt nem probaljuk.
_AWK_RE = re.compile(r'(?<![\w-])(?:[gmn]?awk)(?=\s)')
_AWK_VAL_OPTS = ('-F', '-v', '-W', '-i', '-l', '-E', '--field-separator', '--assign', '--include', '--load')
_AWK_CODE_OPTS = ('-e', '--source')
# deno eval [opciok] "<kod>": az opciok kozul ezek erteket varnak a kovetkezo szoban.
_DENO_VAL_OPTS = ('--ext', '--config', '-c', '--import-map', '--cert', '--location', '--seed', '--v8-flags',
                  '--reload', '-r', '--lock', '--node-modules-dir', '--unstable-features')


def _quoted_range_at(text, state, k):
    """Ha a k pozicion idezojel nyilik, a tartalom (a, b) tartomanya es a zaro jel pozicioja, kulonben None."""
    if k < len(text) and text[k] in ('"', "'"):
        a = j = k + 1
        while j < len(text) and state[j]:
            j += 1
        return a, j
    return None


def _awk_program_ranges(text, state):
    out = []
    for m in _AWK_RE.finditer(text):
        if state[m.start()]:
            continue
        k = m.end()
        for _ in range(48):
            k = _skip_ws(text, k)
            if k >= len(text) or state[k]:
                break
            if text[k] != '-':
                break
            e = _interp_word_end(text, state, k)
            tok = text[k:e]
            if tok == '--':
                k = e
                break
            if tok in _AWK_CODE_OPTS:
                r = _quoted_range_at(text, state, _skip_ws(text, e))
                if r:
                    out.append(r)
                    k = r[1] + 1
                else:
                    k = e
                continue
            if tok == '-f' or tok.startswith('--file') or tok.startswith('-f'):
                k = -1                                          # a program fajlbol jon: nem latszik
                break
            k = _interp_word_end(text, state, _skip_ws(text, e)) if tok in _AWK_VAL_OPTS else e
        if k < 0:
            continue
        k = _skip_ws(text, k)
        r = _quoted_range_at(text, state, k)
        if r:
            out.append(r)
    return out


def _deno_eval_ranges(text, state):
    out = []
    for m in re.finditer(r'(?<![\w-])deno\s+eval(?=\s)', text):
        if state[m.start()]:
            continue
        k = m.end()
        for _ in range(32):
            k = _skip_ws(text, k)
            if k >= len(text) or state[k] or text[k] != '-':
                break
            e = _interp_word_end(text, state, k)
            tok = text[k:e]
            k = _interp_word_end(text, state, _skip_ws(text, e)) if tok in _DENO_VAL_OPTS else e
        r = _quoted_range_at(text, state, k)
        if r:
            out.append(r)
    return out


# 7fd3134e (Igor 4083, measured): `dash -c '<code>'`, `ksh -c`, `"bash" -c`, `'bash' -c`, `busybox sh -c`, `su -c`, `script -qc` ran
# anything, because the table above only knows interpreters BY NAME. The inverted rule: the program word after a `-c` style flag (a
# short option cluster WITH a c anywhere in it, any length, or --command) is code whoever the command is. A name that is not in the table is not
# evidence that the string is data. `-exec` ends in c too and takes a command, not a string: it is not a flag of this kind.
# Round 1 of Sam's review (msg 4142) found that the first head read only a QUOTED string directly after the flag, and that its
# "known interpreter" exemption looked for the name anywhere in the segment. Both are replaced by proofs, not by more shapes:
#   - the exemption holds only for the COMMAND of the segment (behind env / time / sudo / ... and their options), never for a word
#     that merely appears as an argument (`env -u sh dash -c`, `su -s /bin/sh -c`);
#   - the word after the flag (past options and `--`) is either one fully quoted string (its content is
#     scanned as code), or a plain word with no quote, escape or expansion (a single word cannot be a command line: harmless), or it
#     is NOT PROVABLY either, and then the whole command is denied (`dash -c git\ reset`, `dash -c $'...'`, `dash -c 'a'"b"`).
_GENERIC_C_FLAG = re.compile(r'(?<![\w-])(?:-[A-Za-z]*c[A-Za-z]*|--command)(?![\w-])')  # a `c` ANYWHERE in the cluster: `-ce`, `-cex`
_PLAIN_C_WORD = re.compile(r'^[\w./=:@%+,~-]*$')


# Commands whose `-c` is a COUNT / FORMAT / BYTES / COOKIE-FILE option, never a program: the string after it is a pattern or a value
# (`grep -c "pat"`, `stat -c '%y'`, `cut -c "1-5"`, `curl -c jar`, `jq -c '.a | {b,c}' f`: compact output, the filter is the next word). A closed list of well-defined tools, not of dangerous shapes: any
# other command's -c string is read as code. Measured on the 3,901-command corpus: without it, 9 grep/stat lines were denied.
# The name must be the plain name or the path of the system binary: `./grep -c '<R>'` is a script of the agent's choosing.
_C_FLAG_NOT_CODE = {'grep', 'egrep', 'fgrep', 'rg', 'ag', 'stat', 'cut', 'head', 'tail', 'curl', 'sort', 'wc', 'ls', 'uniq', 'diff', 'git', 'tar', 'du', 'sqlite3', 'jq'}
_STD_BIN_DIRS = ('/usr/bin/', '/bin/', '/usr/local/bin/')
_KNOWN_INTERP_NAME = re.compile(r'^(?:python|bash|sh|zsh|node|bun|perl|ruby|php)[\d.]*$')
_KNOWN_SHELL_NAME = re.compile(r'^(?:bash|sh|zsh)[\d.]*$')  # the others (python, node, perl, ruby, php, bun) take CODE of their own language after -c
_PLAIN_CMD_NAME = re.compile(r'^(?:/[\w./+-]+|[\w.+-]+)$')
# PATH assigned anywhere in the command (`PATH=/tmp/x:$PATH python3 -c`, `export PATH=...`, `env PATH=...`, a `PATH=...;` statement): a bare tool
# name then resolves to whatever the agent put there, so no NAME is evidence of the tool it names. An ASSIGNMENT is a `PATH=` word that stands
# among the leading assignments / `export` / `env` / options of a statement; `echo PATH=1` is an argument.
_ASSIGN_LEAD = frozenset(('export', 'env', 'declare', 'typeset', 'readonly', 'local', 'command', 'time', 'nice', 'nohup', 'timeout', 'exec', 'sudo'))
_path_assigned_cache = {}


def _path_assigned(text):
    if text in _path_assigned_cache:
        return _path_assigned_cache[text]
    state = _quote_map(text)
    found, start = False, 0
    for i in range(len(text) + 1):
        if i < len(text) and not (not state[i] and text[i] in ';&|\n(){}`'):    # a statement also starts after `(`, `{`, `$(` and a backtick
            continue
        for w in _raw_words(text[start:i]):
            if re.match(r'^PATH\+?=', w):
                found = True
                break
            if re.match(r'^[A-Za-z_]\w*=', w) or w in _ASSIGN_LEAD or w.startswith('-'):
                continue
            break
        if found:
            break
        start = i + 1
    if len(_path_assigned_cache) > 64:
        _path_assigned_cache.clear()
    _path_assigned_cache[text] = found
    return found


def _anchored_tool(name, text):
    """True when `name` is ANCHORED to the system tool of that name (round 3 of Sam's review, SEVERE 1: the exemptions looked at the NAME, so
    `/tmp/x/python3 -c`, a symlink to /bin/sh, or `PATH=<dir>:$PATH python3 -c` were taken for python). Anchored: a plain name or a path in the
    system binary directories (no `..`), and no PATH assignment anywhere in the command. `./python3` is not a plain name. Anything else is not
    anchored, and the -c string is read as a shell program. NAMED LIMIT (Sam, round 4): a plain name is "the first hit on the session's PATH", NOT
    proof of the system tool; a writable PATH directory in front of /usr/bin (~/.bun/bin here) can hold a `python3` shell script. See the docs."""
    if _PLAIN_CMD_NAME.match(name) is None:
        return False
    if '/' in name and (not name.startswith(_STD_BIN_DIRS) or '..' in name):
        return False
    return not _path_assigned(text)

# Wrappers that run their trailing words as a command, and the options of each that TAKE a value (the next word is not the command).
_C_WRAPPERS = {
    'env': {'-u', '-C', '--unset', '--chdir'}, 'time': {'-f', '-o', '--format', '--output'}, 'nice': {'-n', '--adjustment'},
    'nohup': set(), 'timeout': {'-s', '-k', '--signal', '--kill-after'}, 'command': set(), 'exec': {'-a'},
    'xargs': {'-I', '-n', '-P', '-d', '-L', '-s', '-E', '-a', '-l'},
}


def _raw_words(text):
    """The words of `text` as written (quotes and escapes kept), split at unquoted blanks."""
    state = _quote_map(text)
    out, start = [], None
    for i, ch in enumerate(text):
        blank = ch in ' \t\n' and not state[i]
        if blank:
            if start is not None:
                out.append(text[start:i])
                start = None
        elif start is None:
            start = i
    if start is not None:
        out.append(text[start:])
    return out


def _c_command(words):
    """(index, name) of the command word of a segment given as raw words: env assignments and the wrappers above (with their
    options) are peeled. None where there is no command word (the segment ends in a wrapper). A word that is not a plain name (`env -S 'x'` leaves a quoted word) is returned as the command: it is not a known tool, so its -c string is read as code."""
    i = 0
    for _ in range(16):
        while i < len(words) and re.match(r'^[A-Za-z_]\w*=', words[i]):
            i += 1
        if i >= len(words):
            return None
        name = os.path.basename(words[i]) if _PLAIN_CMD_NAME.match(words[i]) else None
        if name not in _C_WRAPPERS:
            return i, words[i]
        takes = _C_WRAPPERS[name]
        i += 1
        while i < len(words) and words[i].startswith('-') and words[i] != '-':
            w = words[i]
            i += 1
            if w == '--':
                break
            if w in takes:
                i += 1
        if name == 'timeout':
            i += 1  # the duration
    return None


def _c_program_word(text, state, k):
    """Skip what may sit between a -c flag and the program word (blanks, options, `--`, the value of -o/-O; a line
    continuation or ${IFS} is not skipped: the word that starts with it is unprovable and the command is denied), and return (kind, a, b): ('quoted', a, b) the content range of one fully quoted string, ('plain', ...) a harmless single
    word, ('none', ...) nothing follows, ('unprovable', ...) anything else."""
    n = len(text)
    for _ in range(32):
        while k < n and text[k] in ' \t':
            k += 1
        if k >= n or (not state[k] and text[k] in ';&|\n<>)'):
            return 'none', k, k
        e = _interp_word_end(text, state, k)
        word = text[k:e]
        if not state[k] and word[:1] in '-+' and re.match(r'^[-+][A-Za-z-]*$', word):
            k = e
            if word in ('-o', '+o', '-O', '+O'):
                while k < n and text[k] in ' \t':
                    k += 1
                k = _interp_word_end(text, state, k)
            continue
        if word[:1] in ('"', "'"):
            r = _quoted_range_at(text, state, k)
            if r and (r[1] >= n or r[1] + 1 == e):  # unterminated: bash rejects it, the rest is scanned as the string anyway
                return 'quoted', r[0], r[1]
            return 'unprovable', k, e
        if _PLAIN_C_WORD.match(word):
            return 'plain', k, e
        return 'unprovable', k, e
    return 'unprovable', k, k


def _generic_c_ranges(text):
    """The strings after a `-c` style flag whose command is not provably a tool with a non-program -c (see _GENERIC_C_FLAG): code.
    Denies the command where the word after the flag cannot be proved to be a quoted string or a harmless plain word."""
    out = []
    state = _quote_map(text)
    for m in _GENERIC_C_FLAG.finditer(text):
        if state[m.start()]:
            continue
        a = m.start()
        while a > 0 and not (not state[a - 1] and text[a - 1] in ';&|\n(`'):
            a -= 1
        words = _raw_words(text[a:m.start()])
        cmd = _c_command(words)
        if cmd:
            idx, name = cmd
            anchored = _anchored_tool(name, text)    # the SYSTEM tool of that name, not a script or a PATH lookalike (Sam, round 3)
            base = os.path.basename(name)
            if anchored and base in _C_FLAG_NOT_CODE:
                continue
            if anchored and _KNOWN_INTERP_NAME.match(base) and not _KNOWN_SHELL_NAME.match(base):
                continue  # python -c / node -e / perl -e ...: the string is code of ANOTHER language, read by the interpreter-specific logic
            if anchored and _KNOWN_INTERP_NAME.match(base):
                # a known shell keeps its OWN flag logic when a script name stands before the flag (`bash tool.sh -c x`: the
                # script's argument); with only options in between the -c is the shell's own and the string is its program
                rest, j = words[idx + 1:], 0
                only_options = True
                while j < len(rest):
                    w = rest[j]
                    if w in ('-o', '+o', '-O', '+O'):
                        j += 2
                        continue
                    if not (w.startswith('-') or w.startswith('+')):
                        only_options = False
                        break
                    j += 1
                if not only_options:
                    continue
        kind, x, y = _c_program_word(text, state, m.end())
        if kind == 'quoted':
            out.append((x, y))
        elif kind == 'unprovable':
            block('A -c (vagy --command) kapcsolo utani szo nem bizonyithatoan sima szo vagy egyetlen idezett string (%r): az a shell-program, '
                  'es a kapu nem tudja kiolvasni. Irj egyszeru idezojelet: -c \'...\'' % text[x:y][:40])
    return out


def _script_arg_ranges(text):
    """Az ertelmezonek -c/-e utan atadott idezett szkript tartomanyai: ez FUTO KOD."""
    out = []
    state = _quote_map(text)
    for m in re.finditer(r'(?<![\w-])((?:python|bash|sh|zsh|node|bun|perl|ruby|php)[\d.]*)(?=\s)', text):
        fam = _interp_family(m.group(1))
        k = _interp_code_flag_end(text, state, fam, m.end())
        if k is None:
            # A regi, kozvetlen alak (php is ide tartozik: a tablazatban nincs). Az
            # unio sosem gyengiti a vedelmet.
            lm = re.match(r'\s+(-\w|--\w+)', text[m.end():])
            if not lm or lm.group(1) not in SCRIPT_FLAGS:
                continue
            k = m.end() + lm.end()
        for _ in range(16):
            while k < len(text) and text[k] in ' \t':
                k += 1
            r = _quoted_range_at(text, state, k)
            if not r:
                break
            out.append(r)
            # perl -e A -e B, php -r A -B B: a TOBBI kod-kapcsolo is kod (INTERPFLAG v2).
            nk = _interp_code_flag_end(text, state, fam, r[1] + 1) if fam in _MULTI_CODE_FAMILIES else None
            if nk is None:
                break
            k = nk
    out += _awk_program_ranges(text, state)
    out += _deno_eval_ranges(text, state)
    # GATEGAPS1003: `eval "<parancs>"` ugyanugy FUTO KOD, mint a `sh -c "<parancs>"`.
    for m in re.finditer(r'(?<![\w-])eval\s+(?=["\'])', text):
        k = m.end() + 1
        j = k
        while j < len(text) and state[j]:
            j += 1
        out.append((k, j))
    return out


def scannable(cmd):
    """A parancs azon resze, amely TENYLEG lefut. Lasd a modul-fejlec 1-4. pontjat."""
    data, code = _heredoc_body_ranges(cmd)
    text = _blank_ranges(cmd, data)
    text = _blank_ranges(text, _comment_ranges(text, code))
    _require_same_reading(cmd, text, data, code)
    keep = _script_arg_ranges(text)
    text = _blank_ranges(text, _prose_quote_ranges(text, keep, code))
    return text


def _require_same_reading(cmd, text, data, code):
    """Silent only on proof (card 798c3c24): `cmd` is read by the shell reader (_shell_scan) and `text` (the same command with the data
    heredocs and the comments blanked) by the two-state quote map every later step stands on. Every character the shell reads as COMMAND
    text must be unquoted for the map too; a character it calls quoted that the shell runs is how a quote in a comment, a `$'..'`, a
    backtick or a continuation turned the destructive command on the next line into 'data'. Where the two readers differ, or the shell
    reader cannot read the text at all, the command is refused. (The interpreter bodies `code` are another language: blanked for the
    map here.)"""
    try:
        _comments, conts, top = _shell_scan(cmd, data + code, None, True)
    except _ScanUnsure as exc:
        _scan_block(exc)
    if conts:
        _scan_block('a line continuation reached the quote map')
    state = _quote_map(_blank_ranges(text, code))
    for i in sorted(top):
        if state[i] and cmd[i] not in ' \t':
            _scan_block('the quote map reads offset %d as quoted, the shell as a command: %r' % (i, cmd[max(0, i - 12):i + 12]))


def segments(text):
    """Logikai szegmensek (&&, ||, ;, |, ujsor, $(, backtick) -- IDEZOJEL-TUDATOSAN.

    A regi valtozat vakon vagott, ezert egy idezett grep-minta belsejeben levo '|'
    uj szegmenst nyitott, es a minta kovetkezo szava parancsnevnek latszott.
    """
    return [seg for seg, _pos in segments_pos(text)]


def _redir_char_before(text, state, i):
    """Is text[i - 1] an unquoted, unescaped `<` or `>`, that is a redirection operator (cards 95d0cbc5 round 2 and 6b631f69)? Read from the quote map and
    the backslash parity, not from the raw character: `echo \\>& rm` has a `>` before the `&` that is an argument, `echo '>'& rm` too, `echo \\\\>& f`
    (an escaped backslash, then a real `>`) is a redirection."""
    if i < 1 or text[i - 1] not in '<>' or state[i - 1]:
        return False
    n, k = 0, i - 2
    while k >= 0 and text[k] == '\\' and not state[k]:
        n += 1
        k -= 1
    return n % 2 == 0


def _is_background_amp(text, i, state=None):
    """A lone `&` that ends a command (card 95d0cbc5): `sleep 1 & <cmd>` runs <cmd> as a command of its own and the gate read it as an
    argument of `sleep`. Not one: the `&` of `>&` and `<&` (a duplication, with a REAL operator in front: an escaped or quoted `>` is an
    argument and the `&` behind it ends the command), `&>` and `&>>` (a redirection; `&<` is NOT one in bash: it ends the command and `<` starts a
    redirection of the next one), and `&&` (a delimiter of its own; the `|&` pipe is ended by the `|` delimiter already). Everything else unquoted
    is a border: a doubtful `&` costs one more segment that is checked, never one less (inverted direction)."""
    if text[i] != '&' or text.startswith('&&', i):
        return False
    if state is None:
        state = _quote_map(text)
    if state[i]:
        return False
    if _redir_char_before(text, state, i):
        return False
    n, k = 0, i - 1
    while k >= 0 and text[k] == '\\' and not state[k]:
        n += 1
        k -= 1
    if n % 2:
        return False                       # an escaped `&` is a letter of the word (`x=a\&c rm`, card 95d0cbc5 regression)
    if text[i + 1:i + 2] == '>':
        return False
    return True


def _matching_paren(text, state, k):
    """Offset of the `)` that closes the `$(` whose body starts at k, or -1. Only unquoted parentheses count (a quoted one belongs to a string
    inside the substitution), and a backslash takes the next character with it."""
    depth = 1
    while k < len(text):
        if not state[k]:
            if text[k] == '\\':
                k += 2
                continue
            if text[k] == '(':
                depth += 1
            elif text[k] == ')':
                depth -= 1
                if depth == 0:
                    return k
        k += 1
    return -1


def _matching_brace(text, state, k):
    """Offset of the `}` that closes the function substitution `${ cmd; }` / `${|cmd;}` whose body starts at k, or -1. Unquoted braces only, a backslash
    takes the next character with it (card 46f43d1a round 3: the substitution is a command list, the characters behind its `}` are the rest of the
    word and the command comes after them)."""
    depth = 1
    while k < len(text):
        if not state[k]:
            if text[k] == '\\':
                k += 2
                continue
            if text[k] == '{':
                depth += 1
            elif text[k] == '}':
                depth -= 1
                if depth == 0:
                    return k
        k += 1
    return -1


def _legacy_arith_end(text, k):
    """Offset of the `]` that closes the legacy `$[ .. ]` whose `$[` starts at k, or -1; the brackets nest (`$[ a[1] + 2 ]`, measured with bash)."""
    depth, k = 1, k + 2
    while k < len(text):
        if text[k] == '\\':
            k += 2
            continue
        if text[k] == '[':
            depth += 1
        elif text[k] == ']':
            depth -= 1
            if depth == 0:
                return k
        k += 1
    return -1


# a function header in front of the body: `f()`, `f ()`, `function f`, `function f()` (`f() { x=$(date) rm .. }` runs rm inside the function; card 46f43d1a round 3)
_FUNC_HEAD = re.compile(r'\s*(?:function\s+[\w.:+-]+\s*(?:\(\s*\))?|[\w.:+-]+\s*\(\s*\))')


def _command_still_to_come(prefix):
    """Does the text in front of a glued `$(` hold NO command word yet, only assignments and redirections (`x=`, `FOO=a y=`, `>`, `2>`, `> `)? Then what
    stands behind the closing parenthesis is not an argument of the last command inside the substitution: it is the command itself (card 46f43d1a:
    `x=$(date) rm -rf <dir>` ran rm). A spaced `x= $(..)` and an empty prefix are not judged here (the substitution IS the command word then, the
    opaque-substitution rule has it). A function header in front does not count (`f() { x=$(date) rm .. }`, round 3); the keywords and braces are skipped by command_index."""
    toks = _bare_tokens(_FUNC_HEAD.sub('', prefix, count=1))
    if not toks or command_index(toks) is not None:
        return False
    if prefix[-1:] not in (' ', '\t'):
        return True                                            # glued: `x=$(..)`, `>$(..)`, `2>$(..)`
    m = _REDIR_WORD_RE.match(toks[-1][0])
    return bool(m) and not m.group(1)                          # a bare operator, its target is the substitution: `> $(..)`


def _glued_tail_end(text, state, a, b):
    """End offset of the word that starts at a within text[:b]: the first unquoted, unescaped blank (a quoted or escaped blank belongs to the
    word). Behind the `)` that closes a substitution in an assignment or a redirection target, the characters up to that blank are the rest of the
    VALUE (`x=$(echo a)b rm`: `b` is part of x, the command is rm; card 46f43d1a round 2)."""
    k = a
    while k < b:
        if state[k]:
            k += 1
            continue
        if text[k] == '\\':
            k += 2
            continue
        if text.startswith('${', k):
            depth, k = 1, k + 2            # a parameter expansion may hold blanks (`${Y:-b c}`) and belongs to the word whole
            while k < b and depth:
                if not state[k]:
                    if text[k] == '\\':
                        k += 1
                    elif text[k] == '{':
                        depth += 1
                    elif text[k] == '}':
                        depth -= 1
                k += 1
            continue
        if text.startswith('$[', k) or text.startswith(('<(', '>('), k):
            close = _legacy_arith_end(text, k) if text[k] == '$' else _matching_paren(text, state, k + 2)
            if 0 <= close < b:             # the legacy `$[ 1 + 2 ]` and a process substitution `<(..)` hold blanks and belong to the word whole
                k = close + 1
                continue
        if text[k] in ' \t':
            break
        k += 1
    return min(k, b)


def segments_pos(text):
    """segments(), de minden szegmenshez a KEZDO-OFFSETJE is a szovegben (DAFB69DB: kell hozza, hogy egy szegmensrol
    megmondjuk, interpreter-torzsben (python3 - <<PY) all-e)."""
    state = _quote_map(text)
    parts, start, i = [], 0, 0
    borders = set()                        # the `)` that closes a `$(` in an assignment or a redirection target: a command may follow it (card 46f43d1a)
    tails = set()                          # segment starts right behind such a `)`: the glued rest of the value comes first, then the command (round 2)
    while i < len(text):
        if state[i]:
            i += 1
            continue
        if i in borders:
            parts.append((text[start:i], start))
            i += 1
            start = i
            tails.add(start)
            continue
        if text[i] == '\\' and text[i + 1:i + 2] in ('\\', ';', '|', '&'):
            i += 2                         # an escaped separator is a letter of the word (`x=a\;c rm`), an escaped backslash does not escape the next one (card 40650fd7)
            continue
        hit = next((d for d in DELIMS if text.startswith(d, i)), None)
        ws = _glued_tail_end(text, state, start, i) if start in tails else start
        if hit == '$(' and ((start in tails and ws >= i) or _command_still_to_come(text[ws:i])):
            close = _matching_paren(text, state, i + 2)
            if close >= 0:
                borders.add(close)
        if hit is None and text.startswith('${', i) and text[i + 2:i + 3] in (' ', '\t', '\n', '|') \
                and ((start in tails and ws >= i) or _command_still_to_come(text[ws:i])):
            close = _matching_brace(text, state, i + 2)       # a function substitution is a command list: its body is cut like `$(..)`, the `}` is a border
            if close >= 0:
                borders.add(close)
                parts.append((text[start:i], start))
                i += 2
                start = i
                continue
        if hit == '|' and _redir_char_before(text, state, i):
            i += 1                         # `>|`: the noclobber redirection, not a pipe (card 6b631f69: it cut `>|f rm` in front of the target)
            continue
        if hit is None and _is_background_amp(text, i, state):
            hit = '&'
        if hit:
            parts.append((text[start:i], start))
            i += len(hit)
            start = i
            continue
        i += 1
    parts.append((text[start:], start))
    out = []
    for p, st in parts:
        if st in tails:
            cut = _glued_tail_end(text, state, st, st + len(p)) - st
            p, st = p[cut:], st + cut
        if p.strip():
            out.append((p.strip(), st + len(p) - len(p.lstrip())))
    return out


def _dq_unescape(s):
    """What bash makes of the inside of a double-quoted string: `\\\\` `\\\"` `\\$` and a backslash-backtick lose their backslash, a
    backslash-newline disappears; every other backslash stays."""
    out, i = [], 0
    while i < len(s):
        c = s[i]
        if c == '\\' and i + 1 < len(s):
            nx = s[i + 1]
            if nx == '\n':
                i += 2
                continue
            if nx in '$`"\\':
                out.append(nx)
                i += 2
                continue
        out.append(c)
        i += 1
    return ''.join(out)


def _run_text(text, state, a, b):
    """text[a:b] as the program it is: unescaped when it sits inside double quotes."""
    return _dq_unescape(text[a:b]) if a < len(text) and state[a] == 2 else text[a:b]


def _param_brace_end(seg, state, k):
    """Offset of the `}` that closes the `${` whose body starts at k, or -1. Only unquoted braces count, a backslash takes the next character."""
    depth = 1
    while k < len(seg):
        if state[k] == 0:
            if seg[k] == '\\':
                k += 2
                continue
            if seg[k] == '{':
                depth += 1
            elif seg[k] == '}':
                depth -= 1
                if depth == 0:
                    return k
        k += 1
    return -1


def _token_spans(seg):
    """Idezojel-tudatos szavakra bontas. Elemek: (szoveg idezojel nelkul, volt-e benne
    idezojelen beluli szokoz, a szo kezdete, a szo vege (kizarolag) a szegmensben): _tokens() ennek a vetulete (card 4b42b6b0 round 3: the
    brace / glob check must know WHERE the command word stands to read its quote state from the whole command)."""
    state = _quote_map(seg)
    ansis = _ansi_strings(seg) or {}
    toks, cur, had_space, i, wstart = [], [], False, 0, None
    while i < len(seg):
        ch = seg[i]
        if i in ansis:
            # `$'..'` is ONE word part whose value is the escapes expanded (card 4b42b6b0: `$'\x72m'` is rm to the shell and was `$\x72m`
            # here, a word no rule knew)
            a, b = ansis[i]
            val = _ansi_decode(seg[a:b])
            if re.search(r'\s', val):
                had_space = True
            if wstart is None:
                wstart = i
            cur.append(val)
            i = b + 1
            continue
        if not state[i] and seg.startswith('$[', i) and _legacy_arith_end(seg, i) >= 0:
            # the legacy `$[ 1 + 2 ]` is ONE word part, its blanks do not end the word (card 46f43d1a round 3: `x=$[ 1 + 2 ] rm` ran rm)
            b = _legacy_arith_end(seg, i) + 1
            had_space = had_space or bool(re.search(r'\s', seg[i:b]))
            if wstart is None:
                wstart = i
            cur.append(seg[i:b])
            i = b
            continue
        if not state[i] and ch == '\\' and i + 1 < len(seg):
            # an unquoted backslash makes the next character a letter of the word, a blank or a tab as well (`x=a\\ b rm` is ONE assignment word and then rm;
            # card 40650fd7 round 2)
            if wstart is None:
                wstart = i
            if seg[i + 1] in ' \t':
                had_space = True
            cur.append(seg[i:i + 2])
            i += 2
            continue
        if state[i] == 0 and seg.startswith('${', i) and seg[i + 2:i + 3] not in ('', ' ', '\t', '|'):    # `${ cmd; }` and `${|cmd;}` are command substitutions (card 8ed4c8e8), not a word part
            j = _param_brace_end(seg, state, i + 2)
            if j >= 0:                         # a parameter expansion is ONE word part, blanks and `>` inside it included (`>${X:-a b} rm`)
                if wstart is None:
                    wstart = i
                cur.append(seg[i:j + 1])
                i = j + 1
                continue
        if state[i] == 0 and ch in '<>' and not seg.startswith(('<(', '>('), i) and cur:
            # the shell cuts a word at an unquoted `<` or `>` as well (`nohup>f rm`, `rm>f -rf x`, `git>f push` are a word and a redirection);
            # the digits or `{name}` in front of the operator and the `&` of `&>` belong to it (card 6b631f69 round 2, Sam 4575)
            raw = seg[wstart:i]
            if not re.fullmatch(r'(?:\{[A-Za-z_]\w*\}|[0-9]+)?[<>&|]*', raw):
                if raw.endswith('&') and state[i - 1] == 0 and cur[-1] == '&':
                    cur.pop()
                    if cur:
                        toks.append((''.join(cur), had_space, wstart, i - 1))
                    cur, had_space, wstart = ['&'], False, i - 1
                else:
                    toks.append((''.join(cur), had_space, wstart, i))
                    cur, had_space, wstart = [], False, i
        if not state[i] and ch in ' \t':
            if cur:
                toks.append((''.join(cur), had_space, wstart, i))
            cur, had_space, wstart = [], False, None
            i += 1
            continue
        if not state[i] and ch in ('"', "'"):
            if wstart is None:
                wstart = i
            i += 1
            continue
        if state[i] == 2 and ch == '\\' and i + 1 < len(seg) and seg[i + 1] in '$`"\\\n':
            # inside double quotes the backslash is the shell's own escape (card 798c3c24 round 2: `bash -c "r\\<NL>m"` hands the inner shell
            # a backslash-newline)
            if wstart is None:
                wstart = i
            if seg[i + 1] != '\n':
                cur.append(seg[i + 1])
            i += 2
            continue
        if state[i] and ch in ' \t':
            had_space = True
        if wstart is None:
            wstart = i
        cur.append(ch)
        i += 1
    if cur:
        toks.append((''.join(cur), had_space, wstart, len(seg)))
    return toks


def _tokens(seg):
    """Idezojel-tudatos szavakra bontas. Elemek: (szoveg idezojel nelkul, volt-e benne idezojelen beluli szokoz)."""
    return [(t, sp) for t, sp, _a, _b in _token_spans(seg)]


# --- Burkolo-parancsok (dec196bb) --------------------------------------------
# A kapu a szegmens ELSO szavat nezi parancsnevnek. Enelkul minden burkolo, amely
# parancsot kap ARGUMENTUMKENT, atvinne mellette a tiltott parancsot:
#     ls /tmp | xargs <tiltott>          find . -exec <tiltott> {} ;
#     timeout 5 <tiltott> /tmp/x         bash -c "<tiltott> ..."
# Mind a tizenegy megmert alak a kapu KORABBI valtozatan is atment: ez nem regresszio
# volt, hanem kezdettol nyitva allo res. 3365 valos parancson megmerve a bovites 0 uj
# blokkot, 0 tort kontrollt es 0 elveszett blokkot hozott -- a koltseg MERT, nem becsult.
#
# A KORLAT, amit ki kell mondani: a beagyazott szkript vizsgalata CSAK EGY SZINTIG hat.
#     bash -c "<tiltott> -rf /tmp/x"              -> BLOKK
#     bash -c "bash -c \"<tiltott> -rf /tmp/x\""  -> ATENGED
# mert a token-kinyeres nem bontja vissza a visszaperjeles idezojel-vedest. Ez tehat a
# VELETLEN ellen ved, nem az elszant megkerules ellen -- ami illik a kapu jellegehez
# (egyuttmukodo agensek kormanyzasa), de ne higgye senki teljesnek.
# Tovabbra sem zarul: "ssh gep <tiltott>" -- az tavoli gepen fut, arra kulon szabaly
# kellene, nem burkolo-felismeres.
# SHELL-KULCSSZAVAK a parancsnev ELOTT. A `if rm -f /x; then ...` szegmens elso
# tokenje az `if`, ami nem tiltott parancsnev -- a kapu ezert a mogotte allo `rm`-et
# SOHA NEM NEZTE MEG. 2026-09-24-en merve az ELES kapun: `rm -f /tmp/x` -> exit 2,
# `if rm -f /tmp/x; then echo ok; fi` -> exit 0. A res azert sulyos, mert a hazi
# stilus (CLAUDE.md: "Minden ellenorzes if ... then ... else ... fi formaban") EPP
# ezt az alakot irja elo, tehat a leggyakoribb alak volt a vak folt.
# Az `if`/`while`/`!`/`{` elotag, a `fi`/`done`/`}` lezaro -- mindegyiket atlepjuk:
# a lezarok utan vagy nincs semmi, vagy a kovetkezo parancs all, es azt nezni kell.
_KEYWORDS = ('if', 'then', 'elif', 'else', 'fi', 'while', 'until', 'do', 'done',
             'case', 'esac', 'in', 'select', 'function', 'coproc',
             '!', '{', '}', '(', ')', '[[', ']]')
_TRANSPARENT = ('exec', 'command', 'time', 'nohup', 'env', 'busybox', 'toybox')
# Az ertekuket KULON szoban hozo kapcsolok burkolonkent (a tobbi kapcsolo onallo).
_TRANSPARENT_VALUE_OPTS = {
    'env': ('-C', '-u', '--chdir', '--unset'),
    'exec': ('-a',),
    'time': ('-f', '-o', '--format', '--output'),
}
# `env -S "<parancs>"`: a kapcsolo erteke egy TELJES parancssor, amit a prozaszuro kimos.
# Nem koveto -- tiltjuk, nem talalgatunk.
_ENV_SPLIT_RE = re.compile(r'(?<![\w./-])env\s+(?:[^;&|\n]*\s)?(?:-[A-Za-z]*S\b|--split-string)')
_PREFIX_WRAPPERS = ('xargs', 'timeout', 'nice', 'ionice', 'stdbuf', 'watch', 'parallel',
                    'flock', 'chroot', 'setsid', 'unbuffer')
_FIND_EXEC = ('-exec', '-execdir', '-ok', '-okdir')
_SHELLS = ('sh', 'bash', 'zsh', 'dash', 'ksh')
# A kapcsolok, amelyek KULON szoban hozzak az ertekuket (xargs -I {} / -n 1 / -P 4).
_VALUE_FLAGS = ('-I', '-i', '-n', '-P', '-L', '-s', '-d', '-E', '-a',
                '--max-args', '--max-procs', '--delimiter', '--replace', '--arg-file')
_NUMERIC = re.compile(r'^[0-9]+(\.[0-9]+)?[smhd]?$')
# Explicit melysegkorlat a hurokvedelem (sub != cmd) MELLE. A mert maximalis melyseg 3;
# a korlat nem a mai viselkedes miatt kell, hanem hogy egy jovobeli valtoztatas se
# tudjon vegtelen rekurzioba futni. Tullepese BLOKK, nem atengedes: egy ennyire agyazott
# parancsot a kapu nem tud vegigkovetni, es amit nem lat at, azt nem engedi.
_MAX_NEST = 8


def _cname(word):
    """Egy parancsnev-jelolt alapneve a SHELL szemevel: a visszaper-vedes (`\\rm`, `r\\m`) a
    shellben eltunik, tehat `\\rm -f x` ugyanaz, mint `rm -f x`. GATEGAPS1003: a v4 kapu a
    `\\rm`-et nem ismerte fel (alias-megkerulo, bevett shell-forma), es atengedte."""
    return os.path.basename(re.sub(r'\\(.)', r'\1', word))


_FUNCDEF_RE = re.compile(r'^\s*(?:function\s+[\w.-]+\s*(?:\(\s*\))?|[\w.-]+\s*\(\s*\))\s*\{?\s*')


def _strip_funcdef(seg):
    """`f(){ rm -f x` / `function f { rm -f x`: a fuggveny-DEFINICIO torzse parancssor, ami a
    fuggveny hivasakor lefut. A szegmens elso szava itt a fuggveny NEVE, tehat a torzs parancsa
    (rm) a kapu elol rejtve maradt (GATEGAPS1003, a v4 elo kapun mert: `f(){ rm -f /etc/x; }; f`
    ATMENT). A definicio-elotagot levagjuk, a torzs sajat parancsnevet kapja."""
    return _FUNCDEF_RE.sub('', seg, count=1)


def _bare_tokens(seg):
    """The words of a segment with the parentheses read as blanks. An ESCAPED parenthesis is a letter of its word (`x=a\\(b rm`, card 40650fd7 round 2),
    so only an unquoted, unescaped one becomes a blank."""
    state = _quote_map(seg)
    out, i = [], 0
    while i < len(seg):
        if seg[i] == '\\' and not state[i] and i + 1 < len(seg):
            out.append(seg[i:i + 2])
            i += 2
            continue
        out.append(' ' if seg[i] in '()' else seg[i])
        i += 1
    return [(t, sp) for t, sp in _tokens(''.join(out)) if t]


def _words_not_commands_at(text, top, A):
    """Is offset A inside a place where the words are not commands: a compound assignment `name=( ... )` / `name+=( ... )` (the elements of
    `declare -A F=( ["k"]="a/b" )`) or a parameter expansion `${ ... }` (a `|` or `;` in it splits the segmenter's text, not the shell's)? Found as
    the innermost opener that is not closed before A; a `$(`, a plain `(` and a `{ ...; }` group are command positions."""
    depth = 0
    for k in range(A - 1, -1, -1):
        if k not in top:
            continue
        ch = text[k]
        if ch in ')}':
            depth += 1
        elif ch in '({':
            if depth == 0:
                return (ch == '(' and k > 0 and text[k - 1] == '=') or (ch == '{' and k > 0 and text[k - 1] == '$')
            depth -= 1
    return False


def _proof_of(cmd):
    """(quote map, command-level offsets) of the REAL command text, read by the shell reader with the heredoc bodies skipped, or None where it cannot
    read it. The text the segments come from (`scannable`) has quoted prose and comments blanked, so its quote map is not the shell's (card 4b42b6b0
    round 3: a grep pattern with a double quote inside single quotes was cut into 'words')."""
    try:
        data, code = _heredoc_body_ranges(cmd)
        qs = [0] * len(cmd)
        top = _shell_scan(cmd, data + code, qs, True)[2]
        return qs, frozenset(top)
    except _ScanUnsure:
        return None


def _unreadable_command_word(text, seg, seg_pos, idx, proof=None):
    """Why the command word (token `idx` of `seg`, which stands at `seg_pos` of `text`) is not a name the gate can read, or None (card 4b42b6b0
    round 3, Sam 1901). A word with an UNQUOTED brace expansion (`{rm,-f,x}`, `r{m,}`, `{r..r}m`, `r{m,}$X`, `"a b"{c,d}`) or, when the word holds a slash
    (`~user/..` too), an UNQUOTED glob character (`/usr/bin/r[m]`, `bin/r?`, `~root/bin/r[m]`, `./x*`) is expanded by the shell into ANOTHER name: no rule
    meets the real one. The quote state is read from the WHOLE command (not from the segment alone), and a word that does not begin as command text
    (inside `${..}`, a quote, a heredoc body) is a segmentation artefact, not a command."""
    bare = seg.replace('(', ' ').replace(')', ' ')
    spans = _token_spans(bare)
    if idx >= len(spans):
        return 'the token list and the word list differ'
    a, b = spans[idx][2], spans[idx][3]
    word = bare[a:b]
    has_meta = any(c in word for c in '{}*?[]')
    if not has_meta and not any(c in word for c in '$`'):
        return None
    A = seg_pos + a
    if proof is None:
        proof = _proof_of(text)
    if proof is None:
        return 'the shell reader cannot read the command'
    qs, top = proof
    if A not in top or _words_not_commands_at(text, top, A):
        return None
    if not has_meta:
        return _built_by_expansion(seg, spans, idx)
    if text[A:A + (b - a)].replace('(', ' ').replace(')', ' ') != word:
        return 'the word cannot be placed in the command'
    local = _quote_map(bare)
    if any(local[a + k] != qs[A + k] for k in range(b - a)):
        return 'the quote readings of the word and of the command disagree'
    k, n = 0, b - a
    stack, braces, globs, esc = [], False, False, False
    while k < n:
        ch, st = word[k], qs[A + k]
        if st != 0:
            k += 1
            continue
        if ch == '\\':
            k += 2
            continue
        if ch == '$' and k + 1 < n and word[k + 1] in '{(' and qs[A + k + 1] == 0:
            # `${..}` and `$(..)` are no brace expansion: skip to the matching closer
            op, cl = (word[k + 1], '}' if word[k + 1] == '{' else ')')
            depth, j = 1, k + 2
            while j < n and depth:
                if qs[A + j] == 0 and word[j] == op:
                    depth += 1
                elif qs[A + j] == 0 and word[j] == cl:
                    depth -= 1
                j += 1
            k = j
            continue
        if ch == '{':
            stack.append(False)
        elif ch == '}' and stack:
            if stack.pop():
                braces = True
        elif stack and (ch == ',' or (ch == '.' and word[k + 1:k + 2] == '.')):
            stack[-1] = True
        elif ch in '*?':
            globs = True
        elif ch == '[' and ']' in word[k + 1:]:
            globs = True
        k += 1
    if braces:
        return 'a brace expansion'
    if globs and '/' in word:
        return 'a glob in a path'
    return _built_by_expansion(seg, spans, idx)


def _built_by_expansion(seg, spans, idx):
    """Card 8ed4c8e8: the BASENAME of the command word holds an expansion and the word is made of name characters and expansions only (`${X}rm`,
    `r${X}m`, `r$(echo m)`, `"${X}"rm`, `${p:0:1}${p:1}`): the shell builds the name at run time. A word that IS a variable is judged by the variable rule."""
    eflags = _bare_expansion_flags(seg)
    tok = spans[idx][0]
    if len(eflags) == len(spans) and eflags[idx] and not _VAR_NAME_RE.match(tok) and _name_built_by_expansion(tok):
        return 'a name built by an expansion'
    return None


_EXPANSION_RE = re.compile(r'\$\{[^{}]*\}|\$[A-Za-z_][A-Za-z0-9_]*|\$[@*#?!$0-9-]|\$\([^()]*\)|`[^`]*`')


def _name_built_by_expansion(word):
    """The word is made of name characters and expansions only (`${X}rm`, `r${X}m`, `/usr/bin/$(echo r)m`): the spelling of a command name. Python text,
    patterns (`[${p:0:1}]${p:1}`) and escaped dollars are not (card 8ed4c8e8: the first form of the check refused four real commands that were)."""
    if re.search(r'(?<!\\)\$\$[{(]', word):
        return True                                    # a locale string's dollar glued to an expansion (`r$""${X}m` reads as `$$` + `{X}`): loud
    rest = _EXPANSION_RE.sub('', word)
    if re.search(r'\$[{(]|`', rest):
        return True                                    # an expansion that does not close inside the word (`${ }rm` is cut at its space): unreadable, loud
    rest = rest.replace("$'", "'")                      # `$'\\x72'` is a spelling too
    if re.search(r'(?<!\\)\$', rest):
        return True                                    # a dollar no expansion above owns: what a locale string leaves in the token (`rm$""`, `$"r"m$""`), loud
    if rest != word and not rest.replace('"', '').replace("'", ''):
        return True                                    # nothing but expansions and quotes (`${p:0:1}${p:1}`, `"${X}"`): the whole name is built at run time
    return rest != word and re.match(r"^[A-Za-z0-9_./+@%:~,\\'\"-]*$", rest) is not None and re.search(r'[A-Za-z0-9]', rest) is not None


def _bare_expansion_flags(seg):
    """For each token of _bare_tokens(seg), in order: does the word hold an expansion the shell performs (a `$` outside single quotes, or a
    backtick) in the part after its last unquoted slash, its BASENAME? The token list drops the quote characters, so a `$` in single quotes
    (literal) cannot be told from one outside them without this (card 8ed4c8e8: `${NOPE}rm`, `r${NOPE}m`, `"${NOPE}"rm`, `${ }rm`, `$((0))rm` are the
    command rm; the rule that refuses a word which IS a variable did not meet them)."""
    text = seg.replace('(', ' ').replace(')', ' ')
    state = _quote_map(text)
    flags, cur, exp, i, n = [], False, False, 0, len(text)
    bdepth = 0                                 # inside a `${ ... }`: a slash there is text of the expansion, not a directory border (card 8ed4c8e8 round 3)
    inword = set()                             # offsets inside a `${..}` that _token_spans reads as ONE word part: a blank there does not end the word (card 6b631f69 round 3)
    k = 0
    while k < n:
        if state[k] == 0 and text.startswith('${', k) and text[k + 2:k + 3] not in ('', ' ', '\t', '|'):
            e = _param_brace_end(text, state, k + 2)
            if e >= 0:
                inword.update(range(k, e + 1))
                k = e + 1
                continue
        k += 1
    while i < n:
        ch = text[i]
        if state[i] != 1:
            if ch == '$' and text[i + 1:i + 2] == '{':
                bdepth += 1
                cur = True
                exp = True
                i += 2
                continue
            if bdepth and ch == '{':
                bdepth += 1
            elif bdepth and ch == '}':
                bdepth -= 1
        if not state[i] and ch in ' \t' and i not in inword:
            if cur:
                flags.append(exp)
                cur, exp = False, False
            i += 1
            continue
        if not state[i] and ch in ('"', "'"):
            i += 1
            continue
        if state[i] == 0 and ch == '\\' and i + 1 < n:
            cur = True
            i += 2
            continue
        cur = True
        if ch == '/' and state[i] != 1 and not bdepth:
            exp = False                    # the part before the last slash is a directory: it may be anything; the basename starts here
        elif state[i] != 1 and ((ch == '$' and i + 1 < n and (text[i + 1].isalnum() or text[i + 1] in '{(_@*#?!$-' or (state[i] == 0 and text[i + 1] == '"'))) or ch == '`'):
            exp = True
        i += 1
    if cur:
        flags.append(exp)
    return flags


def _after_wrapper(toks, i):
    """A burkolo utani elso parancsnev-jelolt indexe (kapcsolokat es szamot atlepve)."""
    j = i + 1
    while j < len(toks):
        t = toks[j][0]
        skip = _redirect_len(toks, j)
        if skip:
            j += skip                # `timeout 5 >f rm x`: the shell takes the redirection out before timeout sees its words
            continue
        if t.startswith('-'):
            j += 1
            if t in _VALUE_FLAGS:
                while j < len(toks) and _redirect_len(toks, j):
                    j += _redirect_len(toks, j)            # `timeout -s >f KILL 5 rm`, `xargs -I >f {} rm`
                j += 1
            continue
        if _NUMERIC.match(t):        # timeout 5 CMD, nice 10 CMD
            j += 1
            continue
        return j
    return None


_REDIR_WORD_RE = re.compile(r'^(?:\{[A-Za-z_][A-Za-z0-9_]*\}|[0-9]+)?(?:&>>|&>|>>|>\||<<<|<<-|<<|<>|<&|>&|[<>])(.*)$', re.S)


def _redirect_len(toks, i):
    """How many tokens, from toks[i], are ONE redirection (card 6b631f69): `>/dev/null` and `2>&1` are one token, `> /dev/null` and `<<< x` are an
    operator and its target. 0 when toks[i] is not one. The shell takes the redirections out of the words before it looks for the command, wherever
    they stand (`>/dev/null rm -rf x`, `env 2>&1 rm x`, `rm >f -rf x` all run rm); a token list that keeps them reads the first redirection as the
    command name and never meets the real one. A word that began with a quote (`'>x'`) is read as a redirection too: the cost is one more
    command name that is checked, never one less."""
    m = _REDIR_WORD_RE.match(toks[i][0])
    if not m:
        return 0
    return 1 if m.group(1) else min(2, len(toks) - i)


def command_index(toks):
    """A szegmens TENYLEGES parancsnevenek indexe, a burkolokon atlatva.

    A kornyezeti hozzarendelesek (FOO=bar), az atiranyitasok (>/dev/null, 2>&1), az atlatszo elotagok (exec, env, ...) es a
    burkolok (xargs, timeout, ...) atlepesre kerulnek. None, ha nincs parancsnev.
    """
    i = 0
    for _ in range(12):             # a lanc hossza korlatos: nem hurkolunk vegtelenul
        while i < len(toks):
            if re.match(r'^[A-Za-z_][A-Za-z0-9_]*(?:\[[^\]]*\])?\+?=', toks[i][0]):
                i += 1
                continue
            skip = _redirect_len(toks, i)
            if not skip:
                break
            i += skip
        if i >= len(toks):
            return None
        base = _cname(toks[i][0])
        if toks[i][0] in _KEYWORDS and not toks[i][1]:
            i += 1
            continue
        if base in _TRANSPARENT:
            i += 1
            # A burkolo sajat KAPCSOLOI a parancsnev elott allnak (`env -C dir rm x`,
            # `exec -a nev rm x`, `command -p rm x`, `time -p rm x`). MERVE 2026-10-03
            # (FLEETOWNDIR1003, felulvizsgalo meres): ezeknel a kapu a kapcsolot (`-C`, `-i`, `-p`)
            # nezte parancsnevnek, tehat `env -i rm -f /etc/hostname` a TELJES tiltas
            # ellenere ATMENT -- az eles kapun is, nem csak a javitott agon.
            valopts = _TRANSPARENT_VALUE_OPTS.get(base, ())
            while i < len(toks):
                skip = _redirect_len(toks, i)
                if skip:
                    i += skip
                    continue
                if not (toks[i][0].startswith('-') and not toks[i][1]):
                    break
                opt = toks[i][0]
                i += 1
                if opt == '--':
                    break
                if base == 'command' and opt in ('-v', '-V'):
                    return None          # csak lekerdez, nem futtat
                if opt in valopts:
                    while i < len(toks) and _redirect_len(toks, i):
                        i += _redirect_len(toks, i)        # `env -u >f X rm`: the redirection is taken out before env sees its words
                    i += 1
            continue
        if base in _PREFIX_WRAPPERS:
            nxt = _after_wrapper(toks, i)
            if nxt is None:
                return None
            i = nxt
            continue
        return i
    return None


def _sub_scripts(toks, idx):
    """A szegmens shell-parancsanak -c kapcsoloval atadott szkriptje(i).

    GATEGAPS1003: az `eval` is ide tartozik. Az argumentumait szokozzel osszefuzve a shell
    parancssorkent futtatja, tehat `eval "rm -f x"` ugyanaz, mint `sh -c "rm -f x"`. A v4 kapu az
    `eval`-t nem ismerte, es a benne allo torlest atengedte."""
    if idx is not None and _cname(toks[idx][0]) == 'eval':
        words = [t for t, _sp in toks[idx + 1:]]
        return [' '.join(words)] if words else []
    if idx is None or (_cname(toks[idx][0]) not in _SHELLS
                       and _interp_family(_cname(toks[idx][0])) not in ('sh', 'bash', 'zsh')):
        return []
    for k in range(idx + 1, len(toks)):
        # INTERPFLAG1004: a csomagolt alak (`bash -lc`, `sh -ec`) is -c, a kod a KOVETKEZO szo.
        if (toks[k][0] in ('-c', '--command') or re.fullmatch(r'-[A-Za-z]*c[A-Za-z]*', toks[k][0])) \
                and k + 1 < len(toks):
            return [toks[k + 1][0]]
    return []


def _under(path, root):
    """True, ha a (mar abszolut) path a root ALATT van. A root maga NEM szamit bele."""
    root = os.path.normpath(root)
    path = os.path.normpath(path)
    return path.startswith(root + os.sep)


def _resolve(arg, cwd, lexical=False):
    """A torlendo argumentum abszolut alakja, vagy None ha nem eldontheto.

    Symlinkre SZANDEKOSAN nem oldunk fel: az `rm link` magat a linket torli, tehat a
    cel helye nem szamit. A szulokonyvtar viszont szamit, ezert azt feloldjuk -- egy
    munkakonyvtarba mutato symlink-konyvtaron keresztul kulonben kifele lehetne torolni.
    """
    if not arg or any(c in arg for c in RM_UNRESOLVABLE):
        return None
    arg = os.path.expanduser(arg)
    if not os.path.isabs(arg):
        if cwd is None:
            return None
        arg = os.path.join(cwd, arg)
    # A '..'-ot NEM normpath-pal szuntetjuk meg a feloldas ELOTT (FLEETOWNDIR1003): a
    # shell egy symlink-konyvtar utani '..'-ot FIZIKAILAG oldja fel (a link CELJANAK
    # szulojere lep), a normpath viszont szovegesen (a link szulojere). Igy a
    # `<sajat>/link/../x` -- ahol a link kifele mutat -- a gyoker ALATT latszott, es a
    # kapu atengedte volna. A realpath a szuloben levo '..'-ot is fizikailag oldja fel.
    if lexical:
        # `cd` szovegesen oldja a '..'-ot (bash alapbol logikai, -L): a `cd link/..`
        # a link SZOVEGES szulojebe visz, nem a celjanak szulojebe.
        arg = os.path.normpath(arg)
    arg = arg.rstrip('/') or '/'
    parent, base = os.path.split(arg)
    if base in ('.', '..'):
        return None                  # az rm maga is megtagadja a '.' es '..' torleset
    try:
        parent = os.path.realpath(parent)
    except OSError:
        return None
    return os.path.normpath(os.path.join(parent, base))


def _effective_targets(raw, cwd):
    """Az a tovabbi cel, amelyet az `rm` a literal argumentum mellett VALOJABAN erint.

    ZARO PERJEL (FLEETOWNDIR1003, felulvizsgalo es fo agens merese GNU rm 9.7-en: area/link ->
    target, `rm -rf area/link/` rc=0, a link megmaradt, a target TARTALMA torlodott): a
    `link/` a symlinket DEREFERALJA, tehat a cel a link CELJA. A _resolve a perjelet
    levagja, igy csak a linket latta. Itt a teljes ut realpath-ja szamit.
    Lista (0 vagy 1 elem); None = nem eldontheto. A '.' / '..' vegu argumentumot az
    _resolve mar visszautasitotta (az rm is megtagadja). A glob + zaro perjel alakot a
    sajat-terulet szabaly (_area_literal_ok) tiltja; a nem-eles masolaton, ahol az nem
    szamit, ugyanez nem eldontheto, tehat BLOKK.
    """
    if not raw.endswith('/') or raw == '/':
        return []
    if any(c in raw for c in '*?['):
        return None
    arg = os.path.expanduser(raw)
    if not os.path.isabs(arg):
        if cwd is None:
            return None
        arg = os.path.join(cwd, arg)
    try:
        return [os.path.normpath(os.path.realpath(arg.rstrip('/') or '/'))]
    except OSError:
        return None


def _rm_allowed(toks, argstart, cwd, links=False):
    """(engedett?, indoklas) -- a torles minden celpontja engedett teruleten van-e.

    Ket kulon jog, es csak az egyik fugg a telepites jellegetol:
      1. A MUNKAKONYVTAR (PROJECT_ROOT) alatti torles (PR #1357) -- CSAK eldobhato
         masolatban. Eles telepites gyokeren nincs (be8ef9f1, _live_install()).
      2. Az agens SAJAT munkaterulete (OWN_AGENT, lasd _own_area) -- eles telepiteseken
         IS, mert a sajat szemetet takaritani nem kockazat (FLEETOWNDIR1003).
    A korabbi, feltetel nelkuli tiltas nem kockazatot csokkentett, hanem atfogalmazast
    tanitott: a sajat munkajat takarito agens megkerulesi alakokat keresett. Amit a kapu
    tovabbra sem enged at, az a teruleteken KIVULRE mutato torles es minden alak, amirol
    nem tudja eldonteni, hova mutat -- ez utobbi nem szigor, hanem a kapu egyetlen
    tisztesseges valasza arra, amit nem lat at.
    """
    if OWN_AGENT in NO_DELETE_AGENTS:
        # PONDERNODELETE1004: nincs sajat-terulet jog, nincs munkakonyvtar-jog, nincs kivetel.
        return False, 'ennek az agensnek (%s) nincs torlesi joga, a sajat munkateruleten sem' % OWN_AGENT
    live = _live_install(PROJECT_ROOT)
    area = _own_area(OWN_AGENT)
    operands, j = 0, argstart
    while j < len(toks):
        skip = _redirect_len(toks, j)
        if skip:
            j += skip                  # `rm >$(echo f) -rf x`: the segmenter cut the operands off behind the substitution (card 46f43d1a)
            continue
        if toks[j][0] != '--' and not (toks[j][0].startswith('-') and toks[j][0] != '-'):
            operands += 1
        j += 1
    if not operands:
        return False, 'nem latszik, MIT torolne (pl. csovezetekbol vagy -exec {}-bol jon a lista)'
    paths, skip = [], 0
    for tok, quoted_space in toks[argstart:]:
        if skip:
            skip -= 1
            continue
        if quoted_space:              # szokozos idezett szoveg: nem utvonal (lasd ba856d56)
            return False, 'idezett, szokozt tartalmazo argumentum'
        if tok == '--':
            continue
        if tok.startswith('-') and tok != '-':
            continue
        paths.append(tok)
    if not paths:
        return False, 'nem latszik, MIT torolne (pl. csovezetekbol vagy -exec {}-bol jon a lista)'
    for raw in paths:
        abspath = _resolve(raw, cwd)
        if abspath is None:
            return False, 'nem eldontheto utvonal: %s' % raw[:60]
        # A literal ut MELLE kerul az is, amit az rm VALOJABAN erint (FLEETOWNDIR1003):
        # a zaro perjeles symlink-hivatkozas dereferal, a glob pedig a kapu verdiktje utan
        # bomlik ki. Mindegyik cel kulon szamit.
        extra = _effective_targets(raw, cwd)
        if extra is None:
            return False, 'nem eldontheto, mit erint (zaro perjel + glob): %s' % raw[:60]
        lit = _area_literal_ok(raw)
        for tgt in [abspath] + extra:
            ok, why = _target_allowed(tgt, raw, area, live, links, lit)
            if not ok:
                return False, why
    return True, ''


_FIND_PATH_OPTS = {'-H', '-L', '-P'}


def _check_find_delete(toks, argstart, cwd, links, seg):
    """`find <utak> ... -delete` torol, `rm` nelkul (GATEGAPS1003: a v4 kapu atengedte).

    Cel: a find UTVONAL-argumentumai (a kifejezes elott allo szavak). Ugyanaz a verdikt, mint
    az `rm`-nel: a sajat munkaterulet alatt szabad, azon kivul nem, nem eldontheto = blokk.
    Utvonal nelkuli `find -delete` a '.'-ot jarja be, es a '.' az `rm`-nel is nem eldontheto;
    itt viszont a `.` a munkakonyvtar, ezert azt oldjuk fel, nem utasitjuk el vakon."""
    words = [t for t, _sp in toks[argstart:]]
    if '-delete' not in words:
        return
    paths, j = [], 0
    while j < len(toks) - argstart and toks[argstart + j][0] in _FIND_PATH_OPTS:
        j += 1
    while j < len(toks) - argstart:
        t, sp = toks[argstart + j]
        if t.startswith('-') or t in ('(', ')', '!', ','):
            break
        if sp:
            block('find -delete: idezett, szokozt tartalmazo utvonal-argumentum, nem eldontheto.\n'
                  '(a teljes szegmens: %s)' % seg[:160])
        paths.append(t)
        j += 1
    if not paths:
        paths = ['.']
    resolved = []
    for raw in paths:
        if os.path.normpath(raw) == '.':
            if cwd is None:
                block('find -delete: a munkakonyvtar nem ismert, a "." celpont nem eldontheto.\n'
                      '(a teljes szegmens: %s)' % seg[:160])
            resolved.append(cwd)
        else:
            resolved.append(raw)
    ok, why = _rm_allowed([('-r', False)] + [(r, False) for r in resolved], 0, cwd, links=links)
    if not ok:
        block('find -delete, amit a kapu nem engedhet at: %s.\nA find a torlest `rm` nelkul vegzi, de '
              'ugyanaz a szabaly all ra: csak a sajat munkateruleten szabad.\n(a teljes szegmens: %s)'
              % (why, seg[:160]))


def _target_allowed(abspath, raw, area, live, links, lit):
    """Egyetlen, mar feloldott torlesi cel verdiktje: (engedett?, indoklas)."""
    # Elobb a SAJAT terulet: ha az ut alatta van, a verdikt ITT dol el.
    if area is not None and _under(abspath, area):
        if links:
            return False, ('a parancs symlinket is letrehoz (ln/symlink), tehat a torles '
                           'celja nem eldontheto: %s' % raw[:60])
        if lit[0]:
            return True, ''
        if live:
            return False, lit[1]
        # Eldobhato masolaton a munkakonyvtar-szabaly (lent) dont tovabb.
    # The live-install check runs AFTER the path checks (#1744, card 67433099): the verdict is
    # identical (a live root allows rm only in the own area), but the REASON must name what
    # actually stops the command. Checked first, an rm aimed OUTSIDE the root (the session
    # scratchpad under /tmp) was blamed on the live root, which sent the diagnosis wrong.
    if not _under(abspath, PROJECT_ROOT):
        return False, 'a munkakonyvtaron KIVULRE mutat: %s' % abspath
    rel = tuple(os.path.relpath(abspath, PROJECT_ROOT).split(os.sep))
    for prot in RM_PROTECTED:
        n = min(len(rel), len(prot))
        # fnmatch es nem ==: a shell a globot a kapu VERDIKTJE UTAN terjeszti ki,
        # tehat egy `rm -rf *` a vedett nevekre IS kiterjed. A '*' szegmens ezert
        # ugy szamit, mintha a vedett nevre illene -- kulonben a vedett lista egy
        # csillaggal megkerulheto. (Merve 2026-09-25, 9e34a3b7: a javitas elott
        # `rm -rf *` a gyoker alatt ATMENT, es vele a store/, a .git es maga a kapu.)
        if all(fnmatch.fnmatch(prot_seg, rel_seg)
               for rel_seg, prot_seg in zip(rel[:n], prot[:n])):
            return False, 'vedett utvonal a munkakonyvtaron belul: %s' % '/'.join(prot)
    if live:
        return False, ('ez ELES telepites gyokere (%s), es az ut nem a SAJAT '
                       'munkaterulet alatt van: %s' % (PROJECT_ROOT, abspath))
    return True, ''


def _cd_target(toks, argstart, cwd):
    """A `cd` uj munkakonyvtara, vagy None ha nem kovetheto.

    Miert kell: a szegmensekre bontas utan a `cd /etc && rm foo` masodik fele ugy nezne
    ki, mintha az agens sajat konyvtaraban torolne. Ez nem elmeleti -- ez AZ eset,
    amiert a munkakonyvtar-alapu engedely kulonben egy sorban megkerulheto lenne.
    """
    args = [t for t, _sp in toks[argstart:] if not t.startswith('-')]
    if not args:
        return HOME                  # a puszta `cd` a HOME-ba visz
    tgt = _resolve(args[0], cwd, lexical=True)
    return tgt


# The git GLOBAL options (in front of the subcommand) that take their value as a SEPARATE word. A scanner that misses one takes the value
# for the subcommand (`git --attr-source status -c core.fsmonitor=x status`: `status` is the value of --attr-source, git 2.53; ff9a0528
# round 2, Sam 1772 A2). One list for every scanner below; `--exec-path` is kept apart because its value is glued (`--exec-path=<p>`).
_GIT_GLOBAL_VALUE_OPTS = ('-C', '-c', '--git-dir', '--work-tree', '--namespace', '--super-prefix', '--config-env', '--attr-source')


def _git_push_index(toks, argstart):
    """A 'push' alparancs indexe, a git sajat kapcsoloin (-C ut, -c kulcs=ertek) atlepve."""
    i = argstart
    while i < len(toks):
        t = toks[i][0]
        if t in _GIT_GLOBAL_VALUE_OPTS or t == '--exec-path':
            i += 2
            continue
        if t.startswith('-'):
            i += 1
            continue
        return i if t == 'push' else None
    return None


# A `git push` HOSSZU kapcsoloi (git 2.46). A git minden EGYERTELMU roviditest elfogad
# (`--force-w` = `--force-with-lease`), a kapu pedig eddig pontos nevre illesztett: a rovidites
# athaladt. Egy ketertelmu rovidites (`--no-ver`: verify/verbose) a gitnel hiba, tehat nincs push.
_PUSH_BOOL_LONG = ['all', 'branches', 'prune', 'mirror', 'delete', 'tags', 'follow-tags',
                   'atomic', 'dry-run', 'porcelain', 'force', 'force-with-lease',
                   'force-if-includes', 'thin', 'progress', 'verbose', 'quiet', 'set-upstream',
                   'signed', 'verify', 'recurse-submodules']
PUSH_LONG_OPTIONS = set(_PUSH_BOOL_LONG) | {'no-' + o for o in _PUSH_BOOL_LONG} | {
    'repo', 'receive-pack', 'exec', 'push-option', 'ipv4', 'ipv6'}


def _resolve_push_long(flag):
    """A `--kapcsolo[=ertek]` teljes neve, vagy None, ha ismeretlen/ketertelmu."""
    name = flag[2:].split('=', 1)[0]
    if name in PUSH_LONG_OPTIONS:
        return name
    cands = [o for o in PUSH_LONG_OPTIONS if o.startswith(name)]
    return cands[0] if len(cands) == 1 else None


# A `.git/hooks` MUTALASA: a push-kapuk fajljai (pre-push, pre-push.d/*, pre-commit.d/*). A
# dispatcher ma mar hibanak veszi a nem futtathato tagot, de a tag TORLESE/atirasa/lecserelese
# ugyanazt a kapu-kikapcsolast jelenti, ezert azokat a parancsokat tiltja a kapu, amelyek
# fajlt irnak, mozgatnak, torolnek vagy jogot valtoztatnak. Olvasas (cat, ls, grep) szabad.
HOOKS_MUTATORS = {'chmod', 'chown', 'chattr', 'mv', 'rm', 'cp', 'ln', 'install', 'truncate',
                  'tee', 'sed', 'dd', 'touch', 'rmdir', 'unlink', 'rsync', 'patch', 'perl', 'awk'}
# A kapuk fajljai, ES minden fajl, amelybe a core.hooksPath-t be lehet irni: a repo configja
# (`.git/config`, `config.worktree`) es a felhasznaloi gitconfig. A `printf ... >> .git/config`
# ugyanolyan tartos kikapcsolas, mint a `git config core.hooksPath X`, csak a parancsnev nem
# `git` (Sam, SULYOS 2).
_GITCFG = (r'(\.git/(hooks(/|$|[\s\'"])|config($|[\s\'"]|\.worktree))'
           r'|\.gitconfig($|[\s\'"])|\.config/git/config($|[\s\'"]))')
_HOOKS_PATH = re.compile(r'(^|[\s/\'"=])' + _GITCFG)
_HOOKS_REDIRECT = re.compile(r'>{1,2}\s*[^\s;|&<>]*(\.git/(hooks/|config)|\.gitconfig|\.config/git/config)')
_FIND_ACTIONS = {'-delete', '-exec', '-execdir', '-ok', '-okdir', '-fprint', '-fprintf', '-fls'}


_REDIRECT_TARGET = re.compile(r'>{1,2}\s*([^\s;|&<>]+)')


def _is_gate_path(tok, cwd):
    """Mutat-e ez az argumentum a kapuk fajljaira (.git/hooks, a git config fajlok)?

    A nyers szoveg ES a munkakonyvtarhoz kepest feloldott ut is szamit: a `cd .git && ... >> config`
    es a `cd .git/hooks/pre-push.d && find . -delete` alakban az ut relativ, a szoveg onmagaban
    nem tartalmazza a `.git/...` reszt (Sam, 2. kor). Ismeretlen cwd + relativ ut: csak a nyers
    szoveg illesztese tortenik meg.
    """
    if _HOOKS_PATH.search(' ' + tok + ' '):
        return True
    if tok.startswith('-') or not tok:
        return False
    resolved = _resolve(tok, cwd)
    return bool(resolved and _HOOKS_PATH.search(' ' + resolved + ' '))


def _check_hooks_dir(base, toks, argstart, seg, cwd=None):
    for target in _REDIRECT_TARGET.findall(seg):
        if _is_gate_path(target, cwd):
            block('Atiranyitas a .git/hooks vagy egy git config fajl ala: a push/commit kapuk '
                  'fajljainak atirasa. Nem az ugynok dontese.')
    args = [t for t, _sp in toks[argstart:]]
    touches = any(_is_gate_path(t, cwd) for t in args)
    if base == 'find' and touches and any(t in _FIND_ACTIONS for t in args):
        block('find ... -delete/-exec a .git/hooks vagy a git config fajlokon: a push/commit kapuk '
              'eltavolitasa vagy atirasa. Nem az ugynok dontese.')
    if base in HOOKS_MUTATORS and touches:
        block('%s a .git/hooks alatt: a push/commit kapuk (force-guard, szemelyes-adat kapu, '
              'secret-gate) fajljainak modositasa vagy eltavolitasa. Nem az ugynok dontese.' % base)


_READ_CONFIG_FLAGS = {'--get', '--get-all', '--get-regexp', '--unset', '--unset-all', '--list', '-l'}


_CONFIG_VALUE_FLAGS = {'--file', '-f', '--blob', '--type', '-t', '--default'}
_TAMPER_KEYS = ('core.hookspath', 'include.path', 'includeif.')


def _hooks_tamper_git(toks, argstart=0):
    """core.hooksPath BARMELY git-hivasban: a pre-push/pre-commit kapuk kikapcsolasa.

    A korabbi szabaly csak a `git push` szegmensen BELUL lato `-c core.hooksPath=` alakot fogta;
    a `git config core.hooksPath X` kulon parancs TARTOSAN kikapcsolta a kapukat, utana a sima
    push mar tiszta volt (Sam, 013b1bb9). Olvasas es a beallitas TOROLESE (visszaallitas) szabad:
    `git config core.hooksPath` (csak a kulcs), `git config get ...`, `--get`, `--unset`, `--list`.
    """
    text = ' '.join(t for t, _sp in toks).lower()
    # Az `include.path` / `includeIf.*` ugyanazt tudja, mint a core.hooksPath: egy MASIK fajlbol
    # huzza be, tehat a `git config include.path /tmp/g` tartosan, kozvetve kapcsolja ki a kapukat
    # (Sam, 2. kor).
    if not any(k in text for k in _TAMPER_KEYS):
        return
    # a git sajat globalis kapcsoloi: `-c core.hooksPath=X` mindig iras (arra az egy hivasra is)
    i = argstart
    while i < len(toks):
        t = toks[i][0]
        if t == '-c' and i + 1 < len(toks) and any(k in toks[i + 1][0].lower() for k in _TAMPER_KEYS):
            block('git -c core.hooksPath=...: a pre-push/pre-commit kapukat kikapcsolo alak. '
                  'Nem az ugynok dontese.')
        if t in _GIT_GLOBAL_VALUE_OPTS or t == '--exec-path':
            i += 2
            continue
        if t.startswith('-'):
            i += 1
            continue
        break
    if i < len(toks) and toks[i][0] == 'config':
        pos, skip = [], False
        for t, _sp in toks[i + 1:]:
            if skip:
                skip = False
                continue
            if t in _CONFIG_VALUE_FLAGS:
                skip = True
                continue
            if not t.startswith('-'):
                pos.append(t)
        if (pos and pos[0] in ('get', 'list')) or len(pos) == 1:
            return                      # olvasas: csak a kulcs, vagy `get`/`list`
    if any(t in _READ_CONFIG_FLAGS for t, _sp in toks):
        return
    block('git + core.hooksPath / include.path: a pre-push/pre-commit kapukat (force-guard, '
          'szemelyes-adat kapu, secret-gate) kikapcsolo beallitas. Nem az ugynok dontese.')


# ---------------------------------------------------------------------------------------------------------------------------
# GIT CONFIG VALUES THAT RUN PROGRAMS (card ff9a0528; Sam msg 4155, HEX 4160). By INVERTED PROOF, like the rest of the family.
#
# Measured on the live gate before this block: `git -c core.fsmonitor='touch /tmp/x' status` was rc 0, and so were core.pager,
# core.sshCommand, diff.external, sequence.editor, an `alias.x=!prog` after a harmless subcommand, a `credential.helper=!prog`, the
# `--config-env=KEY=VAR` form, and `git config core.fsmonitor 'prog'` / `git config --global core.pager 'prog'` (a persistent write).
# git RUNS the value of those keys as a shell command line whenever the matching subcommand runs, so the value is a program the
# gate never read.
#
# The rule is not a list of the dangerous keys (core.fsmonitor, core.pager, ... a list that the next git release outgrows). A config
# key handed to git on the command line (`-c`, `--config-env`) or written with `git config` is silent only when the gate can PROVE
# it cannot run a program OF THE COMMAND'S CHOOSING: it is on the closed list of INERT keys (any literal value; commit.gpgsign and
# tag.gpgsign do start `gpg.program`, user.signingkey may start ssh-keygen, but that program comes from the config / PATH, and a
# `gpg.program` or `PATH=` before git is a deny of its own), or it is a credential helper whose value is
# EMPTY (resets the list) or exactly the fork-push recipe `!gh auth git-credential`. Everything else, a key the gate does not know,
# a key made of an expansion, a value that comes from an environment variable (`--config-env`), is a deny.
#
# The environment form: GIT_EDITOR, GIT_SEQUENCE_EDITOR, GIT_PAGER and GIT_ASKPASS appear in every normal workflow with the value `true`,
# but their VALUE is a program. Round 1 let them through the environment allowlist and judged only the `NAME=value` token; round 2 (Sam
# 1772) took them OFF the allowlist: every way of binding one is a deny (`+=`, `printf -v`, `read`, `for`, `export`, ...) except the
# plain `NAME=<no-op literal>` word (true, false, :, cat, empty), see _prog_env_noop_assignment.
#
# NAMED LIMITS: (a) the config files git reads by themselves (a repo's .git/config, ~/.gitconfig, an included file) are not read here;
# the gate judges what the COMMAND hands to git, and the writes to those files by the other rules (core.hooksPath / include.path /
# alias, check_gitcfg_write); (b) an option whose VALUE is a program but that is not a config key (`git rebase --exec`, `git bisect
# run`, `git submodule foreach`, `git fetch --upload-pack`, `git grep -O`, `git difftool --extcmd`, `git filter-branch --*-filter`)
# is a different class, not judged here; (c) `-c` after the subcommand is the subcommand's own option (`git commit -c <commit>`).
# The global options that take no value, or take it glued (`--git-dir=<p>`). Together with _GIT_GLOBAL_VALUE_OPTS this is the closed list
# the scan in _git_config_programs steps over; the ones that only print something and exit (`--version`, `--help`, `--html-path`...)
# start no subcommand, so they are on the valueless list as well.
_GIT_GLOBAL_NOVALUE = {'--no-pager', '-P', '--paginate', '-p', '--no-optional-locks', '--no-replace-objects', '--literal-pathspecs',
                       '--glob-pathspecs', '--noglob-pathspecs', '--icase-pathspecs', '--bare', '--no-advice', '--no-lazy-fetch',
                       '--version', '-v', '--help', '-h', '--html-path', '--man-path', '--info-path', '--exec-path'}
_GIT_GLOBAL_GLUED = {'--git-dir', '--work-tree', '--namespace', '--super-prefix', '--attr-source', '--list-cmds', '--exec-path'}
_GIT_INERT_KEY = re.compile(
    r'^(?:user\.(?:name|email|signingkey)|commit\.gpgsign|tag\.gpgsign|core\.quotepath|core\.autocrlf|core\.safecrlf|core\.filemode|'
    r'color\.[\w.-]+|advice\.\w+|init\.defaultbranch|diff\.(?:renames|algorithm|context|colormoved)|merge\.(?:ff|conflictstyle)|'
    r'pull\.(?:rebase|ff)|rebase\.autostash|safe\.directory|gc\.auto|protocol\.file\.allow|push\.default|fetch\.prune|'
    r'credential\.(?:[^=\s]*\.)?(?:usehttppath|interactive|username))$', re.I)
_GIT_CRED_HELPER_KEY = re.compile(r'^credential\.(?:[^=\s]*\.)?helper$', re.I)
_GIT_CRED_HELPER_OK = {'', '!gh auth git-credential'}
_GIT_PROG_ENV = re.compile(r'^(GIT_(?:EDITOR|SEQUENCE_EDITOR|PAGER|ASKPASS))=(.*)$', re.S)
_GIT_NOOP_PROGRAMS = {'true', 'false', ':', 'cat', '', '/bin/true', '/usr/bin/true', '/bin/false', '/usr/bin/false'}


def _git_config_value_runs_nothing(key, value):
    """None when `key` (with `value`, None = unknown, e.g. --config-env) provably runs no program, else the reason."""
    k = key.strip().lower()
    if not k:
        return 'the key is empty, the gate cannot read it'            # (a key made of an expansion is not on the closed list: a deny)
    if _GIT_INERT_KEY.match(k):
        return None
    if _GIT_CRED_HELPER_KEY.match(k):
        if value is None:
            return 'a credential helper whose value comes from the environment is a program the gate cannot read'
        if value not in _GIT_CRED_HELPER_OK:   # (a blanked quoted value is spaces: not on the list, so a deny)
            return ('a credential helper runs its value as a program; only an empty value or `!gh auth git-credential` (the fork-push '
                    'recipe) is allowed')
        return None
    return 'the key is not on the closed list of keys that run no program (core.fsmonitor, core.pager, core.editor, core.sshCommand, ' \
           'diff.external, sequence.editor, pager.*, alias.*, ... run their value)'


_GIT_C_BARE_KEY = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]*$')
_RAW_C_WORD = re.compile(r"""(?<![\w-])-c\s*((?:[^\s'"]|'[^']*'|"[^"]*")+)""")


def _raw_c_pairs():
    """Every word that follows a `-c` in the command AS TYPED, with the quotes of its quoted pieces removed. A quoted value with a
    space reaches the segment scanner BLANKED to spaces of the same length (prose masking), so the text of such a `-c` value is only
    in the raw command."""
    out = []
    for m in _RAW_C_WORD.finditer(_RAW_CMD or ''):
        out.append(re.sub(r"'([^']*)'|\"([^\"]*)\"", lambda q: q.group(1) if q.group(1) is not None else q.group(2), m.group(1)))
    return out


def _git_c_pair(kv):
    """Block on a `key=value` handed to `git -c`. A blanked pair (a quoted value with a space, or a whole quoted pair) is read from the
    raw command: every typed `-c` word of the same length (and the same key, when the key survived) must pass; none found is a deny."""
    key, eq, val = kv.partition('=')
    if not kv.strip() or (eq and val and not val.strip()):
        cands = [p for p in _raw_c_pairs()
                 if len(p) == len(kv) and (not key.strip() or p.partition('=')[0].strip().lower() == key.strip().lower())]
        if not cands:
            block('git -c <idezett par>: a kapu nem tudja kiolvasni, milyen kulcsot allit. Nem az ugynok dontese.')
        for p in cands:
            _git_c_pair(p)
        return
    if not eq:
        if _GIT_C_BARE_KEY.match(kv):
            return                  # `-c KEY` with no `=` sets the boolean true: there is no value, so nothing is run
        # A word with no visible `=` that is not a plain key: a quoted pair whose `=` was blanked with the rest (`$'core.fsmonitor=..'`,
        # `core.fsmonitor"=touch m"`). ANSI-C quoting is not decoded here, so the gate cannot read the key: unprovable, a deny.
        block('git -c <idezett vagy $\'..\' par>: a kapu nem tudja kiolvasni, milyen kulcsot allit. Nem az ugynok dontese.')
    why = _git_config_value_runs_nothing(key, val)
    if why:
        block('git -c %s: %s. Nem az ugynok dontese.' % (key[:40], why))


def _git_config_programs(toks, argstart, in_code=False):
    """Block a config key/value that git would run as a program (see the block comment above). `toks` is the git segment,
    `argstart` the index after the `git` word."""
    n = len(toks)
    i = argstart
    while i < n:
        t = toks[i][0]
        if t == '-c':
            if i + 1 >= n:
                return                  # a trailing `-c` with no word after it sets nothing (git itself refuses it)
            _git_c_pair(toks[i + 1][0])
            i += 2
            continue
        if t.startswith('-c') and not t.startswith('--') and len(t) > 2:          # glued: -ckey=value
            _git_c_pair(t[2:])
            i += 1
            continue
        if t == '--config-env' or t.startswith('--config-env='):
            pair = toks[i + 1][0] if t == '--config-env' and i + 1 < n else t.partition('=')[2]
            why = _git_config_value_runs_nothing(pair.partition('=')[0], None)
            if why:
                block('git --config-env=%s: %s. Nem az ugynok dontese.' % (pair.partition('=')[0][:40], why))
            i += 2 if t == '--config-env' else 1
            continue
        if t == '--exec-path' or t.startswith('--exec-path='):
            if t != '--exec-path':
                block('git --exec-path=<ut>: a git kulso alparancsait onnan futtatja. Nem az ugynok dontese.')
            i += 1
            continue
        if t in _GIT_GLOBAL_VALUE_OPTS:
            i += 2                      # (-c and --config-env are handled above; the rest take their value as the next word)
            continue
        if t in _GIT_GLOBAL_NOVALUE or t.partition('=')[0] in _GIT_GLOBAL_GLUED:
            i += 1
            continue
        if t.startswith('-'):
            # An option the gate does not know: it cannot tell whether the NEXT word is its value or the subcommand, so it cannot tell
            # where the -c pairs end. Inverted proof: unprovable is a deny (ff9a0528 round 2, Sam 1772 A2), but only where the doubt can
            # matter, i.e. when something this function judges (a -c / --config-env pair, a `config` word) stands behind it; a shape
            # with none of them (`git --others`, the lossy tokens of an interpreter body) has nothing to hide.
            if not in_code and any(w == 'config' or w.startswith('--config-env') or (w.startswith('-c') and not w.startswith('--'))
                                   for w, _sp in toks[i + 1:]):
                block('git %s: a git globalis kapcsolo, amit a kapu nem ismer, igy nem tudja, hol kezdodik az alparancs es hol vegzodnek '
                      'a -c parok. Nem az ugynok dontese.' % t[:30])
            i += 1
            continue
        break
    if i >= n:
        return
    if toks[i][0] != 'config':
        return
    # `git config`: a WRITE of a key is judged like `-c`. Reading (one positional, --get*, --list, get/list), unsetting and the
    # path/type flags are silent.
    args, skip = [], False
    flags = set()
    for t, _sp in toks[i + 1:]:
        if skip:
            skip = False
            continue
        if t in _CONFIG_VALUE_FLAGS:
            skip = True
            continue
        if t.startswith('-'):
            flags.add(t.split('=', 1)[0])
            continue
        args.append(t)
    if flags & {'-e', '--edit'}:
        block('git config --edit: megnyitja a szerkesztot (core.editor / GIT_EDITOR), a kapu nem tudja, melyik programot. '
              'Nem az ugynok dontese.')
    if flags & _READ_CONFIG_FLAGS:
        return
    if args[:1] in (['get'], ['list'], ['unset']):
        return
    if args[:1] == ['set']:
        args = args[1:]
    if len(args) < 2:
        return                           # a read: `git config <key>`
    why = _git_config_value_runs_nothing(args[0], args[1])
    if why:
        block('git config %s <ertek>: %s. Nem az ugynok dontese.' % (args[0][:40], why))


def _git_program_env(toks):
    """Block `GIT_EDITOR=...` / `GIT_SEQUENCE_EDITOR=...` / `GIT_PAGER=...` / `GIT_ASKPASS=...` whose value is not a no-op program.
    They are allowed in front of git (the normal workflow sets them to `true`), but git RUNS the value."""
    for t, _sp in toks:
        m = _GIT_PROG_ENV.match(t)
        if m and m.group(2) not in _GIT_NOOP_PROGRAMS:
            block('%s=%s: git futtatja ezt az erteket programkent; csak egy ures muvelet (true, false, :, cat) engedett, mas ertek '
                  'vagy kifejtes nem bizonyithato. Nem az ugynok dontese.' % (m.group(1), m.group(2)[:30]))


def _effective_hooks_path(toks, argstart, pi, cwd, cmd_idx, sub='push'):
    """A core.hooksPath TENYLEGES erteke ahhoz a `git <sub>`-hoz (push, commit, merge, am, rebase, pull ...), amit a parancs inditana.

    Round 3 (Sam, SEVERE 1): a lekerdezes eddig CSAK push elott futott, es egy interpreterbol a repo .git/config-jaba irt
    `core.hooksPath=/dev/null` a COMMIT-kori kapukat (prod-tree-guard, secret-gate, commit-identity) kapcsolta ki. Most ugyanez a
    lekerdezes fut minden hook-futtato alparancs elott.

    A parancsszoveg-mintazas mindig egy irasmoddal le van maradva (Sam, 2. kor: alternativ
    config-fajl, include.path, cd utani relativ ut). Ez a lepes nem az IRAST nezi, hanem az
    EREDMENYT: ugyanazzal a `-C` / inline kornyezettel lekerdezi, mit latna a git. Ha barmely
    config-forras (repo, user, system, include) hooksPath-t ad, a kapuk nem futnanak: blokk.

    Amit NEM lat: egy fajl, amely CSAK ugyanabban a parancsban jon letre (`printf > /tmp/g &&
    GIT_CONFIG_GLOBAL=/tmp/g git push`). Ezt a kornyezeti-valtozo szabaly fogja (a
    GIT_CONFIG_GLOBAL / _SYSTEM / XDG_CONFIG_HOME / HOME atiranyitas maga tiltott), ez a ketto egyutt zar.
    """
    env = dict(os.environ)
    if cmd_idx is not None:
        for t, _sp in toks[:cmd_idx]:
            m = re.match(r'^([A-Za-z_][A-Za-z0-9_]*)=(.*)$', t)
            if m:
                env[m.group(1)] = m.group(2)
    globalflags, i = [], argstart
    while i < pi:
        t = toks[i][0]
        if t in ('-C', '--git-dir', '--work-tree') and i + 1 < pi:
            globalflags += [t, toks[i + 1][0]]
            i += 2
            continue
        i += 1 if not t in ('-c', '--namespace', '--exec-path') else 2
    import subprocess
    try:
        r = subprocess.run(['git'] + globalflags + ['config', '--show-origin', '--get-all', 'core.hooksPath'],
                           cwd=cwd or None, env=env, capture_output=True, text=True, timeout=8)
    except (subprocess.TimeoutExpired, OSError):
        block('git %s: a core.hooksPath tenyleges erteket nem sikerult lekerdezni, a kapu ezert '
              'nem tudja, futnanak-e a git kapuk. Nem engedi at.' % sub)
        return
    if r.returncode not in (0, 1):
        # 1 = the key is not set; anything else (128: not a repository, the -C directory does not exist yet ...) means the gate
        # could not read the config the push would see (Sam round 1: `git -C /tmp/c push` passed, `cd /tmp/c && git push` did not)
        block('git %s: a core.hooksPath tenyleges erteket nem sikerult lekerdezni (git config rc=%d), a kapu ezert nem tudja, futnanak-e '
              'a git kapuk. Nem engedi at.' % (sub, r.returncode))
        return
    if r.returncode == 0 and r.stdout.strip():
        origin = r.stdout.strip().splitlines()[0].split('\t')[0][:80]
        block('git %s: a core.hooksPath BE VAN ALLITVA (%s), a pre-commit/pre-push kapuk (prod-fa, secret-gate, identitas, force-guard, '
              'szemelyes-adat kapu) ezzel nem futnanak. Nem az ugynok dontese.' % (sub, origin))


# ---- DAFB69DB: a git subcommand that RUNS CLIENT HOOKS is judged by an ALLOWLIST (the owner's standing rule 11, inverted proof)
# The class is "a way to run git so that the repo's hooks (pre-commit: secret gate, commit identity; pre-push: force guard,
# personal data, Sam-green; pre-merge-commit) do not run". Spellings of it keep appearing (-n, --no-verify, an unambiguous
# abbreviation, a per-call alias, include.path, -c core.hooksPath, GIT_CONFIG_*), and a list of spellings is always one
# short. So nothing here lists spellings: for commit, merge, am, rebase, push, pull, cherry-pick and revert every OPTION
# must be one the installed git is known to have AND known not to skip a hook; an option the table does not know, an
# ambiguous abbreviation, or an abbreviation that could be a skipping option is a deny ("cannot prove the hooks run").
# The same for the options in front of the subcommand (-c keys, --git-dir ...), the environment assignments in front of
# git, and a subcommand that is not a git builtin (an alias, an external command).
# MEASURED (git 2.53.0, a probe hook per subcommand, one option per call): the options that make a call SUCCEED without
# running its hook are, besides the ones below, only options that create no commit at all (--dry-run, --short, --no-commit,
# --squash, ...) -- nothing to gate -- so the skipping set is exactly: commit -n/--no-verify/--no-post-rewrite, am -n/--no-verify,
# merge/pull/rebase/push --no-verify. Tables: scripts/git-hook-option-tables.py regenerates them from the installed git; the
# test scripts/__tests__/git-hook-switch.test.py fails when git knows an option the table does not.
_GIT_HOOK_OPTS = {   # git 2.53.0; regenerate with scripts/git-hook-option-tables.py
    'am': {
        'long': {
            '3way': None, 'abort': None, 'allow-empty': None, 'binary': None, 'committer-date-is-author-date': None,
            'continue': None, 'directory': 'required', 'empty': 'optional', 'exclude': 'required', 'gpg-sign': None,
            'ignore-date': None, 'ignore-space-change': None, 'ignore-whitespace': None, 'include': 'required',
            'interactive': None, 'keep': None, 'keep-cr': None, 'keep-non-patch': None, 'message-id': None, 'no-3way': None,
            'no-binary': None, 'no-committer-date-is-author-date': None, 'no-directory': None, 'no-exclude': None,
            'no-gpg-sign': None, 'no-ignore-date': None, 'no-ignore-space-change': None, 'no-ignore-whitespace': None,
            'no-include': None, 'no-interactive': None, 'no-keep': None, 'no-keep-cr': None, 'no-keep-non-patch': None,
            'no-message-id': None, 'no-patch-format': None, 'no-quiet': None, 'no-rebasing': None, 'no-reject': None,
            'no-rerere-autoupdate': None, 'no-resolvemsg': None, 'no-scissors': None, 'no-signoff': None, 'no-utf8': None,
            'no-verify': None, 'no-whitespace': None, 'patch-format': 'required', 'quiet': None, 'quit': None, 'quoted-cr':
            'required', 'rebasing': None, 'reject': None, 'rerere-autoupdate': None, 'resolved': None, 'resolvemsg':
            'optional', 'retry': None, 'scissors': None, 'show-current-patch': None, 'signoff': None, 'skip': None, 'utf8':
            None, 'verify': None, 'whitespace': 'required',
        },
        'short': {'3': None, 'C': 'required', 'S': 'optional', 'c': None, 'i': None, 'k': None, 'm': None, 'n': None, 'p': 'required', 'q': None, 'r': None, 's': None, 'u': None},
    },
    'cherry-pick': {
        'long': {
            'abort': None, 'allow-empty': None, 'allow-empty-message': None, 'cleanup': 'required', 'commit': None,
            'continue': None, 'edit': None, 'empty': 'optional', 'ff': None, 'gpg-sign': None, 'keep-redundant-commits':
            None, 'mainline': 'required', 'no-allow-empty': None, 'no-allow-empty-message': None, 'no-cleanup': None,
            'no-commit': None, 'no-edit': None, 'no-ff': None, 'no-gpg-sign': None, 'no-keep-redundant-commits': None,
            'no-mainline': None, 'no-rerere-autoupdate': None, 'no-signoff': None, 'no-strategy': None,
            'no-strategy-option': None, 'quit': None, 'rerere-autoupdate': None, 'signoff': None, 'skip': None, 'strategy':
            'required', 'strategy-option': 'required',
        },
        'short': {'S': 'optional', 'X': 'required', 'e': None, 'm': 'required', 'n': None, 's': None, 'x': None},
    },
    'commit': {
        'long': {
            'ahead-behind': None, 'all': None, 'allow-empty': None, 'allow-empty-message': None, 'amend': None, 'author':
            'required', 'branch': None, 'cleanup': 'required', 'date': 'required', 'dry-run': None, 'edit': None, 'file':
            'required', 'fixup': 'optional', 'gpg-sign': None, 'include': None, 'inter-hunk-context': 'required',
            'interactive': None, 'long': None, 'message': 'required', 'no-ahead-behind': None, 'no-all': None,
            'no-allow-empty': None, 'no-allow-empty-message': None, 'no-amend': None, 'no-author': None, 'no-branch': None,
            'no-cleanup': None, 'no-date': None, 'no-dry-run': None, 'no-edit': None, 'no-file': None, 'no-fixup': None,
            'no-gpg-sign': None, 'no-include': None, 'no-interactive': None, 'no-long': None, 'no-message': None, 'no-null':
            None, 'no-only': None, 'no-patch': None, 'no-pathspec-file-nul': None, 'no-pathspec-from-file': None,
            'no-porcelain': None, 'no-post-rewrite': None, 'no-quiet': None, 'no-reedit-message': None, 'no-reset-author':
            None, 'no-reuse-message': None, 'no-short': None, 'no-signoff': None, 'no-squash': None, 'no-status': None,
            'no-template': None, 'no-untracked-files': None, 'no-verbose': None, 'no-verify': None, 'null': None, 'only':
            None, 'patch': None, 'pathspec-file-nul': None, 'pathspec-from-file': 'required', 'porcelain': None,
            'post-rewrite': None, 'quiet': None, 'reedit-message': 'required', 'reset-author': None, 'reuse-message':
            'required', 'short': None, 'signoff': None, 'squash': 'required', 'status': None, 'template': 'required',
            'trailer': 'required', 'unified': 'required', 'untracked-files': None, 'verbose': None, 'verify': None,
        },
        'short': {'C': 'required', 'F': 'required', 'S': 'optional', 'U': 'required', 'a': None, 'c': 'required', 'e': None, 'i': None, 'm': 'required', 'n': None, 'o': None, 'p': None, 'q': None, 's': None, 't': 'required', 'u': 'optional', 'v': None, 'z': None},
    },
    'merge': {
        'long': {
            'abort': None, 'allow-unrelated-histories': None, 'autostash': None, 'cleanup': 'required', 'commit': None,
            'compact-summary': None, 'continue': None, 'edit': None, 'ff': None, 'ff-only': None, 'file': None, 'gpg-sign':
            None, 'into-name': 'required', 'log': None, 'message': 'required', 'no-abort': None,
            'no-allow-unrelated-histories': None, 'no-autostash': None, 'no-cleanup': None, 'no-commit': None,
            'no-compact-summary': None, 'no-continue': None, 'no-edit': None, 'no-ff': None, 'no-gpg-sign': None,
            'no-into-name': None, 'no-log': None, 'no-message': None, 'no-overwrite-ignore': None, 'no-progress': None,
            'no-quiet': None, 'no-quit': None, 'no-rerere-autoupdate': None, 'no-signoff': None, 'no-squash': None,
            'no-stat': None, 'no-strategy': None, 'no-strategy-option': None, 'no-summary': None, 'no-verbose': None,
            'no-verify': None, 'no-verify-signatures': None, 'overwrite-ignore': None, 'progress': None, 'quiet': None,
            'quit': None, 'rerere-autoupdate': None, 'signoff': None, 'squash': None, 'stat': None, 'strategy': 'required',
            'strategy-option': 'required', 'summary': None, 'verbose': None, 'verify': None, 'verify-signatures': None,
        },
        'short': {'F': 'required', 'S': 'optional', 'X': 'required', 'e': None, 'm': 'required', 'n': None, 'q': None, 's': 'required', 'v': None},
    },
    'pull': {
        'long': {
            'all': None, 'allow-unrelated-histories': None, 'append': None, 'autostash': None, 'cleanup': 'required',
            'commit': None, 'compact-summary': None, 'deepen': 'required', 'depth': 'required', 'dry-run': None, 'edit':
            None, 'ff': None, 'ff-only': None, 'force': None, 'gpg-sign': None, 'ipv4': None, 'ipv6': None, 'jobs': None,
            'keep': None, 'log': None, 'negotiation-tip': 'required', 'no-all': None, 'no-allow-unrelated-histories': None,
            'no-append': None, 'no-autostash': None, 'no-cleanup': None, 'no-commit': None, 'no-compact-summary': None,
            'no-deepen': None, 'no-depth': None, 'no-dry-run': None, 'no-edit': None, 'no-ff': None, 'no-force': None,
            'no-gpg-sign': None, 'no-ipv4': None, 'no-ipv6': None, 'no-jobs': None, 'no-keep': None, 'no-log': None,
            'no-negotiation-tip': None, 'no-progress': None, 'no-prune': None, 'no-quiet': None, 'no-rebase': None,
            'no-recurse-submodules': None, 'no-server-option': None, 'no-set-upstream': None, 'no-shallow-exclude': None,
            'no-shallow-since': None, 'no-show-forced-updates': None, 'no-signoff': None, 'no-squash': None, 'no-stat':
            None, 'no-strategy': None, 'no-strategy-option': None, 'no-summary': None, 'no-tags': None, 'no-update-shallow':
            None, 'no-upload-pack': None, 'no-verbose': None, 'no-verify': None, 'no-verify-signatures': None, 'progress':
            None, 'prune': None, 'quiet': None, 'rebase': None, 'recurse-submodules': None, 'refmap': 'required',
            'server-option': 'required', 'set-upstream': None, 'shallow-exclude': 'required', 'shallow-since': 'required',
            'show-forced-updates': None, 'signoff': None, 'squash': None, 'stat': None, 'strategy': 'required',
            'strategy-option': 'required', 'summary': None, 'tags': None, 'unshallow': None, 'update-shallow': None,
            'upload-pack': 'required', 'verbose': None, 'verify': None, 'verify-signatures': None,
        },
        'short': {'4': None, '6': None, 'S': 'optional', 'X': 'required', 'a': None, 'f': None, 'j': 'optional', 'k': None, 'n': None, 'o': 'required', 'p': None, 'q': None, 'r': None, 's': 'required', 't': None, 'v': None},
    },
    'push': {
        'long': {
            'all': None, 'atomic': None, 'branches': None, 'delete': None, 'dry-run': None, 'exec': 'required',
            'follow-tags': None, 'force': None, 'force-if-includes': None, 'force-with-lease': None, 'ipv4': None, 'ipv6':
            None, 'mirror': None, 'no-all': None, 'no-atomic': None, 'no-branches': None, 'no-delete': None, 'no-dry-run':
            None, 'no-exec': None, 'no-follow-tags': None, 'no-force': None, 'no-force-if-includes': None,
            'no-force-with-lease': None, 'no-mirror': None, 'no-porcelain': None, 'no-progress': None, 'no-prune': None,
            'no-push-option': None, 'no-quiet': None, 'no-receive-pack': None, 'no-recurse-submodules': None, 'no-repo':
            None, 'no-set-upstream': None, 'no-signed': None, 'no-tags': None, 'no-thin': None, 'no-verbose': None,
            'no-verify': None, 'porcelain': None, 'progress': None, 'prune': None, 'push-option': 'required', 'quiet': None,
            'receive-pack': 'required', 'recurse-submodules': 'optional', 'repo': 'required', 'set-upstream': None,
            'signed': None, 'tags': None, 'thin': None, 'verbose': None, 'verify': None,
        },
        'short': {'4': None, '6': None, 'd': None, 'f': None, 'n': None, 'o': 'required', 'q': None, 'u': None, 'v': None},
    },
    'rebase': {
        'long': {
            'abort': None, 'allow-empty-message': None, 'apply': None, 'autosquash': None, 'autostash': None,
            'committer-date-is-author-date': None, 'continue': None, 'edit-todo': None, 'empty': 'optional', 'exec':
            'required', 'ff': None, 'force-rebase': None, 'fork-point': None, 'gpg-sign': None, 'ignore-date': None,
            'ignore-whitespace': None, 'interactive': None, 'keep-base': None, 'keep-empty': None, 'merge': None,
            'no-allow-empty-message': None, 'no-autosquash': None, 'no-autostash': None, 'no-committer-date-is-author-date':
            None, 'no-exec': None, 'no-ff': None, 'no-force-rebase': None, 'no-fork-point': None, 'no-gpg-sign': None,
            'no-ignore-date': None, 'no-ignore-whitespace': None, 'no-keep-base': None, 'no-keep-empty': None, 'no-onto':
            None, 'no-preserve-merges': None, 'no-quiet': None, 'no-reapply-cherry-picks': None, 'no-rebase-merges': None,
            'no-rerere-autoupdate': None, 'no-reschedule-failed-exec': None, 'no-reset-author-date': None, 'no-root': None,
            'no-signoff': None, 'no-stat': None, 'no-strategy': None, 'no-strategy-option': None, 'no-update-refs': None,
            'no-verbose': None, 'no-verify': None, 'no-whitespace': None, 'onto': 'required', 'preserve-merges': None,
            'quiet': None, 'quit': None, 'reapply-cherry-picks': None, 'rebase-merges': None, 'rerere-autoupdate': None,
            'reschedule-failed-exec': None, 'reset-author-date': None, 'root': None, 'show-current-patch': None, 'signoff':
            None, 'skip': None, 'stat': None, 'strategy': 'required', 'strategy-option': 'required', 'update-refs': None,
            'verbose': None, 'verify': None, 'whitespace': 'required',
        },
        'short': {'C': 'required', 'S': 'optional', 'X': 'required', 'f': None, 'i': None, 'm': None, 'n': None, 'q': None, 'r': 'optional', 's': 'required', 'v': None, 'x': 'required'},
    },
    'revert': {
        'long': {
            'abort': None, 'cleanup': 'required', 'commit': None, 'continue': None, 'edit': None, 'gpg-sign': None,
            'mainline': 'required', 'no-cleanup': None, 'no-commit': None, 'no-edit': None, 'no-gpg-sign': None,
            'no-mainline': None, 'no-reference': None, 'no-rerere-autoupdate': None, 'no-signoff': None, 'no-strategy':
            None, 'no-strategy-option': None, 'quit': None, 'reference': None, 'rerere-autoupdate': None, 'signoff': None,
            'skip': None, 'strategy': 'required', 'strategy-option': 'required',
        },
        'short': {'S': 'optional', 'X': 'required', 'e': None, 'm': 'required', 'n': None, 's': None},
    },
}
_GIT_HOOK_SKIP_LONG = {'commit': {'no-verify', 'no-post-rewrite'}, 'merge': {'no-verify'}, 'am': {'no-verify'},
                       'rebase': {'no-verify'}, 'push': {'no-verify'}, 'pull': {'no-verify'}}
_GIT_HOOK_SKIP_SHORT = {'commit': {'n'}, 'am': {'n'}}
_GIT_BUILTINS = frozenset((
    'add', 'am', 'annotate', 'apply', 'archive', 'backfill', 'bisect', 'blame', 'branch', 'bugreport', 'bundle',
    'cat-file', 'check-attr', 'check-ignore', 'check-mailmap', 'check-ref-format', 'checkout', 'checkout-index',
    'cherry', 'cherry-pick', 'clean', 'clone', 'column', 'commit', 'commit-graph', 'commit-tree', 'config',
    'count-objects', 'credential', 'credential-cache', 'credential-store', 'daemon', 'describe', 'diagnose', 'diff',
    'diff-files', 'diff-index', 'diff-pairs', 'diff-tree', 'difftool', 'fast-export', 'fast-import', 'fetch',
    'fetch-pack', 'filter-branch', 'fmt-merge-msg', 'for-each-ref', 'for-each-repo', 'format-patch', 'fsck',
    'fsck-objects', 'gc', 'get-tar-commit-id', 'grep', 'hash-object', 'help', 'hook', 'http-backend', 'http-fetch',
    'http-push', 'imap-send', 'index-pack', 'init', 'init-db', 'instaweb', 'interpret-trailers', 'last-modified',
    'log', 'ls-files', 'ls-remote', 'ls-tree', 'mailinfo', 'mailsplit', 'maintenance', 'merge', 'merge-base',
    'merge-file', 'merge-index', 'merge-octopus', 'merge-one-file', 'merge-ours', 'merge-recursive',
    'merge-recursive-ours', 'merge-recursive-theirs', 'merge-resolve', 'merge-subtree', 'merge-tree', 'mergetool',
    'mktag', 'mktree', 'multi-pack-index', 'mv', 'name-rev', 'notes', 'pack-objects', 'pack-redundant', 'pack-refs',
    'patch-id', 'pickaxe', 'prune', 'prune-packed', 'pull', 'push', 'quiltimport', 'range-diff', 'read-tree',
    'rebase', 'receive-pack', 'reflog', 'refs', 'remote', 'remote-ext', 'remote-fd', 'remote-ftp', 'remote-ftps',
    'remote-http', 'remote-https', 'repack', 'replace', 'replay', 'repo', 'request-pull', 'rerere', 'reset',
    'restore', 'rev-list', 'rev-parse', 'revert', 'rm', 'send-pack', 'shell', 'shortlog', 'show', 'show-branch',
    'show-index', 'show-ref', 'sparse-checkout', 'stage', 'stash', 'status', 'stripspace', 'submodule', 'subtree',
    'switch', 'symbolic-ref', 'tag', 'unpack-file', 'unpack-objects', 'update-index', 'update-ref',
    'update-server-info', 'upload-archive', 'upload-pack', 'var', 'verify-commit', 'verify-pack', 'verify-tag',
    'version', 'whatchanged', 'worktree', 'write-tree',
))
# `-c key=value` keys that cannot change where hooks come from or what a subcommand means. Everything else (core.*,
# include.*, alias.*, init.templateDir, ...) is a deny in front of a hook-running subcommand.
_GIT_C_KEY_OK = re.compile(r'^(credential\.[\w.-]*|user\.(name|email)|advice\.\w+|color\.[\w.-]*|safe\.directory|gc\.auto)$', re.I)
# Options in front of the subcommand that change nothing about hooks.
_GIT_GLOBAL_OK = {'--no-pager', '-P', '--paginate', '-p', '--no-optional-locks', '--no-replace-objects',
                  '--literal-pathspecs', '--glob-pathspecs', '--noglob-pathspecs', '--icase-pathspecs'}
# Environment assignments in front of git that may stay. GIT_CONFIG_* / XDG_CONFIG_HOME / HOME are handled by the segment
# loop; this is the rest of the GIT_ namespace, plus the fleet's own hook-override switches (named in the hooks).
_GIT_ENV_OK = re.compile(r'^GIT_(AUTHOR|COMMITTER)_(NAME|EMAIL|DATE)$|^GIT_(EDITOR|SEQUENCE_EDITOR|TERMINAL_PROMPT|MERGE_AUTOEDIT|PAGER|ASKPASS)$')
_GIT_OVERRIDE_ENV = re.compile(r'^(SKIP_[A-Z0-9_]*GATE|MARVEEN_PROD_[A-Z0-9_]*_OK)$')


_EXPANSION_LEAD = re.compile(r'^[$`{\\]')
_LIT_VAR_LEAD = re.compile(r'^\$(?:([A-Za-z_]\w*)|\{([A-Za-z_]\w*)\})(.*)$', re.S)
_LITERALS = {}      # NAME -> literal value of the variables that got ONE literal value on this command line


def _resolve_word(a):
    """A word that starts with `$N` / `${N}` of a variable with ONE literal value is read with that value (`$SHA:refs/heads/x`); anything
    else is returned unchanged."""
    m = _LIT_VAR_LEAD.match(a)
    if m:
        v = _LITERALS.get(m.group(1) or m.group(2))
        if v is not None and not re.search(r'[$`{]', m.group(3)):
            return v + m.group(3)
    return a


def _git_hook_option_verdict(sub, args):
    """None when every option of the call is KNOWN and not hook-skipping, else (token, why).

    A word that is not consumed as the value of a known option and STARTS with an expansion (`$N`, `${N:--n}`, `$'-n'`, `{-n,-m}`,
    a backtick) can become any option once the shell has expanded it (Sam round 1, SEVERE 1: `N=-n; git commit $N -m x`), and the
    gate reads text, not the expanded line: it is not provable, so it is a deny. A variable with ONE literal value on the command
    line is read as that value. After `--` every word is a path."""
    t = _GIT_HOOK_OPTS[sub]
    skip_l, skip_s = _GIT_HOOK_SKIP_LONG.get(sub, set()), _GIT_HOOK_SKIP_SHORT.get(sub, set())
    i = 0
    while i < len(args):
        a = _resolve_word(args[i])
        i += 1
        if a == '--':
            break
        if _EXPANSION_LEAD.match(a) and (skip_l or skip_s):
            # only for the subcommands that HAVE a hook-skipping option (cherry-pick and revert have none: replay, 11 of 24)
            return a, 'an expansion in an option position, the shell may turn it into any option'
        if a.startswith('--'):
            name, eq, _val = a[2:].partition('=')
            cands = [name] if name in t['long'] else [o for o in t['long'] if name and o.startswith(name)]
            # an abbreviation that COULD be a skipping option is a deny, whatever else it could be
            if name and (name in skip_l or any(o.startswith(name) for o in skip_l)):
                return a, 'a hook-skipping option or an abbreviation of one'
            if len(cands) != 1:
                return a, 'an option git does not list for this subcommand, or an ambiguous abbreviation'
            if t['long'][cands[0]] == 'required' and not eq:
                i += 1
            continue
        if a.startswith('-') and len(a) > 1:
            cluster = a[1:]
            for k, c in enumerate(cluster):
                if c in skip_s:
                    return a, 'a hook-skipping short option'
                if c not in t['short']:
                    return a, 'a short option git does not list for this subcommand'
                kind = t['short'][c]
                if kind == 'optional':
                    break                                   # the rest of the cluster is the attached value
                if kind == 'required':
                    if k == len(cluster) - 1:
                        i += 1                              # the value is the next word
                    break                                   # else: the rest of the cluster is the value
    return None


_RAW_QUOTED_C = re.compile(r"""(?<![\w-])-c\s+(?:'([^']*)'|"([^"]*)")""")


def _raw_quoted_c_keys_clean():
    """A quoted `-c 'key=value with spaces'` reaches the gate BLANKED (a quoted string with a space is prose to the segment
    scanner), so its key is invisible there. Read the keys from the command as typed instead: True only when there is at
    least one quoted -c and EVERY such key is on the allowlist (inverted proof: nothing found, or anything else, is a deny)."""
    keys = [(m.group(1) if m.group(1) is not None else m.group(2)).split('=', 1)[0].strip() for m in _RAW_QUOTED_C.finditer(_RAW_CMD)]
    return bool(keys) and all(_GIT_C_KEY_OK.match(k) for k in keys)


def _git_hook_class(toks, argstart, cmd_idx=None, in_code=False, tail_subst=False):
    """DAFB69DB: block a hook-running git subcommand unless the hooks provably run (see the block comment above)."""
    # 2. the options in front of the subcommand
    i = argstart
    glob_bad = None
    while i < len(toks):
        t = toks[i][0]
        if t == '-C':
            i += 2
            continue
        if t == '-c' or (t.startswith('-c') and not t.startswith('--') and len(t) > 2):
            kv = toks[i + 1][0] if t == '-c' and i + 1 < len(toks) else t[2:]
            key = kv.split('=', 1)[0]
            if not kv.strip() and _raw_quoted_c_keys_clean():
                key = 'credential.x'                        # blanked quoted value, every typed key is allowlisted
            if not _GIT_C_KEY_OK.match(key):
                glob_bad = glob_bad or '-c %s' % key[:40]
            i += 2 if t == '-c' else 1
            continue
        if t in _GIT_GLOBAL_OK:
            i += 1
            continue
        if t in ('--version', '-h', '--help', '--html-path', '--man-path', '--info-path'):
            return
        if t.startswith('-'):
            glob_bad = glob_bad or t[:30]
            i += 2 if t in ('--git-dir', '--work-tree', '--namespace', '--super-prefix', '--config-env', '--exec-path') else 1
            continue
        break
    if i >= len(toks):
        return
    sub = toks[i][0]
    if sub not in _GIT_BUILTINS:
        if in_code:
            # the words of a python3/node heredoc BODY are source text, not a shell command line: `git in the path` in a
            # string or a comment is prose, and a subprocess call is not tokenised as `git ...` here at all. The other
            # git checks keep reading such a body; only "this word is an alias" needs a real command position. Named limit.
            return
        block('git %s: nem git beepitett alparancs (alias vagy kulso program), a hook-futast nem lehet bizonyitani. '
              'Nem az ugynok dontese.' % sub[:30])
    if sub in ('send-pack', 'http-push', 'remote-ext', 'remote-fd', 'remote-ftp', 'remote-ftps', 'remote-http', 'remote-https'):
        # push plumbing: it sends the refs WITHOUT running pre-push (Sam round 1, SEVERE 4: `git send-pack --force ../remote.git x`
        # rc 0, hook not run, forced update on the remote), so every gate that rests on pre-push is skipped
        block('git %s: a push-vezetek (plumbing) a pre-push kapukat (force-guard, szemelyes-adat kapu, Sam-green, 20-outgoing-identity) '
              'kihagyja, force-szal is. Nem az ugynok dontese.' % sub)
    if sub in _GIT_HOOK_OPTS and tail_subst and (sub in _GIT_HOOK_SKIP_LONG or sub in _GIT_HOOK_SKIP_SHORT):
        block('git %s ... $( vagy `: a parancs maradeka egy ki nem fejtett behelyettesitesbol jon, a kapu nem latja, milyen kapcsolo lesz '
              'belole. Idezd az erteket ("$(...)"), vagy ird ki.' % sub)
    if sub in _GIT_HOOK_OPTS:
        # the environment in front of git: the fleet's own override switches, and the rest of the GIT_ namespace
        for t, _sp in toks[:max(argstart - 1, 0)]:
            name = t.split('=', 1)[0] if '=' in t else ''
            if _GIT_OVERRIDE_ENV.match(name):
                block('%s=...: a kapukat (secret-gate, commit-identitas, sam-green, prod-fa) kikapcsolo, naplozott '
                      'felulbiralas. Nem az ugynok dontese; kerd a fo agenst.' % name)
            if name.startswith('GIT_') and not _GIT_ENV_OK.match(name):
                block('%s=... a git elott: a hook-keresest, a konfigot vagy a repot atiranyithatja. Nem az ugynok '
                      'dontese.' % name)
    if sub == 'config':
        # a persistent alias can hide any switch later; core.hooksPath and include.path are _hooks_tamper_git's
        pos = [t for t, _sp in toks[i + 1:] if not t.startswith('-')]
        if pos[:1] == ['set']:
            pos = pos[1:]
        elif pos[:1] in (['get'], ['list'], ['unset'], ['edit']):
            pos = []
        if len(pos) >= 2 and any(re.match(r'^alias\.', x, re.I) for x in pos):
            block('git config alias.*: a tartos alias barmit elrejthet (a hook-kapcsolot is), ezert nem irhato. '
                  'Nem az ugynok dontese.')
        return
    if sub not in _GIT_HOOK_OPTS:
        return
    if glob_bad:
        block('git %s ... %s: a hook-utat, a repot vagy az alparancs jelenteset atirhato globalis kapcsolo; a kapu a '
              'hook-futtato alparancs elott csak a hook-futast nem befolyasolo kapcsolokat engedi.' % (glob_bad, sub))
    bad = _git_hook_option_verdict(sub, [t for t, _sp in toks[i + 1:]])
    if bad:
        block('git %s %s: %s. A kapu a hook-futtato alparancsoknal csak az ismert, hook-kihagyast nem okozo kapcsolokat '
              'engedi (pre-commit/pre-push/pre-merge-commit: secret-gate, identitas, sam-green). Nem az ugynok dontese.'
              % (sub, bad[0][:30], bad[1]))
    return sub, i


# ---------------------------------------------------------------------------------------------------------------------------
# HEAD-MOVE GATE for sub-agents, by INVERTED PROOF (card deecccda, HEX 4011; found by Igor 4009 and Sam 4010).
#
# Measured 2026-10-14: a sub-agent could move the HEAD and the branch of the LIVE main checkout with no hook and no gate in the
# way: a branch committed in a linked worktree and fast-forwarded in (`git merge --ff-only`), `update-ref`, `reset`, `checkout`.
# That puts code on the live tree: it is a rollout, and only the main agent rolls out. So the rule is not "deny these spellings";
# it is: a git call of a SUB-AGENT is silent only when the gate can PROVE it does not move the HEAD or the refs of the install's
# main checkout. Everything else is loud, with a message that names the main agent.
#
# The refs of the install repo that matter are two: its HEAD, and the branch its main checkout has checked out (read live).
#   1. a READ subcommand (closed list) is silent anywhere;
#   2. a subcommand that touches only the index, the work tree, the config, objects, tags or a new repo (closed list) is silent;
#   3. a subcommand that MOVES the HEAD of the repo it runs in (commit, merge, reset, checkout, switch, rebase, cherry-pick,
#      revert, am, pull, bisect, branch -m ...) is silent only when its target is PROVEN not to be the install's main checkout.
#      The target is the event cwd followed through `cd` (literal or a variable that got ONE literal value on this line; a `cd` to
#      a directory that does not exist yet counts for BOTH the old and the new directory, because a failed `cd` leaves the old one),
#      and through `-C`. A directory outside the install's work tree cannot be its main checkout; inside it, `git rev-parse
#      --show-toplevel` must name another repo. A linked worktree of the install and a foreign repo both pass;
#   4. a subcommand that writes a ref BY NAME (update-ref, symbolic-ref, branch create/-d/-D/-f, fetch into a named ref,
#      checkout/switch -b/-B) does not need a target proof, but its NAME must not be the branch the main checkout has checked
#      out, nor HEAD when the target is the main checkout (the refs of a linked worktree are shared with it);
#   5. an unknown subcommand, an unknown global option, a `-c` key outside a short closed list, `--git-dir` / `--work-tree`,
#      `pushd` / `popd` / `cd -` / CDPATH / `env -C` (the working directory the gate cannot follow): loud, because the gate
#      cannot read what they do.
# The main agent is not affected: its identity is "unknown" here, as in every other sub-agent-only rule.
#
# NAMED LIMITS, said out loud: (a) a commit in a linked worktree is ordinary work and passes (the standing limit of the waiver in
# self-pace-gate.mjs); (b) the state the gate reads is the state BEFORE the command: a repo that an EARLIER segment of the same
# command creates, links or re-points (a `.git` file written by `echo`, a symlink made by `ln -s`) is not followed; (c) a git call
# inside interpreter code (`subprocess.run(['git', ...])`) is not judged here, only as visible as the rest of the gate makes it;
# (d) a caller whose transcript path is not under agents/<name>/.claude-config is "unknown" and is treated as the main agent.
HM_READ = {
    'log', 'diff', 'show', 'status', 'rev-parse', 'rev-list', 'merge-base', 'grep', 'ls-files', 'ls-tree', 'ls-remote',
    'cat-file', 'check-ignore', 'var', 'archive', 'format-patch', 'blame', 'shortlog', 'describe', 'name-rev', 'for-each-ref',
    'show-ref', 'diff-tree', 'diff-index', 'diff-files', 'whatchanged', 'count-objects', 'verify-commit', 'verify-tag',
    'cherry', 'range-diff', 'show-branch', 'help', 'version', 'merge-tree', 'check-ref-format', 'get-tar-commit-id',
    'check-attr', 'column', 'fmt-merge-msg', 'interpret-trailers', 'mailinfo', 'mailsplit', 'patch-id', 'stripspace',
    'unpack-file', 'show-index', 'verify-pack',
}
# touches the index, the work tree, the config, objects, tags or a NEW repo; cannot move a HEAD or a branch ref (worktree, stash,
# config, push, fetch, reflog have write forms that are screened in _head_move_gate)
HM_NOMOVE = {
    'add', 'rm', 'mv', 'restore', 'clean', 'apply', 'config', 'remote', 'init', 'clone', 'gc', 'prune', 'pack-refs', 'repack',
    'stash', 'worktree', 'tag', 'fetch', 'push', 'submodule', 'sparse-checkout', 'update-index', 'write-tree', 'read-tree',
    'checkout-index', 'hash-object', 'mktree', 'commit-tree', 'unpack-objects', 'pack-objects', 'index-pack', 'maintenance',
    'credential', 'lfs', 'auth', 'rerere', 'fsck', 'notes', 'reflog', 'bundle', 'merge-file',
}
# can move a HEAD, or write a ref by name
HM_MOVE = {
    'commit', 'merge', 'reset', 'checkout', 'switch', 'rebase', 'cherry-pick', 'revert', 'am', 'pull', 'bisect', 'branch',
    'update-ref', 'symbolic-ref', 'filter-branch', 'replace',
}
# git's own options that change nothing about the target
HM_GLOBAL_FLAGS = {
    '--no-pager', '-P', '--paginate', '-p', '--no-optional-locks', '--literal-pathspecs', '--glob-pathspecs',
    '--noglob-pathspecs', '--icase-pathspecs', '--no-replace-objects', '--no-lazy-fetch', '--no-advice',
}
# `git -c key=value`: only keys that cannot re-point the repo, define an alias, or reach another repo (credential helpers are the
# fork-push recipe; `core.editor` is refused earlier, for the hook-running subcommands, by the hooks rule above)
HM_C_KEYS = re.compile(r'^(user\.(name|email)|commit\.gpgsign|tag\.gpgsign|core\.quotepath|color\.[a-z.]+|advice\.[a-z]+|'
                       r'init\.defaultbranch|diff\.(renames|algorithm|context)|merge\.(ff|conflictstyle)|pull\.(rebase|ff)|'
                       r'rebase\.autostash|credential\.[a-z0-9.:/@*_-]*(helper|usehttppath|interactive))$', re.I)
# `git config <key> <value>` that re-points a repo or redefines what a command runs
_HM_CONFIG_REPOINT = re.compile(r'^(core\.(worktree|bare|gitdir|hookspath|fsmonitor|editor|sshcommand|pager|askpass)|'
                                r'include\.path|includeif\..*|alias\..*|credential\..*|url\..*|safe\.directory|'
                                r'diff\.external|merge\..*\.driver|filter\..*|remote\..*\.(url|pushurl|push|mirror))$', re.I)
_HM_WT_PLAIN = {'-b', '-B', '--detach', '--orphan', '--lock', '--reason', '--no-checkout', '--checkout', '--quiet', '-q',
                '--track', '--no-track', '--guess-remote', '--no-guess-remote', 'add'}
_HM_CONFIG_WRITE_FLAGS = {'--add', '--replace-all', '--unset', '--unset-all', '--rename-section', '--remove-section', '-e',
                          '--edit'}
_HM_BRANCH_MOVE_LETTERS = set('mMcC')
_HM_BRANCH_NAME_LETTERS = set('dDf')
_HM_BRANCH_CONFIG_FLAGS = {'--set-upstream-to', '--unset-upstream', '--edit-description', '--track', '--no-track', '-u', '-t'}
_HM_BRANCH_LIST_FLAGS = {'-l', '--list', '-a', '--all', '-r', '--remotes', '--show-current', '--contains', '--merged',
                         '--no-merged', '--points-at', '--sort', '--format', '--column', '--no-column'}
_HM_CACHE = {}
_HM_NOCWD = object()
_HM_RAWLIT = re.compile(r'^[\w./+@%=,:~^-]+$')                      # no quote, escape, $, glob, brace, bracket, comment character
_HM_FLAGLIT = re.compile(r'^-[\w=./:@+,%~-]*$')
_HM_PREV = re.compile(r'^@\{-\d+\}$')
_HM_REDIR_ATT = re.compile(r'^(\d*|&)(>>?|<)[\w./-]+$')            # 2>file  &>file  >file  <file
_HM_REDIR_ALN = re.compile(r'^(\d*|&)(>>?|<)$')                    # 2>  >>  <      (the target is the NEXT word)
_HM_REDIR_DUP = re.compile(r'^\d*[<>]&\d+-?$')                      # 2>&1
_HM_REDIR_ANY = re.compile(r'^(\d*|&|\{[A-Za-z_]\w*\})(>>|<<<|<<|<>|>\||>&|<&|&>>|&>|>|<)$')   # any operator that takes the next word
_HM_RAW = {'words': [], 'bad': False}   # the typed words of the git call after its subcommand: redirections out, comment cut
_HM_TAIL = [False]                      # the git call is followed by a command substitution that supplies more words


def _hm_lit(word):
    """A TYPED word that is what git receives: no quote, escape, variable, substitution, glob, brace or empty expansion in it."""
    return bool(word) and _HM_RAWLIT.match(word) is not None


def _hm_strip(raw):
    """(words, bad): the typed words of a git call without the redirections and without a trailing comment. A redirection form
    outside a short whitelist (`>&`, `{fd}>`, `<<<`, `&>>f`...) is not understood: it is dropped, with the word it takes if it is
    an operator on its own, and `bad` says so."""
    out, bad, skip = [], False, False
    for w in raw:
        if skip:
            skip = False
            if not _hm_lit(w):
                bad = True
            continue
        if w.startswith('#'):                            # a comment: nothing after it is an argument
            break
        if _HM_REDIR_ATT.match(w) or _HM_REDIR_DUP.match(w):
            continue
        if _HM_REDIR_ALN.match(w):
            skip = True
            continue
        if _HM_REDIR_ANY.match(w):
            skip, bad = True, True
            continue
        if re.search(r'[<>&{}()|`]', w) and not _HM_PREV.match(w):
            bad = True                                   # an attached or unknown redirection / substitution piece
        out.append(w)
    return out, bad


def _hm_git(dirpath, *args):
    """stdout of `git -C dirpath args...` (stripped), or None on failure. Cached: the gate process judges one command."""
    key = (dirpath, args)
    if key in _HM_CACHE:
        return _HM_CACHE[key]
    import subprocess
    try:
        r = subprocess.run(['git', '-C', dirpath, '-c', 'core.fsmonitor=false'] + list(args), capture_output=True, text=True,
                           timeout=4)
        out = r.stdout.strip() if r.returncode == 0 else None
    except Exception:
        out = None
    _HM_CACHE[key] = out
    return out


def _hm_install_top():
    top = _hm_git(PROJECT_ROOT, 'rev-parse', '--show-toplevel')
    try:
        return os.path.realpath(top) if top else os.path.realpath(PROJECT_ROOT)
    except OSError:
        return PROJECT_ROOT


def _hm_loose(path, cwd, physical=False):
    """Absolute normalised path of a LITERAL path (relative to cwd); None when it is computed or cwd is unknown. It need not exist."""
    if not path or any(c in path for c in '$`*?[]{}()<>;&|!'):
        return None
    path = os.path.expanduser(path)
    if not os.path.isabs(path):
        if cwd is None:
            return None
        path = os.path.join(cwd, path)
    return _hm_phys(path) if physical else os.path.normpath(path)


def _hm_phys(path):
    """`path` (absolute) with every `..` taken AFTER the symlink before it is resolved: how the kernel (git -C) walks it, unlike
    os.path.normpath, which cuts `..` lexically."""
    cur = '/'
    for comp in path.split('/'):
        if comp in ('', '.'):
            continue
        cur = os.path.dirname(os.path.realpath(cur)) if comp == '..' else os.path.join(cur, comp)
    return cur


def _hm_real(path):
    """realpath of the nearest EXISTING ancestor, joined with the rest: where `path` would be once it exists."""
    rest = []
    cur = path
    while cur and not os.path.exists(cur):
        parent, name = os.path.split(cur)
        if parent == cur:
            break
        rest.append(name)
        cur = parent
    try:
        base = os.path.realpath(cur or '/')
    except OSError:
        return path
    return os.path.join(base, *reversed(rest)) if rest else base


def _hm_where(path):
    """Where a directory sits relative to the install's repo: 'main' (its main checkout), 'linked' (a linked worktree of it),
    'outside' (not in its work tree and not a worktree of it; includes a path that does not exist yet), 'norepo' (inside its
    work tree but in no repo), 'unknown' (inside its work tree, does not exist yet)."""
    real = _hm_real(path)
    inst = _hm_install_top()
    inside = real == inst or real.startswith(inst.rstrip(os.sep) + os.sep)
    exists = os.path.isdir(real)
    if not inside:
        if not exists:
            return 'outside'
        mine = _hm_git(real, 'rev-parse', '--path-format=absolute', '--git-common-dir')
        theirs = _hm_git(PROJECT_ROOT, 'rev-parse', '--path-format=absolute', '--git-common-dir')
        try:
            if mine and theirs and os.path.realpath(mine) == os.path.realpath(theirs):
                return _hm_linked(real)
        except OSError:
            return 'linked'
        return 'outside'
    if not exists:
        return 'unknown'
    top = _hm_git(real, 'rev-parse', '--show-toplevel')
    if top is None:
        return 'norepo'
    try:
        top = os.path.realpath(top)
    except OSError:
        return 'unknown'
    if top == inst:
        return 'main'
    mine = _hm_git(real, 'rev-parse', '--path-format=absolute', '--git-common-dir')
    theirs = _hm_git(PROJECT_ROOT, 'rev-parse', '--path-format=absolute', '--git-common-dir')
    try:
        return _hm_linked(real) if (mine and theirs and os.path.realpath(mine) == os.path.realpath(theirs)) else 'outside'
    except OSError:
        return 'linked'


def _hm_linked(real):
    """'linked' for a linked worktree of the install, but 'main' when its HEAD is the very branch the main checkout has checked
    out (a worktree that took that branch over, e.g. by `checkout --ignore-other-worktrees`, moves the live HEAD with every commit)."""
    head = _hm_git(real, 'symbolic-ref', '-q', 'HEAD')
    prot = _hm_git(PROJECT_ROOT, 'symbolic-ref', '-q', 'HEAD')
    return 'main' if head and prot and head == prot else 'linked'


_HM_SEG = ['']
_HM_LOSSY = [0]      # > 0 while a command is judged that was REBUILT from the literal words of an interpreter's argv list


def _hm_fail(why):
    block('git, sub-agent hivas: a kapu nem tudja BIZONYITANI, hogy ez nem mozgatja a telepites fo checkoutjanak HEAD-jet vagy '
          'ref-jeit (%s). Eles kodot csak a fo agens (%s) tehet a fara. Ha ez munka-worktree-ben fejlesztes: a cel legyen '
          'literalis (`cd <worktree> && git ...` egy lancban, vagy `git -C <worktree> ...`). Nem az ugynok (%s) dontese.\n'
          '(a hivas: %s)' % (why, _main_agent_id(), OWN_AGENT, _HM_SEG[0]))


def _hm_expand(word, lits):
    """`$NAME` / `${NAME}` that got ONE literal value on this command line is read with it; anything else comes back unchanged."""
    def one(m):
        v = lits.get(m.group(1) or m.group(2))
        return v if isinstance(v, str) and not re.search(r'[$`{]', v) else m.group(0)
    return re.sub(r'\$\{([A-Za-z_]\w*)\}|\$([A-Za-z_]\w*)', one, word)


def _hm_cd(toks, argstart, dirs, lits):
    """(dirs, fallback) after a `cd`: the possible working directories (a list of absolute paths, or None when the gate cannot
    follow it), and the OLD directories that stay possible if the `cd` FAILS (the target does not exist yet). The fallback only
    matters for a command that is not chained to the `cd` with `&&`: `cd X && git ...` does not run when the `cd` fails,
    `cd X; git ...` does."""
    if dirs is None:
        return None, []
    args = [t for t, _sp in toks[argstart:]]
    if not args:
        return [os.path.expanduser('~')], []
    if any(a.startswith('-') and a != '--' for a in args):
        return None, []                              # `cd -`, `cd -P`: not followed
    target = [a for a in args if a != '--']
    if len(target) != 1:
        return None, []
    word = _hm_expand(target[0], lits)
    out, fb = [], []
    for d in dirs:
        p = _hm_loose(word, d)
        if p is None:
            return None, []
        # A shell may be in physical mode (`set -P`, `set -o physical`, SHELLOPTS, an `eval`ed or sourced option, a shell started
        # with -P): `cd L/..` then lands at the parent of the link's TARGET, not of the link. Both places stay possible; the
        # call is allowed only if every one of them is clear of the install.
        out.extend([p, _hm_loose(word, d, physical=True)])
        if not (os.path.isdir(p) and os.access(p, os.R_OK | os.X_OK)):        # a cd can fail for more than a missing target
            fb.append(d)
    return sorted(set(out)), sorted(set(fb))


def _hm_parse(toks, argstart, dirs):
    """(dirs, sub, args): the possible target directories after `-C` (None when they cannot be proven), the subcommand, its words."""
    i = argstart
    while i < len(toks):
        t = _resolve_word(toks[i][0])
        if t == '-C' and _HM_LOSSY[0] and not (i + 1 < len(toks) and re.match(r'^[/~.]|/', toks[i + 1][0])):
            dirs = None              # the -C value may have been a variable, dropped from the rebuilt command: a next word that
            i += 1                   # is not path-shaped is the subcommand, not the directory (named limit: a bare dir name)
            continue
        if t == '-C':
            if i + 1 >= len(toks):
                _hm_fail('a -C kapcsolonak nincs erteke')
            if dirs is not None:
                nd = [_hm_loose(_resolve_word(toks[i + 1][0]), d, physical=True) for d in dirs]
                dirs = None if any(x is None for x in nd) else sorted(set(nd))
            i += 2
            continue
        if t == '-c':
            if i + 1 >= len(toks):
                _hm_fail('a -c kapcsolonak nincs erteke')
            kv = _resolve_word(toks[i + 1][0])
            if not (HM_C_KEYS.match(kv.split('=', 1)[0]) or _GIT_C_KEY_OK.match(kv.split('=', 1)[0])):
                _hm_fail('a -c %s kulcs nincs a zart listan (alias, hooksPath, worktree ... atirhatna a parancsot)'
                         % kv.split('=', 1)[0][:30])
            i += 2
            continue
        if t in HM_GLOBAL_FLAGS:
            i += 1
            continue
        if t in ('--version', '--help', '-h', '--html-path', '--man-path', '--info-path'):
            return dirs, 'version', []
        if t.startswith('-'):
            _hm_fail('ismeretlen vagy a celt atiro git-kapcsolo: %s' % t[:24])
        words, bad = _hm_strip([a for a, _sp in toks[i + 1:]])
        _HM_RAW['words'], _HM_RAW['bad'] = words, bad
        return dirs, t, [_resolve_word(a) for a in words]
    return dirs, None, []


def _hm_ref_names(names, dirs, what, fold=True, raws=()):
    """A ref NAME to write must not be the branch the main checkout has checked out, nor HEAD when the target is the main
    checkout. The refs of a linked worktree are SHARED with it; a foreign repo shares nothing, so nothing is screened there."""
    if _HM_LOSSY[0]:
        _hm_fail('%s egy ertelmezo argv-listajabol epitett parancsban: a nem literalis ref-nevek kiestek, nem lathatok' % what)
    kinds = ['unknown'] if dirs is None else [_hm_where(d) for d in dirs]
    if all(k in ('outside', 'norepo') for k in kinds):
        return
    # A ref name is only as good as the WORDS it came from: every positional word of the call must be a typed literal (or
    # `@{-N}`, resolved by the caller), and nothing may follow that a command substitution could supply.
    if _HM_TAIL[0]:
        _hm_fail('%s: a hivas utan $(...) / `...` kovetkezik, a szavai nem lathatok' % what)
    if _HM_RAW['bad']:
        _hm_fail('%s: a hivasban egy nem ertelmezett atiranyitas vagy behelyettesites van' % what)
    for w in _HM_RAW['words']:
        if w.startswith('-') and w != '-' and not _HM_FLAGLIT.match(w):
            _hm_fail('%s: nem literalis kapcsolo (%s)' % (what, w[:20]))
    for w in raws:                                       # the TYPED words the names came from (a path is not one of them)
        if not (w == '-' or _HM_PREV.match(w) or _hm_lit(w)):
            _hm_fail('%s: a ref neve nem literalis szobol jon (%s): idezet, escape, valtozo, glob, kapcsos zarojel vagy ures '
                     'kiterjesztes' % (what, w[:20]))
    in_main = any(k in ('main', 'unknown') for k in kinds)
    prot = _hm_git(PROJECT_ROOT, 'symbolic-ref', '-q', '--short', 'HEAD')    # None: detached, no branch to protect
    for n in names:
        if '..' in n:                                    # not a valid ref name; a path-like spelling of another ref is not provable
            _hm_fail('%s: a ref neve ".." tartalmaz (%s)' % (what, n[:30]))
        short = n[len('refs/heads/'):] if n.startswith('refs/heads/') else n[len('heads/'):] if fold and n.startswith('heads/') else n
        if prot is not None and short == prot:
            _hm_fail('%s a fo checkout kivett agara (%s)' % (what, prot))
        if in_main and n == 'HEAD':
            _hm_fail('%s HEAD a fo checkoutban' % what)


def _hm_prev_names(word, dirs, sub):
    """`-` and `@{-N}` name the PREVIOUS branch, which only the target's reflog knows: the names it resolves to (one per possible
    directory), [] when `word` is no such word. Unresolvable in a place that can matter = denied."""
    if not (word == '-' or _HM_PREV.match(word)):
        return []
    if dirs is None:
        _hm_fail('git %s %s: az elozo ag cel-konyvtara nem ismert' % (sub, word))
    kinds = [_hm_where(d) for d in dirs]
    names = []
    for d in dirs:
        out = _hm_git(d, 'rev-parse', '--abbrev-ref', '@{-1}' if word == '-' else word)
        if out is not None:
            names.append(out)
        elif any(k not in ('outside', 'norepo') for k in kinds):
            _hm_fail('git %s %s: az elozo ag nem feloldhato, nem bizonyithato, hogy nem a fo checkout aga' % (sub, word))
    return names


def _hm_move_target(dirs, sub):
    """The target of a call that moves a HEAD must be PROVEN not to be the install's main checkout."""
    if dirs is None:
        _hm_fail('git %s: a cel-konyvtar nem literalis (szamitott ut, ismeretlen cwd, vagy egy `cd` / pushd, amit a kapu nem kovet)'
                 % sub)
    for d in dirs:
        k = _hm_where(d)
        if k == 'main':
            _hm_fail('git %s a telepites FO checkoutjaban, vagy egy linkelt worktree-ben, amelynek a HEAD-je a fo checkout kivett aga (%s)'
                     % (sub, d))
        if k == 'unknown':
            _hm_fail('git %s: a cel (%s) a telepites fajan belul van, es meg nem letezik' % (sub, d))


def _hm_values(args, value_flags):
    """Positional words with the values of `value_flags` (and every dashed word) dropped."""
    out, skip = [], False
    for a in args:
        if skip:
            skip = False
            continue
        if a in value_flags:
            skip = True
            continue
        if a.startswith('-'):
            continue
        out.append(a)
    return out


def _head_move_gate(toks, argstart, cwd, cmd_idx=None, tail_subst=False):
    """Blocks (via block()) a sub-agent git call that is not provably clear of the install's main checkout HEAD and refs.
    `cwd` is the tracked working directory: a list of possible directories, one directory, or None (unknown)."""
    _HM_SEG[0] = ' '.join(w for w, _sp in toks[max(0, (cmd_idx or 0)):][:12])[:140]
    _HM_TAIL[0] = bool(tail_subst)
    _HM_RAW['words'], _HM_RAW['bad'] = [], False
    if isinstance(cwd, str):
        cwd = [os.path.normpath(cwd)]
    if cmd_idx and any(t == '-C' or t.startswith('--chdir') for t, _sp in toks[:cmd_idx]):
        cwd = None                                   # `env -C dir git ...`: the directory is not the tracked one
    dirs, sub, args = _hm_parse(toks, argstart, cwd)
    if sub is None or sub in HM_READ:
        return
    flags = [a for a in args if a.startswith('-')]
    pos = [a for a in args if not a.startswith('-')]
    rw = _HM_RAW['words']                                # the same words, as typed (len(rw) == len(args))
    rpos = [rw[i] for i, a in enumerate(args) if not a.startswith('-')]
    if sub == 'reflog':
        if pos and pos[0] not in ('show', 'list', 'exists'):
            _hm_fail('git reflog %s' % pos[0][:12])
        return
    if sub == 'config':
        keys = [a for a in pos if re.match(r'^[A-Za-z][\w-]*(\.[\w*-]+)+$', a)]
        writing = len(pos) >= 2 or any(f in _HM_CONFIG_WRITE_FLAGS for f in flags)
        if keys and writing and _HM_CONFIG_REPOINT.match(keys[0]):
            _hm_fail('git config %s: a repo ujracelzasa vagy egy parancs felulirasa' % keys[0][:30])
        return
    if sub == 'worktree':
        for k, f in enumerate(args):
            if f in ('-b', '-B'):
                _hm_ref_names(args[k + 1:k + 2], dirs, 'worktree add %s' % f, raws=rw[k + 1:k + 2])
        if args[:1] == ['add']:
            # Without --force git itself refuses a branch that is checked out elsewhere (measured, git 2.53). So the branch
            # `worktree add` will take matters only if the call is not PROVABLY unforced: the flags are checked against a closed
            # list, and anything else (`--forc`, `--for`, `-f`, `-ff`, an unknown option) counts as forced.
            unforced = all(f in _HM_WT_PLAIN or f.startswith('--reason=') for f in flags)
            vals, skip = [], False
            for a in args:
                if skip:
                    skip = False
                elif a in ('-b', '-B', '--reason'):
                    skip = True
                elif a == '-' or not a.startswith('-'):
                    vals.append(a)
            made = any(f in ('-b', '-B', '--detach', '--orphan') for f in flags)
            if not unforced and not made and len(vals) > 1:
                cand = vals[2] if len(vals) > 2 else os.path.basename(vals[1].rstrip('/'))
                # under --force EVERY typed positional word counts: one that expands to nothing shifts the others
                _hm_ref_names(_hm_prev_names(cand, dirs, 'worktree add') or [cand], dirs, 'worktree add <ag>', fold=False,
                              raws=[w for i, w in enumerate(rw) if args[i] == '-' or not args[i].startswith('-')])
        return
    if sub == 'push':
        remote = pos[0] if pos else ''
        if remote in ('.', './') or (os.path.isabs(remote) and os.path.isdir(remote)) or remote.startswith(('../', './')):
            _hm_fail('git push egy HELYI repora (%s): masik repo ref-jeinek irasa' % remote[:30])
        return
    if sub == 'fetch':
        for spec in pos[1:]:
            if ':' in spec:
                rdst = rpos[1 + pos[1:].index(spec)].split(':', 1)[1].lstrip('+')
                if rdst.startswith(('refs/remotes/', 'refs/tags/')) and '..' not in rdst:
                    continue                                 # a literal prefix that cannot become refs/heads/<name>, whatever follows it
                _hm_ref_names([spec.split(':', 1)[1].lstrip('+')], dirs, 'fetch cel-ref', raws=[rdst])
        return
    if sub == 'stash':
        if pos[:1] == ['branch']:
            _hm_move_target(dirs, 'stash branch')
            _hm_ref_names(pos[1:2], dirs, 'stash branch', raws=rpos[1:2])
        return
    if sub in HM_NOMOVE:
        return
    if sub not in HM_MOVE:
        _hm_fail('ismeretlen alparancs: git %s' % sub[:20])
    # ---- ref-writing subcommands
    if sub in ('update-ref', 'symbolic-ref'):
        if sub == 'symbolic-ref' and len(_hm_values(args, {'-m'})) < 2 and not any(f in ('-d', '--delete') for f in flags):
            return                                   # `git symbolic-ref [--short] HEAD` only READS
        if '--stdin' in flags:
            _hm_fail('git %s --stdin: a ref-nevek nem lathatok' % sub)
        _hm_ref_names(_hm_values(args, {'-m'})[:2], dirs, sub,       # symbolic-ref: HEAD AND the ref it is pointed at
                      raws=_hm_values(rw, {'-m'})[:2])
        return
    if sub == 'branch':
        letters = set()
        for f in flags:
            if not f.startswith('--'):
                letters |= set(f[1:])
        long_move = any(f in ('--move', '--copy') for f in flags)
        long_name = any(f in ('--delete', '--force') for f in flags)
        if letters & _HM_BRANCH_MOVE_LETTERS or long_move:           # rename / copy: moves the branch the target has checked out
            _hm_move_target(dirs, 'branch %s' % ' '.join(flags)[:12])
            _hm_ref_names(pos, dirs, 'branch', raws=rpos)
            return
        if letters & _HM_BRANCH_NAME_LETTERS or long_name:           # delete / force: names only
            deleting = bool(letters & set('dD')) or '--delete' in flags
            n = len(pos) if deleting else 1                          # delete: every word is a name; `-f <name> <start>`: the first
            _hm_ref_names(pos[:n], dirs, 'branch', raws=rpos[:n])
            return
        if any(f.split('=', 1)[0] in _HM_BRANCH_CONFIG_FLAGS for f in flags):
            return
        if any(f.split('=', 1)[0] in _HM_BRANCH_LIST_FLAGS for f in flags) or not pos:
            return
        _hm_ref_names(pos[:1], dirs, 'branch', raws=rpos[:1])        # `git branch <name> [<start>]`: create
        return
    # ---- ref-moving subcommands: the target must be proven
    _hm_move_target(dirs, sub)
    if sub in ('checkout', 'switch'):
        made = any(f in ('-b', '-B', '-c', '-C', '--orphan') or re.match(r'^-[A-Za-z]*[bBcC]$', f) for f in flags)
        rawall = _HM_RAW['words']
        upto = args[:args.index('--')] if '--' in args else args
        after = rawall[rawall.index('--') + 1:] if '--' in rawall else []
        # `checkout <ref> -- <path>...` restores files and changes no branch. That needs at least one TYPED literal path after the
        # `--` (redirections and a trailing comment are already out): an empty list, a variable, a glob that may match nothing, a
        # quoted or escaped word leaves `checkout main --` a branch switch.
        restores_paths = any(not a.startswith('-') for a in upto) and any(_hm_lit(w) for w in after)
        if not made and not restores_paths and not any(f in ('--detach', '-d') for f in flags):
            picks = [a for a in upto if not a.startswith('-')][:1]
            for a in upto:
                picks += _hm_prev_names(a, dirs, sub)
            # the branch is the FIRST positional word: it must be typed literally (`$NOPE main` would make `main` the branch)
            first = [rw[i] for i, a in enumerate(upto) if a == '-' or not a.startswith('-')][:1]
            _hm_ref_names(picks, dirs, '%s <ag>' % sub, fold=False, raws=first)    # taking the branch over
        for k, f in enumerate(args):
            if f in ('-b', '-B', '-c', '-C', '--orphan') or re.match(r'^-[A-Za-z]*[bBcC]$', f):
                _hm_ref_names(args[k + 1:k + 2], dirs, '%s %s' % (sub, f), raws=rw[k + 1:k + 2])
    elif sub == 'filter-branch':
        _hm_fail('git filter-branch: minden helyi agat atirhat, a kivettet is')
    elif sub == 'replace':
        _hm_fail('git replace: objektumot cserel')


def _hm_raw_toks(cmd, text, seg_pos, seg0):
    """(tokens, argstart, cmd_idx) of the segment as TYPED (quoted words intact), for the git word of the segment; None when the
    typed text cannot be lined up with the scanned one (then the scanned tokens are used)."""
    if len(cmd) != len(text) or text[seg_pos:seg_pos + len(seg0)] != seg0:
        return None
    raw = _bare_tokens(cmd[seg_pos:seg_pos + len(seg0)])
    idx = command_index(raw)
    if idx is None or raw[idx][1] or os.path.basename(raw[idx][0]) != 'git':
        return None
    return raw, idx + 1, idx


def _check_git(toks, argstart, cwd=None, cmd_idx=None, in_code=False, tail_subst=False, hm_cwd=_HM_NOCWD, hm_raw=None):
    """git push: nem tiltott onmagaban (PR #1357), de harom alakja igen.

    Amit a kapu MEGTART: a tortenet ujrairasat (--force es tarsai, '+' refspec), a
    tavoli ref torleset, es a vedett agakra (main/master) iranyulo push-t. Ezek
    kifele mutatnak es mas munkajat is elvihetik -- ezt nem egy agens donti el.
    Amit ELENGED: a sajat munkaag push-a, ami eddig is a munka resze volt, csak
    jovahagyason keresztul.
    """
    _hooks_tamper_git(toks, argstart)
    _git_config_programs(toks, argstart, in_code)
    if OWN_AGENT is not None and not in_code:
        if hm_raw is not None:
            toks, argstart, cmd_idx = hm_raw
        _head_move_gate(toks, argstart, cwd if hm_cwd is _HM_NOCWD else hm_cwd, cmd_idx, tail_subst)
    hooked = _git_hook_class(toks, argstart, cmd_idx, in_code, tail_subst)
    pi = _git_push_index(toks, argstart)
    if pi is None:
        if hooked and hooked[0] != 'push':
            _effective_hooks_path(toks, argstart, hooked[1], cwd, cmd_idx, hooked[0])
        return
    _effective_hooks_path(toks, argstart, pi, cwd, cmd_idx)
    args, skip = [], 0
    for tok, _sp in toks[pi + 1:]:
        if skip:
            skip -= 1
            continue
        if tok in PUSH_VALUE_FLAGS:
            skip = 1
            continue
        args.append(tok)
    flags = [a for a in args if a.startswith('-')]
    positional = [a for a in args if not a.startswith('-')]

    # A push-ellenorzo kapuk (pre-push.d: force-guard, szemelyes-adat kapu) git hookok;
    # a hookot kikapcsolo alak egy ugynok kezeben a kapu kikapcsolasa lenne. A szoveg-szintu
    # tiltas csak az ugynok sajat hivasait fogja; a hook maga (git-szint) minden egyeb alakot lat.
    # Mindketto kell. (A core.hooksPath-t a _hooks_tamper_git mar elbiralta.)
    for f in flags:
        base = f.split('=', 1)[0]
        resolved = _resolve_push_long(f) if f.startswith('--') else None
        if resolved == 'no-verify':
            block('git push %s: a pre-push kapukat (force-guard, szemelyes-adat kapu) '
                  'kihagyo kapcsolo. Nem az ugynok dontese; javitsd a talalatot.' % f[:20])
        # Egybeirt rovid kapcsolok (`-fu`, `-df`): a kapcsolo-csomag barmelyik betuje szamit.
        if (not f.startswith('--') and len(base) > 2 and not base.startswith('-o')
                and ('f' in base[1:] or 'd' in base[1:])):
            block('git push %s: egybeirt rovid kapcsolo, amelyben -f (eroltetett) vagy -d '
                  '(torles) van. Sima push szabad, eroltetett/torlo nem.' % base[:12])
        if resolved in ('force', 'force-with-lease', 'force-if-includes', 'mirror') \
                or base in PUSH_FORCE_FLAGS:
            block('git push %s: a tavoli tortenet ujrairasa mas munkajat is elviheti. '
                  'Sima push szabad, eroltetett nem.' % base)
        if resolved in ('delete', 'prune') or base in PUSH_DELETE_FLAGS:
            block('git push %s: tavoli ag torlese. A torles nem az agens dontese.' % base)
        if resolved == 'all' or base == '--all':
            block('git push --all: minden agat kitolja, a vedetteket is. '
                  'Nevezd meg, melyik agra pusholsz.')

    refspecs = positional[1:]          # az elso pozicionalis a remote (vagy URL)
    if not refspecs:
        block('git push cel-ag nelkul: a kapu nem tudja eldonteni, melyik agra menne '
              '(az upstream nem latszik a parancsbol). Nevezd meg: '
              'git push <remote> HEAD:<ag>.')
    for spec in refspecs:
        # Az ures forras-refspec (`:ag`) ugyanaz a muvelet, mint a --delete: torli a
        # tavoli agat. 2026-09-24-en merve, a szabaly atvitelekor: a kapcsolos alakot
        # tiltotta, a ketpontosat atengedte. Ugyanaz a dontes, ugyanaz a verdikt.
        if spec.startswith(':') or spec.startswith('+:'):
            block('git push %s: ures forras-refspec, azaz tavoli ag torlese. '
                  'A torles nem az agens dontese.' % spec[:40])
        if spec.startswith('+'):
            block('git push +%s: a "+" eloterjesztes eroltetett push. '
                  'Eroltetett push nem az agens dontese.' % spec[1:][:40])
        dest = spec.split(':', 1)[1] if ':' in spec else spec
        if dest.rsplit('/', 1)[-1] in PROTECTED_BRANCHES and not dest.startswith('refs/tags/'):
            block('git push a(z) "%s" agra: vedett ag, ide review-n keresztul megy '
                  'valami. Pusholj sajat munkaagra.' % dest)


# A lathatosag-valtas (privat -> publikus) a repo TELJES tortenetet kiteszi, nem egy
# push-nyi valtoztatast. A push-kapu (szemelyes-adat) csak azt latja, ami egy pushban
# megy ki; a valtas utan mar az egesz regi tortenet nyilvanos. Ezert a valtas maga
# nem az ugynok dontese (013b1bb9, owner 4181). A "privatra" valtas biztonsagos irany,
# az atmegy. A PUBLIKUS letrehozas ugyanez: uj, mar nyilvanos repo.
GH_PUBLIC_VALUES = {'public', 'internal'}
# Kapcsolok, amelyek erteke KULON szoban all: kulonben az ertek (PATCH, a mezo) pozicionalis
# szonak latszana, es a `gh api <ut>` utat eltolna.
GH_VALUE_FLAGS = {'-R', '--repo', '--hostname', '-X', '--method', '-f', '-F', '--field',
                  '--raw-field', '-H', '--header', '--input', '--jq', '-q', '--template',
                  '-t', '--cache'}
GH_FIELD_FLAGS = {'-f', '-F', '--field', '--raw-field'}
_VIS_FIELD = re.compile(r'(^|[&\s])(private\s*=\s*false|visibility\s*=\s*(public|internal))\b', re.I)


# GitHub API paths that move or protect a ref without git (HEX 3809): git/refs..., branch protection, rulesets
_GH_REF_PATH = re.compile(r'^repos/[^/]+/[^/]+/(?:git/refs(?:/|$)|branches/.+/protection(?:/|$)|rulesets(?:/|$))', re.I)
_GH_REF_MUTATION = re.compile(r'\b(?:createRef|updateRef|deleteRef|mergeBranch|createCommitOnBranch|updateBranchProtectionRule|createBranchProtectionRule)\b')


def _flag_value(args, name):
    """A kapcsolo erteke (`--x v` vagy `--x=v`), vagy None, ha a kapcsolo nincs jelen."""
    for k, a in enumerate(args):
        if a == name:
            return args[k + 1] if k + 1 < len(args) else ''
        if a.startswith(name + '='):
            return a.split('=', 1)[1]
    return None


_DASHED_GIT = re.compile(r'^git-([a-z][a-z0-9-]*)$')


def _dashed_git_sub(word):
    """`git-send-pack`, `/usr/lib/git-core/git-http-push`, `./git-commit`: the dashed form of a git builtin is the subcommand itself
    (Sam round 2, SEVERE 4: the dashed send-pack sent a forced update with no pre-push hook). The directory does not matter."""
    m = _DASHED_GIT.match(os.path.basename(word))
    return m.group(1) if m and m.group(1) in _GIT_BUILTINS else None


def _check_gh(toks, argstart):
    raw = [t for t, _sp in toks[argstart:]]
    # Az egybeirt rovid kapcsolo (`-XPATCH`, `-Fprivate=false`, `-X=PATCH`) ugyanaz, mint a
    # kulon szavas: a pflag igy is elfogadja (tipp, gh-val nem futtattam), a kapu pedig ne.
    args = []
    for a in raw:
        m = re.match(r'^(-[XfFHqt])=?(.+)$', a)
        if m and not a.startswith('--'):
            args.extend([m.group(1), m.group(2)])
        else:
            args.append(a)
    words, skip = [], False
    for a in args:
        if skip:
            skip = False
            continue
        if a in GH_VALUE_FLAGS:
            skip = True
            continue
        if a.startswith('-'):
            continue
        words.append(a)

    if words[:2] == ['repo', 'edit']:
        vis = _flag_value(args, '--visibility')
        if vis is not None:
            v = vis.strip().lower()
            if v in GH_PUBLIC_VALUES or not v or any(c in v for c in RM_UNRESOLVABLE):
                block('gh repo edit --visibility %s: a lathatosag-valtas a repo teljes '
                      'tortenetet kiteszi. Nem az ugynok dontese.' % (vis[:20] or '(ures)'))
        return
    if words[:2] == ['repo', 'create']:
        if '--public' in args or '--internal' in args:
            block('gh repo create --public/--internal: uj, azonnal nyilvanos repo. '
                  'Nem az ugynok dontese; privatkent szabad.')
        return
    if words[:1] == ['api'] and len(words) >= 2:
        path = words[1].lstrip('/')
        method = _flag_value(args, '-X')
        if method is None:
            method = _flag_value(args, '--method')
        fields = [args[k + 1] for k, a in enumerate(args[:-1]) if a in GH_FIELD_FLAGS]
        fields += [a.split('=', 1)[1] for a in args
                   if a.startswith(('--field=', '--raw-field='))]
        has_input = _flag_value(args, '--input') is not None
        if method is None:
            method = 'POST' if (fields or has_input) else 'GET'
        if path.lower() == 'graphql' and (_GH_REF_MUTATION.search(_RAW_CMD) or has_input or any(f.startswith('query=@') for f in fields)):
            # the query text is read from the command as typed (a quoted value with spaces is blanked in the tokens); a query the gate
            # cannot read (--input, query=@file) is not provable, so it is a deny
            block('gh api graphql: ref-iro mutacio (createRef/updateRef/deleteRef/mergeBranch/createCommitOnBranch), vagy olyan lekerdezes, '
                  'amelynek a szoveget a kapu nem latja (--input, query=@fajl): a git pre-push kapukat kihagyhatja. Nem az ugynok dontese.')
        if method.upper() != 'GET' and _GH_REF_PATH.match(path):
            block('gh api %s %s: a GitHub ref-/vedelem-API irasa a git pre-push kapukat (force-guard, szemelyes-adat, Sam-green, identitas) '
                  'kihagyja, force-szal is. Olvasas (GET, mezo nelkul) szabad. Nem az ugynok dontese.' % (method.upper(), path[:50]))
        if method.upper() == 'GET':
            return
        if re.match(r'^repos/[^/]+/[^/]+/?$', path):
            if has_input:
                block('gh api %s %s --input: a torzset a kapu nem latja, es ez a vegpont '
                      'a repo lathatosagat is allitja. Mezokkel (-f) add meg.' % (method, path[:40]))
            for f in fields:
                if _VIS_FIELD.search(f):
                    block('gh api %s %s: lathatosag-valtas (publikus/internal). '
                          'Nem az ugynok dontese.' % (method, path[:40]))


# --- Az ERTELMEZO-PAYLOAD belseje (efccadab) ---------------------------------
# Istvan jovahagyta 2026-09-21 04:01, a lean-chief eloterjesztesere. A kapu eddig a
# PARANCSNEVET es az UTVONAL-MINTAT nezte; ha ugyanaz a torles egy `python3 -c`
# egysoron vagy egy `python3 - <<PY` torzsben allt, a kapu nem latott bele. A modul
# fejlece ezt 2026-09-20 ota ISMERT es NYITOTT resként nevezi meg -- ez a szakasz
# zarja be.
#
# A SCOPE-OT A JOVAHAGYAS SZABTA MEG, es szandekosan szuk: "ne vezess be uj
# tiltasokat azon tul, amit a kapu ma is tilt. A cel ugyanaz a szabalykeszlet, csak
# az interpreter-burok mogott is." Ezert a tabla minden sora egy MA IS TILTOTT
# parancs megfeleloje, es a sor ki is mondja, MELYIKE:
#     os.remove / shutil.rmtree / fs.unlinkSync / File.delete ...  ->  rm
#     os.rename / shutil.move  / fs.renameSync  / FileUtils.mv ...  ->  mv
# Ami ma NEM tiltott, az itt sem lesz az. Kifejezetten KIMARAD, noha a 2026-09-20-as
# probaban atment es kezenfekvo volna felvenni:
#     open(f,'w')      csonkitas -- a `: > fajl` alak ma is atmegy, tehat nem szabaly
#     sqlite3 DELETE   DB-tartalom -- a kapu sosem nezett SQL-t
#     urllib POST      kifele iranyulo forgalom -- az az egress-deny dolga, mas kapu
#     .ssh ut darabolt osszefuzessel -- obfuszkacio, kulon dontes kell hozza
# Ez nem feledekenyseg: mindegyik UJ tiltas volna, es a kartya kifejezetten tiltja.
#
# A shell-kihivast (os.system, subprocess, child_process, Ruby backtick...) NEM kulon
# szabalylistaval kezeljuk, hanem VISSZAVEZETJUK a check_bash-re. Igy a burkon beluli
# parancsra pontosan ugyanaz a szabalykeszlet all, es nem keletkezik egy masodik,
# lassan elkulonbozo lista. Ez a kartya kovetelmenyenek szo szerinti alakja.
_PAYLOAD_RULES = (
    # (minta, a ma is tiltott parancs, amelynek ez a megfeleloje)
    (r'\bos\.(remove|unlink|rmdir|removedirs)\s*\(',            'rm'),
    (r'\bshutil\.rmtree\s*\(',                                  'rm'),
    (r'\bos\.(rename|renames|replace)\s*\(',                    'mv'),
    (r'\bshutil\.(move|copyfile)\s*\(',                         'mv'),
    (r'\.unlink\s*\(',                                          'rm'),   # pathlib.Path
    (r'\bPath\([^)]*\)\.(rmdir|rename|replace)\s*\(',           'mv'),
    # Node. A `Sync` vegu nevek maguktol is egyertelmuek, ezert NEM kerul ele
    # pont-tilto elonezet: a leggyakoribb alak `require('fs').rmSync(...)`, ahol a
    # nevet epp egy pont elozi meg. Merve: pont-tiltassal mind a harom node-alak
    # atment a kapun. A pont NELKULI nevek (`rm`, `unlink`, `rename`) tul altalanosak,
    # azok tovabbra is megnevezett fs-objektumot vagy require-t kernek.
    (r'(?<![\w$])(?:rmSync|unlinkSync|rmdirSync)\s*\(',          'rm'),
    (r'(?<![\w$])renameSync\s*\(',                               'mv'),
    (r'\b(?:fs|fsp|fsPromises)\.(?:promises\.)?(?:rm|unlink|rmdir)\s*\(', 'rm'),
    (r'\b(?:fs|fsp|fsPromises)\.(?:promises\.)?rename\s*\(',    'mv'),
    (r'require\(\s*[\'"]fs(?:/promises)?[\'"]\s*\)\s*\.\s*(?:rm|unlink|rmdir)\s*\(', 'rm'),
    (r'require\(\s*[\'"]fs(?:/promises)?[\'"]\s*\)\s*\.\s*rename\s*\(', 'mv'),
    (r'\bDeno\.(?:remove|removeSync)\s*\(',                     'rm'),   # INTERPFLAG v2: deno eval
    (r'\bDeno\.(?:rename|renameSync)\s*\(',                     'mv'),
    (r'\bFile(?:Utils)?\.(delete|unlink|rm|rm_r|rm_rf|remove_entry|remove_entry_secure)\b', 'rm'),
    (r'\bDir\.(delete|rmdir|unlink)\b',                         'rm'),
    (r'\bFile(?:Utils)?\.(rename|mv|move)\b',                   'mv'),
    (r'\b(rmtree|remove_tree)\s*\(',                            'rm'),   # Perl File::Path
    (r'(?<![\w.])unlink\s*\(',                                  'rm'),   # Perl builtin
    (r'(?<![\w.])rename\s*\(',                                  'mv'),   # Perl builtin
)
_PAYLOAD_RE = tuple((re.compile(p), c) for p, c in _PAYLOAD_RULES)

# the word git inside a payload (a quoted element of an argv list, a shell string, a spawn call), and the ways an interpreter hands a
# child an environment other than its own, or edits its own before the child starts (python, node, ruby, perl).
_PAYLOAD_GIT = re.compile(r"""(?<![\w./-])git(?![\w-])""")
_PAYLOAD_ENV = re.compile(
    r"""(?:\benv\s*=(?!=)|\benv\s*:"""
    r"""|\bos\.environ\s*(?:\.(?:clear|pop|popitem|update|setdefault)\b|\[[^\]]*\]\s*(?:\+|-)?=(?!=)|=(?!=))|\bdel\s+os\.environ\b"""
    r"""|\bos\.(?:putenv|unsetenv|execv\w*e|execl\w*e|spawn\w*e|posix_spawnp?)\b"""
    r"""|\bprocess\.env\s*=(?!=)|\bprocess\.env(?:\.\w+|\[[^\]]*\])\s*(?:\|\||\?\?)?=(?!=)|\bdelete\s+process\.env\b|\bexecve\b|\bspawnve\b"""
    r"""|\bsetenv\b|\bputenv\b|\bunsetenv\b|\$ENV\s*\{[^}]*\}\s*=(?!=)|%ENV\s*=(?!=)|\blocal\s+%ENV\b|\bENV\s*(?:\[[^\]]*\]\s*=(?!=)|\.(?:clear|delete|update|replace)\b)|\bclear_env\b)""")

# Ahonnan a payload SHELLT hiv. A zarojeles argumentumbol kiszedjuk a
# karakterlanc-literalokat, szokozzel osszefuzzuk, es visszaadjuk a check_bash-nek.
# A lista-alak (`subprocess.run(['rm','-rf',p])`) igy "rm -rf" lesz -- a parancsnev
# az ELSO szo marad, tehat a meglevo felismeres valtozatlanul all ra.
_SHELLOUT_RE = re.compile(
    # Ket elonezet-osztaly, szandekosan kulon. A megkulonboztetheto nevek (`execSync`,
    # `spawnSync`, `execFileSync`) elott allhat pont -- `require('child_process').execSync`
    # a leggyakoribb node-alak, es a pont-tilto elonezet EPP ezt engedte at (merve).
    # A puszta `system`, `exec`, `qx` viszont tul altalanos: azok elott a pont-tiltas marad,
    # kulonben minden `foo.exec(` talalat lenne.
    r'(?:(?<![\w$])(?:execSync|spawnSync|execFileSync)|'
    r'require\(\s*[\'"]child_process[\'"]\s*\)\s*\.\s*'
    r'(?:exec|execFile|spawn|execSync|execFileSync|spawnSync)|'
    r'(?<![\w.])(?:Deno\.Command|Bun\.(?:spawn|spawnSync)|os\.system|os\.popen|os\.exec[lv]?[pe]*|subprocess\.(?:run|call|'
    r'check_call|check_output|Popen|getoutput)|child_process\.(?:exec|execSync|'
    r'execFile|execFileSync|spawn|spawnSync)|IO\.popen|'
    r'Open3\.(?:capture2|capture3|popen3)|system|exec|qx))\s*\(')
_STR_LIT_RE = re.compile(r"(['\"])((?:\\.|(?!\1).)*)\1")


def _balanced_arg(text, open_idx):
    """A nyito zarojeltol a hozza tartozo zarojelig terjedo szoveg. Ha nincs parja
    (csonka payload), a szoveg vegeig -- egy le nem zart hivast nem engedunk at
    csak azert, mert elgepeltek."""
    depth, i = 0, open_idx
    while i < len(text):
        if text[i] == '(':
            depth += 1
        elif text[i] == ')':
            depth -= 1
            if depth == 0:
                return text[open_idx + 1:i]
        i += 1
    return text[open_idx + 1:]


def interpreter_payloads(cmd):
    """Minden szovegdarab, amit egy ERTELMEZO fog vegrehajtani.

    Harom forras, mind a harom a kartyan nevesitve:
      1. `-c` / `-e` / `-E` / `-p` utani idezett szkript,
      2. az ertelmezonek adott heredoc TORZSE (`python3 - <<PY`), amit a
         _heredoc_body_ranges mar ma is megkulonboztet az adat-heredoctol,
      3. a `-` STDIN-alak csovon at (`echo "..." | python3 -`): ilyenkor az ELOZO
         csoszakasz idezett szovegei a kod. A prozaszures kulonben pont ezeket
         mosna ki, mert szokozt tartalmaznak.
    A kommentsorok es az ADAT-heredocok itt is ki vannak fehérítve, mielott
    barmit kinyernenk: egy kikommentezett sor a payloadon belul sem fut le.
    """
    data, code = _heredoc_body_ranges(cmd)
    text = _blank_ranges(cmd, data)
    text = _blank_ranges(text, _comment_ranges(text, code))
    out = [text[a:b] for a, b in code]
    out += [text[a:b] for a, b in _script_arg_ranges(text)]
    out += [text[a:b] for a, b, _sh in _stdin_pipe_ranges(text)]
    # A MASIK ertelmezo heredoc-torzsenek belseje mar egeszben payload (fent): az abban idezett
    # `bash <<< ...` szoveg nem a shell programja, es a torzsben a kapu idezojel-terkepe nem megbizhato.
    text_nf = _blank_ranges(text, _foreign_code_ranges(cmd))
    out += [code for code, sh in _stdin_program_sources(text_nf) if not sh]
    return [p for p in (_strip_comment_lines(q) for q in out) if p.strip()]


class _SubstUnprovable(Exception):
    """A double-quoted region whose command substitutions the scanner cannot cut out with certainty (f4649c5d)."""


def _skip_sq(text, i):
    j = text.find("'", i)
    if j < 0:
        raise _SubstUnprovable("unclosed single quote")
    return j + 1


def _skip_ansi(text, i):
    n = len(text)
    while i < n:
        if text[i] == "\\":
            i += 2
            continue
        if text[i] == "'":
            return i + 1
        i += 1
    raise _SubstUnprovable("unclosed $'...' quote")


def _backtick_end(text, i):
    """Index of the closing backtick of the one opened at i - 1 (i = first content character)."""
    n = len(text)
    j = i
    while j < n and text[j] != "`":
        if text[j] == "\\":
            if j + 1 < n and text[j + 1] == "`":
                raise _SubstUnprovable("nested backticks")
            j += 2
            continue
        j += 1
    if j >= n:
        raise _SubstUnprovable("unclosed backtick")
    return j


def _subst_end(text, i):
    """Index of the ) that closes the $( whose content starts at i. Quote-aware, parenthesis-counting."""
    depth, n = 1, len(text)
    while i < n:
        ch = text[i]
        if ch == "\\":
            i += 2
            continue
        if ch == "'":
            i = _skip_sq(text, i + 1)
            continue
        if ch == '"':
            i = _scan_dq(text, i + 1, [])
            continue
        if ch == "`":
            i = _backtick_end(text, i + 1) + 1
            continue
        if ch == "$" and text.startswith("$'", i):
            i = _skip_ansi(text, i + 2)
            continue
        if ch == "#" and (i == 0 or text[i - 1] in " \t\n;|&("):
            j = text.find("\n", i)
            i = n if j < 0 else j
            continue
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    raise _SubstUnprovable("unclosed $(")


def _brace_end(text, i):
    """Index of the } that closes the ${ whose content starts at i; a quote inside it is not cut out with certainty."""
    depth, n = 1, len(text)
    while i < n:
        ch = text[i]
        if ch in "'\"":
            raise _SubstUnprovable("a quote inside ${...}")
        if ch == "\\":
            i += 2
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    raise _SubstUnprovable("unclosed ${")


def _scan_dq(text, i, out, region=False):
    """Walk double-quoted content starting at i (just after the opening quote), appending the program text of every command
    substitution to `out`; return the index after the closing quote (`region`: the content runs to the end of text)."""
    n = len(text)
    while i < n:
        ch = text[i]
        if ch == "\\":
            i += 2
            continue
        if ch == '"' and not region:
            return i + 1
        if ch == "`":
            j = _backtick_end(text, i + 1)
            out.append(text[i + 1:j])
            i = j + 1
            continue
        if ch == "$" and text.startswith("$(", i):
            e = _subst_end(text, i + 2)
            body = text[i + 2:e]
            if re.search(r"(^|[\s;&|(])case\s", body):
                raise _SubstUnprovable("a case statement inside $(...)")
            out.append(body)
            i = e + 1
            continue
        if ch == "$" and text.startswith("${", i):
            e = _brace_end(text, i + 2)
            _scan_dq(text[i + 2:e], 0, out, True)
            i = e + 1
            continue
        i += 1
    if region:
        return n
    raise _SubstUnprovable("unclosed double quote")


def dq_subst_programs(cmd):
    """The shell programs that run INSIDE double quotes: the content of every `$(...)` and `...` in a "..." (also `${X:-$(...)}` and
    `$(( $(...) ))` in one). The shell expands them before the command it quoted them for runs, so each is a command line of its
    own for check_bash (f4649c5d: `X="$(rm -rf <dir>)"` and `echo "`rm ...`"` went through, the same without the quotes was
    denied). A single-quoted string is literal and is not entered. A double-quoted region whose substitutions cannot be cut out
    with certainty (an unclosed one, nested backticks, a quote inside ${...}, a case statement inside $(...)) is not guessed at:
    the whole command is denied."""
    data, _code = _heredoc_body_ranges(cmd)  # (a `<<WORD` in a quote or a comment is not an opener there: see _opener_is_real)
    text = _blank_ranges(cmd, data)
    text = _blank_ranges(text, _comment_ranges(text, _code))
    text = _blank_ranges(text, _foreign_code_ranges(cmd))
    out = []
    try:
        i, n = 0, len(text)
        while i < n:
            ch = text[i]
            if ch == "\\":
                i += 2
                continue
            if ch == "'":
                i = _skip_sq(text, i + 1)
                continue
            if ch == "$" and text.startswith("$'", i):
                i = _skip_ansi(text, i + 2)
                continue
            if ch == '"':  # (`$"..."` reaches this branch on its `"`; the `$` is an ordinary character)
                i = _scan_dq(text, i + 1, out)
                continue
            i += 1
        # The body of a heredoc with an UNQUOTED delimiter (`<<EOF`, also fed to python3 / bash) is expanded by the shell exactly like a
        # double-quoted string: its `$(...)` and backticks RUN (Sam 4157, H1-H3, V7/M7). A quoted delimiter (`<<'EOF'`, `<<"EOF"`) keeps
        # the body literal. The body is walked in region mode (a `"` inside it is an ordinary character).
        for _i, _j, m, a, b in _heredocs(cmd):
            if not m.group(1):
                _scan_dq(cmd[a:b], 0, out, True)
    except _SubstUnprovable as exc:
        block('Idezojelen belul allo parancs-behelyettesites, amit a kapu nem tud biztosan kivagni (%s): a $(...) vagy `...` '
              'tartalma FUT, ezert vizsgalat nelkul nem engedhetem at. Nem az ugynok dontese.' % exc)
    return [p for p in out if p.strip()]


_PE_SIMPLE = {'a': 7, 'b': 8, 'e': 27, 'E': 27, 'f': 12, 'n': 10, 'r': 13, 't': 9, 'v': 11, '\\': 92}


def _echo_printf_decode(body, mode):
    """What `echo -e` (mode 'echo') or the FORMAT of `printf` (mode 'printf') makes of the escapes in `body` (card 798c3c24 round 3, Sam 1885: the two
    differ from `$'..'` and from each other, measured against bash 5.3). Both: `\\a \\b \\e \\E \\f \\n \\r \\t \\v \\\\`, `\\xH[H]`, `\\uHHHH`, `\\UHHHHHHHH`; any other backslash stays. echo: `\\0` and up to
    three octal digits (`\\0155` is `m`; `\\155` stays `\\155`), `\\c` ends the output, `\\\"` and `\\?` stay. printf: one to three octal digits with no
    leading zero needed (`\\0155` is CR and `5`), `\\"` `\\'` `\\?` lose the backslash, `\\c` stays."""
    out = bytearray()
    i, n = 0, len(body)
    while i < n:
        ch = body[i]
        if ch != '\\' or i + 1 >= n:
            out += ch.encode('utf-8', 'surrogateescape')
            i += 1
            continue
        c = body[i + 1]
        if c in _PE_SIMPLE:
            out.append(_PE_SIMPLE[c])
            i += 2
        elif mode == 'printf' and c in '"\'?':
            out.append(ord(c))
            i += 2
        elif mode == 'echo' and c == '0':
            j = i + 2
            while j < n and j < i + 5 and body[j] in '01234567':
                j += 1
            out.append(int(body[i + 2:j] or '0', 8) & 255)
            i = j
        elif mode == 'printf' and c in '01234567':
            j = i + 1
            while j < n and j < i + 4 and body[j] in '01234567':
                j += 1
            out.append(int(body[i + 1:j], 8) & 255)
            i = j
        elif c in 'xuU':
            width = {'x': 2, 'u': 4, 'U': 8}[c]
            j = i + 2
            while j < n and j < i + 2 + width and body[j] in '0123456789abcdefABCDEF':
                j += 1
            if j == i + 2:
                out += ('\\' + c).encode()
            elif c == 'x':
                out.append(int(body[i + 2:j], 16))
            else:
                try:
                    out += chr(int(body[i + 2:j], 16)).encode('utf-8')
                except (ValueError, OverflowError):
                    out += body[i:j].encode('utf-8', 'surrogateescape')
            i = j
        elif mode == 'echo' and c == 'c':
            break
        else:
            out += ('\\' + c).encode('utf-8', 'surrogateescape')
            i += 2
    cut = out.find(0)
    if cut >= 0:
        out = out[:cut]
    return out.decode('utf-8', 'surrogateescape')


def _pipe_program_text(text, state, a, b):
    """The program a quoted run on the left of a pipe hands to the shell on its right. A run in double quotes is unescaped by the shell
    first; when it is the FORMAT of a `printf` (or the text of `echo -e`) the command expands the same escapes as `$'..'` once more, so
    `printf 'r\\\\<NL>m' | bash` is `r\\<NL>m`, a line continuation."""
    t = _run_text(text, state, a, b)
    k = a - 1
    while k >= 0 and not (state[k] == 0 and text[k] in ';|&\n('):
        k -= 1
    head = text[k + 1:a].rstrip().rstrip('\'"').rstrip()
    toks = [w for w in re.split(r'\s+', head) if w and not re.match(r'^[A-Za-z_]\w*=', w)]
    if toks and os.path.basename(toks[0]) == 'printf' and (len(toks) == 1 or toks[1:] == ['--']):
        t = _echo_printf_decode(t, 'printf')
        if '%' in t.replace('%%', ''):
            block('A cso bal oldalan egy printf all, amelynek a formatuma kifejtest tartalmaz (%s, %b, %d ...), a jobb oldalon pedig shell: a shell '
                  'programja a kifejtes UTAN keletkezik, a kapu a szoveget latja, ezert nem tudja eldonteni, MI fut. Ird ki a programot kozvetlenul. '
                  'Nem az ugynok dontese.')
        t = t.replace('%%', '%')
    elif toks and os.path.basename(toks[0]) == 'echo' and all(w.startswith('-') for w in toks[1:]) \
            and any(re.match(r'^-[a-zA-Z]*e[a-zA-Z]*$', w) for w in toks[1:]):
        t = _echo_printf_decode(t, 'echo')
    return t


def shell_stdin_programs(cmd):
    """Azok a szovegek, amelyeket egy SHELL a stdin-rol (here-string, <(...), cso) vegrehajt: ezek nem
    ertelmezo-payloadok, hanem parancssorok, tehat a check_bash-nek valok (mint a `bash -c` szkriptje)."""
    data, code = _heredoc_body_ranges(cmd)
    text = _blank_ranges(cmd, data)
    text = _blank_ranges(text, _comment_ranges(text, code))
    text = _blank_ranges(text, _foreign_code_ranges(cmd))     # lasd interpreter_payloads: idegen nyelvu torzs nem shell
    qstate = _quote_map(text)
    out = [_pipe_program_text(text, qstate, a, b) for a, b, sh in _stdin_pipe_ranges(text) if sh]
    out += [c for c, sh in _stdin_program_sources(text) if sh]
    out += [_run_text(text, qstate, a, b) for a, b in _generic_c_ranges(text)]        # 7fd3134e: an unnamed command's -c string is a shell program
    return [p for p in out if p.strip()]


# INTERPFLAG v2 (HEX 2512, merve 2026-10-04): az ertelmezo a PROGRAMJAT a stdin-rol kapja, nem a -c utan, nem
# heredoc-torzsbol es nem `-`-vel. Mind atment az ELO kapun (4571448):
#   python3 <<< "<kod>"          here-string
#   python3 <(echo "<kod>")      process substitution (az ertelmezo /dev/fd/N-t nyit meg)
#   echo "<kod>" | python3       cso, NEM kell hozza a `-` (a python3/node/perl/bash program nelkul stdin-t olvas)
# A kapu itt NEM a parancs nevet nezi, hanem hogy az ertelmezonek VAN-E megnevezett programja: ha az opciok
# utan nem jon program-fajl (vagy a `-`, /dev/stdin), a stdin a program.
_STDIN_PATHS = ('-', '/dev/stdin', '/dev/fd/0', '/proc/self/fd/0')
_SHELL_FAMILIES = ('sh', 'bash', 'zsh')


def _stdin_program_sites(text):
    """[(csalad, pozicio)]: az ertelmezok, amelyek a programjukat a stdin-rol olvassak. A pozicio az
    opciok vege. Idezojelen belul allo ertelmezo-nev (proza) nem szamit.

    Card 6a6191f4, round 2: the shell word is read UNQUOTED and UNESCAPED (`| "sh"`, `| s\\h`, `| 'bash' -s`, `| b"as"h` are the shell), as a
    whole word only (the characters on both sides are real separators, never the inside of a quote); the sourcing of stdin on the pipe side
    (`| . /dev/stdin`, `| source /dev/stdin`) is a site; and a shell's `-c` code that itself reads stdin (`bash -c 'source /dev/stdin'`,
    `sh -c 'cat | sh'`) makes the outer shell a site."""
    state = _quote_map(text)
    n = len(text)
    keep, i = [], 0
    while i < n:
        if state[i] == 0 and text[i] in '\'"':
            i += 1                                      # a quote character of the shell: not part of any word
            continue
        if state[i] == 0 and text[i] == '\\' and i + 1 < n and state[i + 1] == 0:
            keep.append(i + 1)                          # an escaped character: the backslash goes, the character stays
            i += 2
            continue
        keep.append(i)
        i += 1
    u = ''.join(text[x] for x in keep)
    ustate = [state[x] for x in keep]
    out = []

    def standalone(a, e):
        """The characters around u[a:e] are real separators (or a directory slash): never the inside of a quote."""
        if a > 0 and (ustate[a - 1] or u[a - 1] not in ' \t\n;&|(){}<>/'):       # (a `/` ends a directory of a path: `/bin/sh`)
            return False
        if e < len(u) and (ustate[e] or u[e] not in ' \t\n;&|(){}<>'):
            return False
        return True

    def back(pos):
        return keep[pos] if pos < len(keep) else n

    for m in re.finditer(r'(?<![\w.-])((?:python|bash|sh|zsh|node|bun|perl|ruby|php)[\d.]*)(?=[\s<|;&)]|$)', u):
        if not standalone(m.start(), m.end()):
            continue
        fam = _interp_family(m.group(1))
        kind, pos = _interp_opts_scan(u, ustate, fam, m.end())
        if kind == 'code':
            if fam in _SHELL_FAMILIES:
                ks = _skip_ws(u, pos)
                if _stdin_program_sites(u[ks:_interp_word_end(u, ustate, ks)]):
                    out.append((fam, back(pos)))        # `bash -c 'source /dev/stdin'`: the -c code reads the stdin of the shell
            continue
        if kind == 'arg' and u[pos:_interp_word_end(u, ustate, pos)] not in _STDIN_PATHS \
                and not (fam in _SHELL_FAMILIES and _shell_s_flag(u, ustate, m.end())):
            continue                                   # program-FAJL: a stdin annak az adata
        out.append((fam, back(pos)))
    for m in re.finditer(r'(?<![\w./-])(?:source|\.)[ \t]+(?:/dev/stdin|/dev/fd/0|/proc/self/fd/0)(?=[\s;&|)<>]|$)', u):
        if standalone(m.start(), m.start() + (6 if u.startswith('source', m.start()) else 1)):
            out.append(('bash', back(m.end())))        # `| . /dev/stdin`: the shell sources its own stdin
    return out


def _shell_s_flag(text, state, k):
    """True when a shell is started with `-s` (alone or in a group, `-xs`) and without `-c`: it reads its program from stdin whatever
    words follow, which then only set the positional parameters (`bash -s -- x`, `sh -s a b`). Measured with real bash: `printf 'echo
    hi' | bash -s -- x` runs it. Card 6a6191f4: `echo 'rm ...' | bash -s -- x` was rc 0 on the chain head, the file-name test below it
    took `x` for a program file. A `-c` in the options wins (the string is the program), as in bash."""
    n = len(text)
    for _ in range(32):
        k = _skip_ws(text, k)
        if k >= n or state[k] or text[k] != '-':
            return False
        e = _interp_word_end(text, state, k)
        tok = text[k:e]
        if tok == '--' or tok == '-':
            return False
        if tok.startswith('--'):
            k = e
            continue
        letters = tok[1:]
        if 'c' in letters:
            return False
        if 's' in letters:
            return True
        k = _interp_word_end(text, state, _skip_ws(text, e)) if letters[-1:] in ('o', 'O') else e
    return False


def _simple_command_end(text, state, k):
    """Az egyszeru parancs vege: az elso idezojelen kivuli ; | ujsor, vagy olyan & amely nem atiranyitas resze."""
    n = len(text)
    while k < n:
        c = text[k]
        if not state[k]:
            if c in ';|\n':
                break
            if c == '&' and not (k > 0 and text[k - 1] in '<>') and not (k + 1 < n and text[k + 1] in '<>'):
                break
        k += 1
    return k


def _balanced_paren_end(text, state, open_idx):
    """A nyito zarojel parjanak indexe (idezojelen kivul szamolva), vagy len(text)."""
    depth = 0
    for i in range(open_idx, len(text)):
        if state[i]:
            continue
        if text[i] == '(':
            depth += 1
        elif text[i] == ')':
            depth -= 1
            if depth == 0:
                return i
    return len(text)


def _quoted_runs(text, a, b):
    """Az [a, b) tartomany idezojelen BELULI, osszefuggo szakaszai (a nyito/zaro jel nelkul)."""
    state = _quote_map(text)
    out, i = [], a
    while i < b:
        if state[i]:
            j = i
            while j < b and state[j] == state[i]:
                j += 1
            out.append((i, j))
            i = j
        else:
            i += 1
    return out


def _stdin_program_sources(text):
    """[(kod-szoveg, shell-e)]: here-string es process-substitution forrasbol jovo programok."""
    state = _quote_map(text)
    out = []
    for fam, pos in _stdin_program_sites(text):
        shell = fam in _SHELL_FAMILIES
        end = _simple_command_end(text, state, pos)
        i = pos
        while i < end:
            if state[i]:
                i += 1
                continue
            if text.startswith('<<<', i):
                k = _skip_ws(text, i + 3)
                r = _quoted_range_at(text, state, k)
                if r:
                    out.append((_run_text(text, state, r[0], r[1]), shell))
                    i = r[1] + 1
                else:
                    e = _interp_word_end(text, state, k)
                    if e > k:
                        out.append((text[k:e], shell))
                    i = max(e, i + 3)
                continue
            if text.startswith('<(', i):
                close = _balanced_paren_end(text, state, i + 1)
                if shell:
                    out += [(_run_text(text, state, a, b), True) for a, b in _quoted_runs(text, i + 2, close)]
                else:
                    out.append((text[i + 2:close], False))
                i = close + 1
                continue
            i += 1
    # `source <(...)` / `. <(...)`: a shell a fajl tartalmat futtatja
    for m in re.finditer(r'(?:^|[;&|\n({])[ \t]*(?:source|\.)[ \t]+<\(', text):
        op = m.end() - 1
        if state[op]:
            continue
        close = _balanced_paren_end(text, state, op)
        out += [(_run_text(text, state, a, b), True) for a, b in _quoted_runs(text, op + 1, close)]
    return out


def _stdin_pipe_ranges(text):
    """`echo "<kod>" | python3 -` es (v2) `echo "<kod>" | python3` -- az ertelmezo a STDIN-rol olvas.

    Csak akkor ad vissza tartomanyt, ha a cso EGYIK szakaszanak parancsa ertelmezo ES a programja a
    stdin: a puszta `-`, vagy (v2) nincs megnevezett program-fajl. Enelkul minden idezett szoveget
    kodnak kellene tekinteni, ami a prozaszures ellentetje volna.
    Visszaadott elemek: (a, b, shell-e).
    """
    state = _quote_map(text)
    bars = [i for i in range(len(text)) if not state[i] and text[i] == '|'
            and not text.startswith('||', i) and not (i and text[i - 1] == '|')]
    if not bars:
        return []
    bounds = [0] + [b + 1 for b in bars] + [len(text)]
    parts = [(bounds[k], bounds[k + 1] - (1 if k + 1 <= len(bars) else 0))
             for k in range(len(bounds) - 1)]
    out = []
    for k, (a, b) in enumerate(parts):
        toks = [t for t, _sp in _tokens(text[a:b])]
        if not toks or k == 0:
            continue
        old_form = _interp_family(toks[0]) is not None and '-' in toks[1:]
        sites = _stdin_program_sites(text[a:b])
        if old_form or sites:
            # A shell-e a stdin-program, CSAK a `sites` dontse (az ertelmezo programja tenyleg a stdin).
            # A regi `old_form` ('-' bárhol a tokenek kozott) `bash scripts/agent-msg.sh zola sam -`-ra is
            # igaz, ahol a `-` a szkript ARGUMENTUMA, a program a FAJL: ott a cso bal oldalan allo
            # idezett szovegek (pl. `-H "$T"`) NEM parancssorok (Zola 2026-10-05, Sam v5.3 visszajatszasa).
            shell = any(f in _SHELL_FAMILIES for f, _p in sites)
            pa, pb = parts[k - 1]
            prev_state = _quote_map(text[pa:pb])
            # Shell-programnak CSAK a cso kozvetlen elozo parancsa (az utolso idezojelen kivuli ; & ujsor
            # utan) mehet: az elozo parancsok idezett szovegei (`curl -H "$T" ...; echo "x" | bash -`)
            # nem a stdin-be kerulnek. A nem-shell (payload-minta) ag marad a teljes bal oldalon.
            prod_start = 0
            if shell:
                for q in range(pb - pa):
                    if not prev_state[q] and text[pa + q] in ';&\n':
                        prod_start = q
            i = 0
            while i < pb - pa:
                if prev_state[i]:
                    j = i
                    while j < pb - pa and prev_state[j] == prev_state[i]:
                        j += 1
                    out.append((pa + i, pa + j, shell and i >= prod_start))
                    i = j
                else:
                    i += 1
    return out


# INTERPFLAG v2: az awk a parancsot nem fuggvenyhivassal, hanem csovel inditja:
#   "parancs" | getline        print ... | "parancs"        printf ... | "parancs"
_AWK_PIPE_RES = (
    re.compile(r'("(?:[^"\\]|\\.)*")\s*\|\s*getline'),
    re.compile(r'\bprintf?\b[^|;}\n]*\|\s*("(?:[^"\\]|\\.)*")'),
)


_USER_GITCFG = re.compile(r'(^|[\s/\'"=])(\.gitconfig|\.config/git/config)($|[\s\'"])')
_PAYLOAD_WRITES = re.compile(r"""['"][wax]\+?b?['"]|write|copy|move|rename|replace|symlink|link\(|unlink|remove|truncate|chmod|append|dump""", re.I)


def check_payload(payload, _depth=0, cwd=None):
    """A ma is tiltott muveletek az ertelmezo-burkon BELUL."""
    if _USER_GITCFG.search(' ' + payload + ' ') and _PAYLOAD_WRITES.search(payload):
        # the interpreter form of the printf/cp/tee rule for the USER-level git config (the file a HOME redirect makes git read), together
        # with a write primitive. The repo-level .git/config and .git/hooks are not in this rule: a push reads the EFFECTIVE hooksPath
        # (_effective_hooks_path), and sandbox repos are written from interpreters all the time (replay: 22 of 3,901 were exactly that).
        block('Ertelmezo-payloadban a felhasznaloi git config (%s) irasa: a core.hooksPath-t lehet beleirni (HOME= atiranyitassal a git ezt '
              'olvassa). Nem az ugynok dontese.\n(a payload reszlete: %s)' % (_USER_GITCFG.search(' ' + payload + ' ').group(0).strip()[:40], payload[:160]))
    if _PAYLOAD_GIT.search(payload) and _PAYLOAD_ENV.search(payload):
        # an interpreter payload that starts git AND passes or edits the environment (Sam f4057869 round 1, SEVERE 3:
        # `subprocess.run(['git','push',...], env={'PATH': ...})` ran git with none of the markers the hooks look for). The environment an
        # interpreter hands to git cannot be read from its source, so the gate cannot show the hooks see the session's; it is a deny.
        block('Ertelmezo-payload, amely gitet inditana ES a kornyezetet adja at vagy szerkeszti (%s): a kapu nem tudja bizonyitani, hogy a '
              'hookok a session kornyezetet latjak. Nem az ugynok dontese.\n(a payload reszlete: %s)'
              % (_PAYLOAD_ENV.search(payload).group(0).strip()[:30], payload[:160]))
    for rx, equivalent in _PAYLOAD_RE:
        m = rx.search(payload)
        if m:
            block('Ertelmezo-payloadban allo, visszafordithatatlan muvelet: "%s" -- ez a '
                  '"%s" megfeleloje, amit a kapu a shellben is tilt. A burok nem valtoztat '
                  'a dontesen.\n(a payload reszlete: %s)'
                  % (m.group(0).strip(), equivalent, payload[:160]))
    for rx in _AWK_PIPE_RES:
        for m in rx.finditer(payload):
            inner = m.group(1)[1:-1].strip()
            if inner and _depth < _MAX_NEST:
                check_bash(inner, _depth + 1, cwd)
    for m in _SHELLOUT_RE.finditer(payload):
        arg = _balanced_arg(payload, payload.index('(', m.end() - 1))
        words = [g2 for _g1, g2 in _STR_LIT_RE.findall(arg)]
        if not words:
            continue
        inner = ' '.join(words).strip()
        if not inner or _depth >= _MAX_NEST:
            continue
        # Ugyanaz a szabalykeszlet, nem egy masodik lista: a kihivott parancs
        # visszamegy a check_bash-be.
        _HM_LOSSY[0] += 1            # the join above dropped every non-literal word (see _head_move_gate)
        try:
            check_bash(inner, _depth + 1, cwd)
        finally:
            _HM_LOSSY[0] -= 1


# GATEGAPS1003, B. lepes: a parancsnev behelyettesitesbol vagy valtozobol jon. `X=rm; $X -f x`,
# `$(echo rm) -f x`, `"$(command -v rm)" x`: a kapu a SZOVEGET latja, nem azt, ami kifejtes utan
# fut, tehat nem tudja, MI a parancs. Ez ugyanaz a vilagos valasz, mint a nem eldontheto torlesi
# utvonalra: amit nem lat at, azt nem engedi. A tiltolistas felismeres (`rm`, `rmdir`, `unlink`,
# ...) barmikor megkerulheto egy ujabb nevvel; ez az irany nem a NEVET keresi, hanem azt, hogy a
# nev EGYALTALAN ismert-e.
#   - `$(...)` / `` `...` ``: a parancsnev helyen all, ha egy ures vagy csak kulcsszavakbol,
#     atlatszo elotagokbol es hozzarendelesekbol allo elotag elott kezdodik SZO-kent (nem `x=$(..)`,
#     nem `echo $(..)`, nem `case $(..) in`). Idezett `"$(..)"` is az.
#   - `$X` / `${X}` / `"$@"` a parancsnev helyen: feloldjuk, ha EZEN A PARANCSSORON egyszer, literal
#     ertekkel kapott erteket (`N=/usr/bin/node; $N x` -> a feloldott nev kerul vizsgalatra), egyebkent
#     BLOKK. Egy valtozo UTVONAL-reszkent (`$HOME/bin/x`) nem opak: a nev az utolso, literal komponens.
# A koltseg MERT (a mellekelt meres), nem becsult: lasd a jelentest. Kikapcsolni a
# OPAQUE_COMMAND_BLOCK = False beallitassal lehet, hogy a dontes kapcsolo, nem kodszerkesztes.
OPAQUE_COMMAND_BLOCK = True
_CMD_WORD_KW = ('case', 'select', 'in')
_VAR_NAME_RE = re.compile(r'^\$(?:\{([^}]*)\}|([A-Za-z_@*#?!0-9]\w*))$')
_LIT_ASSIGN_RE = re.compile(
    r'(?:^|[;&|\n({]|(?<![\w-])(?:do|then|else|export|local|declare|readonly)[ \t])[ \t]*'
    r'([A-Za-z_]\w*)=(?:"([^"$`\\]*)"|\'([^\']*)\'|([^\s"\'$`;&|()<>\\]*))(?=[\s;&|)]|$)')


def _literal_assignments(text):
    """NAME -> literal ertek, azokra a nevekre, amelyek a parancssorban EGYSZER kapnak literal erteket."""
    seen = {}
    for m in _LIT_ASSIGN_RE.finditer(text):
        val = next((g for g in m.groups()[1:] if g is not None), '')
        seen.setdefault(m.group(1), []).append(val)
    return {k: v[0] for k, v in seen.items() if len(v) == 1 and v[0]}


_NON_SHELL_INTERPRETERS = ('python', 'python3', 'node', 'bun', 'perl', 'ruby', 'php')


def _foreign_code_ranges(cmd):
    """Heredoc-torzsek, amelyeket NEM shell hajt vegre (python3 - <<PY, node <<JS, ...). Ott a `$x`
    perl-valtozo, a backtick pedig python-karakterlancban all: egyik sem shell-parancsnev."""
    lines = cmd.split('\n')
    out = []
    for i, _j, m, a, b in _heredocs(cmd):
        head = lines[i][:m.start()]
        seg = re.split(r'\|\||&&|[;|&]', head)[-1]
        names = [os.path.basename(t.strip('"\'')) for t in seg.split()]
        if any(_interp_family(n) in _NON_SHELL_INTERPRETERS for n in names) and _heredoc_opener_runs_body(head):
            out.append((a, b))
    return out


def _git_subcommand_slot(toks, glued=False):
    """Is the position right after `toks` the SUBCOMMAND of a git command (card 8ed4c8e8: `git $(echo)push --force` names the subcommand by a
    substitution, the segmenter cuts the command there and no git rule meets `push`)? `glued`: the last token is the subcommand word itself,
    already begun. A substitution that is the VALUE of a global option (`git -C $(pwd) status`) is not the subcommand."""
    idx = command_index(toks)
    if idx is None or _cname(toks[idx][0]) != 'git':
        return False
    rest = [t for t, _sp in toks[idx + 1:]]
    end = len(rest) - (1 if glued else 0)
    k = 0
    while k < end:
        t = rest[k]
        if t in _GIT_GLOBAL_VALUE_OPTS:
            if k + 1 >= end:
                return False                       # the substitution (or the word it is glued to) is this option's value
            k += 2
            continue
        if t.startswith('-'):
            k += 1
            continue
        return False                               # a subcommand word is already there
    return True


def _slash_outside_braces(s):
    """Is there a `/` in s that is a directory border, not text inside a `${ ... }` (`it${X%/*}`, `${X//a/b}`: the slash belongs to the expansion; card 8ed4c8e8
    round 3)?"""
    depth, i = 0, 0
    while i < len(s):
        if s.startswith('${', i):
            depth += 1
            i += 2
            continue
        if depth and s[i] == '{':
            depth += 1
        elif depth and s[i] == '}':
            depth -= 1
        elif s[i] == '/' and not depth:
            return True
        i += 1
    return False


def _opaque_substitution(text):
    """A parancsnev helyen allo `$(...)` / backtick reszlete, vagy None."""
    state = _quote_map(text)
    for i, ch in enumerate(text):
        if ch == '`':
            w = i
        elif ch == '$' and text.startswith('$(', i) and not text.startswith('$((', i):
            w = i
        else:
            continue
        # idezett `"$(..)"`: az nyito idezojel a szo eleje
        if w > 0 and text[w - 1] == '"' and not state[w - 1] and state[w]:
            w -= 1
        elif state[w] == 2 and ch != '`' and w > 0 and text[w - 1] != '"':
            pass                                       # `"r$(echo)m"`: a substitution glued to a literal INSIDE a double-quoted word; judged below like `r$(echo)m`
        elif state[w] and ch != '`':
            continue
        if w > 0 and text[w - 1] not in ' \t;&|\n':
            # `x=$(..)`, `($(..)`, `echo foo$(..)`: not a word of its own, nothing to say. But `r$(echo m) -rf x`: a substitution glued to a literal in
            # front, in the BASENAME of the word that is the command, is the command named by an expansion (card 8ed4c8e8).
            k = w - 1
            while k >= 0 and not (text[k] in ';&|\n({' and not state[k] and not (text[k] == '{' and k and text[k - 1] == '$')):
                k -= 1
            if k >= 1 and text[k] == '(' and text[k - 1] in '($':
                if text[k - 1] == '(':
                    continue                           # inside (( )) / $(( )): arithmetic, no command is named there
            gprefix = text[k + 1:w]
            if state[w] == 2 and gprefix.count('"') % 2 == 1 and gprefix.count("'") % 2 == 0 and not any(c in gprefix for c in ';&|\n'):
                gprefix += '"'                         # the quote is the one the word opened: close it, the prefix is then read like any other
            if gprefix.count('"') % 2 or gprefix.count("'") % 2 or any(c in gprefix for c in ';&|\n'):
                continue                               # a stray quote or a separator inside the prefix: the quote map lost sync (heredoc text), nothing is known
            e = w
            while e < len(text) and not (text[e] in ' \t\n;&|' and not state[e]):
                e += 1
            gtoks = _bare_tokens(gprefix)
            if _HM_LOSSY[0]:
                continue                               # the string literals of a python shell-out, joined without their context: not a command line
            if ch == '`':
                se = text.find('`', w + 1)
                se = e if se < 0 else se + 1
            else:
                depth, se = 0, w + 1
                while se < len(text):
                    depth += text[se] == '('
                    depth -= text[se] == ')'
                    se += 1
                    if depth == 0:
                        break
            if gtoks and command_index(gtoks) == len(gtoks) - 1 and not _slash_outside_braces(text[min(se, e):e]) and not gtoks[-1][0].endswith('='):
                return text[w:w + 30].strip()
            if gtoks and _git_subcommand_slot(gtoks, True):
                return text[w:w + 30].strip()
            continue
        j = w - 1
        while j >= 0 and not (text[j] in ';&|\n({' and not state[j]):
            j -= 1
        prefix = text[j + 1:w]
        if prefix.count('"') % 2 or prefix.count("'") % 2:
            continue      # a stray quote: _quote_map lost sync inside a nested `"$(.. "x" ..)"`, nothing is known
        toks = _bare_tokens(prefix)
        if toks and toks[-1][0] in _CMD_WORD_KW:
            continue
        if command_index(toks) is None or (not _HM_LOSSY[0] and _git_subcommand_slot(toks)):
            return text[w:w + 30].strip()
    return None


# --- PONDERWRITE1004: a Ponder csak a SAJAT teruleten ir -------------------------------------------
# HEX 2506 (2. feladat): a kapu a torlest zarta Ponderre, az irast nem. Ponder igy atirhatta a sajat
# agents/ponder/.mcp.json-jat (a launcher kihagyhato), a launcher scriptjet, a ~/.cache/ms-playwright
# tartalmat, a settings-fajlokat. A javaslat az agents/ponder/ tiltasa volt (tiltolista); ennel ALLOW-ONLY
# a megbizhatobb: egy tiltolista pont azt a helyet felejti ki, amelyiket a megkerulo talalja meg (a
# launcher es a browser-cache MAS konyvtarban van, mint az agents/ponder). Ezert forditva: csak ezeken
# a helyeken szabad irnia, minden mas BLOKK:
#   1. a sajat munkaterulete (~/agents_munka/<nev>/),
#   2. <telepites>/agents/<nev>/HANDOFF.md (pontosan ez az egy fajl),
#   3. a Claude Code scratchpadje (/tmp/claude-<uid>/),
#   4. /dev/null, /dev/stdout, /dev/stderr.
# MIT FOG ES MIT NEM (a torles-kapuval azonos jellegu: a VELETLEN ellen ved, nem az elszant ellen):
#   fogja: Write/Edit/NotebookEdit; Bash kimeneti atiranyitas (>, >>, >|, &>); tee, cp, mv (a forras is,
#          mert az mv a forrast eltavolitja), install, ln, dd of=, touch, mkdir, truncate, sed -i.
#   NEM fogja: a szkript/interpreter payloadjaban levo iras (python open(.., 'w'), node writeFile), a
#          git clone/checkout, tar -x, unzip, rsync, curl -o, perl -i. Azokrol a kapu a torlesnel sem
#          dont, es itt sem hazudik teljesseget.
# A transcript-azonositas (OWN_AGENT) ugyanaz, mint a torlesnel; ismeretlen hivora ez nem vonatkozik.
CONFINED_WRITE_AGENTS = frozenset({'ponder'})
_WRITE_DEVICES = ('/dev/null', '/dev/stdout', '/dev/stderr')


_VAR_REF_RE = re.compile(r'\$(?:\{([A-Za-z_]\w*)\}|([A-Za-z_]\w*))')


def _expand_known(raw, known):
    """A `$NAME` / `${NAME}` hivatkozasok kifejtese azokra a nevekre, amelyek EZEN A PARANCSSORON, a hasznalat
    ELOTT, egyszer, literal ertekkel kaptak erteket (`D=/tmp/x; echo > $D/f`). Ugyanaz a feloldas, mint a
    parancsnevnel (_literal_assignments), csak az iras-celra. Ami nem oldodik fel, az marad, es a hivo BLOKKOL."""
    if not known or '$' not in raw:
        return raw
    for _ in range(4):
        new = _VAR_REF_RE.sub(lambda m: known.get(m.group(1) or m.group(2), m.group(0)), raw)
        if new == raw:
            break
        raw = new
    return raw


def _standalone_assignments(toks, literal):
    """NAME -> ertek azokra a `NAME=ertek` (vagy `export NAME=ertek`) szegmensekre, amelyek NEM egy parancs
    elotagjai (`D=x cmd` csak a cmd kornyezetet allitja, a `> $D` mar a hozzarendeles ELOTT kifejtodik), es
    amelyek neve a parancssoron egyszer kap literal erteket (`literal`, _literal_assignments)."""
    words = [t for t, _sp in toks]
    if words and words[0] in ('export', 'local', 'declare', 'typeset', 'readonly'):
        words = words[1:]
    if not words or not all(re.match(r'^[A-Za-z_]\w*=', w) for w in words):
        return {}
    out = {}
    for w in words:
        name, _eq, val = w.partition('=')
        if literal.get(name) == val:
            out[name] = val
    return out


def _confined_write_ok(raw, cwd, known=None):
    """(ok, indoklas): ir-hat-e a korlatozott agens erre az utra. A fizikai (realpath) ut szamit,
    tehat a kifele mutato symlinken at nem lehet irni. `known`: a mar feloldott literal valtozok."""
    agent = OWN_AGENT
    raw = _expand_known(raw, known) if raw else raw
    if not raw or '\0' in raw:
        return False, 'ures vagy ervenytelen ut'
    if raw in _WRITE_DEVICES:
        return True, ''
    if any(c in raw for c in RM_UNRESOLVABLE):
        return False, 'nem eldontheto ut (valtozo vagy behelyettesites): %s' % raw[:60]
    p = os.path.expanduser(raw)
    if not os.path.isabs(p):
        if cwd is None:
            return False, 'relativ ut, a munkakonyvtar nem ismert: %s' % raw[:60]
        p = os.path.join(cwd, p)
    if any(c in p for c in '*?['):
        return False, 'glob a celutban: %s' % raw[:60]
    try:
        real = os.path.realpath(p)
    except (OSError, ValueError):
        return False, 'nem feloldhato ut: %s' % raw[:60]
    roots = []
    area = _own_area(agent)
    if area:
        roots.append(area)
    roots.append(os.path.realpath('/tmp/claude-%d' % os.getuid()))
    if any(real == r or real.startswith(r + os.sep) for r in roots):     # a gyoker maga is (wget cel nelkul: `.`)
        return True, ''
    if real == os.path.join(os.path.realpath(os.path.join(PROJECT_ROOT, 'agents', agent)), 'HANDOFF.md'):
        return True, ''
    return False, ('ide (%s) nem irhat; csak a sajat munkateruleten (%s), az agents/%s/HANDOFF.md-be es a '
                   'scratchpadjara' % (real, area or '~/agents_munka/%s' % agent, agent))


def check_gitcfg_write(path):
    """Write/Edit/NotebookEdit on a file that can hold core.hooksPath or a hook (a gitconfig, .git/config, .git/hooks/*): the Write tool
    reaches it without a shell, so the printf/cp/tee rule never sees it (Sam round 1, SEVERE 3: `HOME=/tmp/h` plus a gitconfig written
    by the Write tool, then `git push` ran without pre-push)."""
    if _HOOKS_PATH.search(' ' + str(path) + ' '):
        block('Iras egy git config- vagy hook-fajlba (%s): a core.hooksPath-t vagy egy hookot lehet beleirni, a kapukat kikapcsolja. '
              'Nem az ugynok dontese.' % str(path)[:80])


def check_write(path, cwd=None):
    """Write/Edit/NotebookEdit: BLOKK, ha a korlatozott agens kivulre irna."""
    if OWN_AGENT not in CONFINED_WRITE_AGENTS:
        return
    ok, why = _confined_write_ok(path, cwd)
    if not ok:
        block('Iras, amit a kapu nem engedhet at: %s.\nEz az agens (%s) csak a sajat munkateruleten ir. '
              'Ha tenyleg kell: szolj a fo agensnek (%s).' % (why, OWN_AGENT, _main_agent_id()))


def _redirect_targets(seg):
    """A szegmens kimeneti atiranyitasainak celjai (idezojelen KIVUL). None elem = nem eldontheto
    (`>(cmd)`, ures cel). A `2>&1` / `>&2` fd-masolat, nem iras."""
    state = _quote_map(seg)
    out, i, n = [], 0, len(seg)
    while i < n:
        if state[i] or seg[i] != '>':
            i += 1
            continue
        j = i + 1
        if j < n and seg[j] in '>|':
            j += 1
        if j < n and seg[j] == '&':
            k = j + 1
            if k < n and (seg[k].isdigit() or seg[k] == '-'):
                i = k + 1
                continue
            j += 1                                       # `>&fajl`: a bash ezt fajlba irja
        while j < n and seg[j] in ' \t':
            j += 1
        k = j
        while k < n and (state[k] or seg[k] not in ' \t;&|<>()'):
            k += 1
        word = ''.join(c for m, c in enumerate(seg[j:k], j) if not (c in '"\'' and not state[m]))
        out.append(word if word and seg[j:j + 1] != '(' else None)
        i = max(k, i + 1)
    return out


# Opciok, amelyek a KOVETKEZO szot ertekkent eszik (rovid betu es hosszu alak).
_WRITE_VERB_VALUE_OPTS = {
    'cp': ('t', 'S', '--target-directory', '--suffix'),
    'mv': ('t', 'S', '--target-directory', '--suffix'),
    'install': ('t', 'm', 'o', 'g', 'S', '--target-directory', '--mode', '--owner', '--group', '--suffix'),
    'ln': ('t', 'S', '--target-directory', '--suffix'),
    'touch': ('r', 'd', 't', '--reference', '--date', '--time'),
    'mkdir': ('m', 'Z', '--mode', '--context'),
    'truncate': ('s', 'r', '--size', '--reference'),
    'tee': (),
    'sed': ('e', 'f', 'l', '--expression', '--file', '--line-length'),
}


def _verb_write_targets(base, toks, argstart, cwd):
    """A parancs altal IRT utak, vagy None, ha nem eldontheto. Csak a _WRITE_VERB_VALUE_OPTS parancsai +
    a `dd of=`."""
    args = [t for t, _sp in toks[argstart:]]
    if base == 'dd':
        return [a[3:] for a in args if a.startswith('of=')]
    vopts = _WRITE_VERB_VALUE_OPTS[base]
    pos, tdir, skip, has_script_opt, in_place = [], None, False, False, False
    for idx, a in enumerate(args):
        if skip:
            skip = False
            continue
        if a == '--':
            pos.extend(args[idx + 1:])
            break
        if a.startswith('--'):
            name, eq, val = a.partition('=')
            if base == 'sed' and name == '--in-place':
                in_place = True
            if name in ('--target-directory',):
                if eq:
                    tdir = val
                elif idx + 1 < len(args):
                    tdir, skip = args[idx + 1], True
            elif name in vopts and not eq:
                skip = True
            if base == 'sed' and name in ('--expression', '--file'):
                has_script_opt = True
            continue
        if a.startswith('-') and len(a) > 1:
            letters = a[1:]
            if base == 'sed':
                if re.match(r'^[nEsrzu]*i', letters):
                    in_place = True
                if letters.endswith(('e', 'f')) or letters in ('e', 'f'):
                    has_script_opt = True
            hit = [c for c in letters if c in vopts]
            if hit and letters.endswith(hit[-1]):        # `-t DIR`, `-pm 755`: a ertek a kovetkezo szo
                if hit[-1] == 't' and base != 'touch' and idx + 1 < len(args):
                    tdir = args[idx + 1]
                skip = True
            continue
        pos.append(a)
    if base == 'tee':
        return pos
    if base == 'sed':
        if not in_place:
            return []
        return pos if has_script_opt else pos[1:]
    if base in ('touch', 'mkdir', 'truncate'):
        return pos
    # cp, mv, install, ln: a cel a -t konyvtar, vagy az utolso szo; mv-nel a FORRAS is erintett.
    out = []
    if tdir is not None:
        out.append(tdir)
        if base == 'mv':
            out.extend(pos)
        return out
    if not pos:
        return []
    if base == 'ln' and len(pos) == 1:
        return [os.path.basename(pos[0].rstrip('/')) or pos[0]]
    out.append(pos[-1])
    if base == 'mv':
        out.extend(pos[:-1])
    return out


# PONDERBINHASH1004 (HEX 2512 pont 2): a keresove szerint ezek a korlatozott agens irasi kapuja mellett
# atmentek. Ket fajta: (1) fajlt IRO parancs, amelynek a CELJAT meg tudjuk nezni (wget, sqlite3), es (2) olyan
# parancs, amelynek a cele a parancssorbol NEM olvashato ki, mert a programjat maga olvassa be (vim/ex/ed a
# -c-bol vagy a stdin-rol, patch a diff fejleceibol, emacs --eval). Az utobbira nincs "ellenorizd a celt":
# a Ponder-nek Write/Edit eszkoze van, szerkesztore nincs szuksege, ezert ott a tiltas a helyes dontes.
_CONFINED_EDITORS = frozenset({'vim', 'vi', 'ex', 'view', 'vimdiff', 'nvim', 'rvim', 'rview', 'gvim', 'gview',
                               'ed', 'red', 'patch', 'emacs'})
# wget: ertekes rovid kapcsolok, es az, hogy melyik IR (o/a naplo, O dokumentum, P konyvtar).
_WGET_SHORT_VALUE = set('OoaPeiBtwTQlARDUIX')
_WGET_LONG_WRITE = ('--output-document', '--directory-prefix', '--output-file', '--append-output',
                    '--save-cookies', '--rejected-log', '--warc-file', '--hsts-file')
# wgetrc-parancsok (`-e`), amelyek nem irnak es nem iranyitanak at: a robots=off a leggyakoribb.
_WGET_E_SAFE = ('robots', 'user_agent', 'header', 'timeout', 'read_timeout', 'connect_timeout', 'dns_timeout',
                'tries', 'wait', 'waitretry', 'retry_connrefused', 'retry_on_http_error')


def _wget_write_targets(toks, argstart):
    """(celok, hiba): a wget altal IRT utak, vagy (None, indok), ha a parancssorbol nem eldontheto.
    A fajlnev nelkuli letoltes a `-P` konyvtarba (vagy a munkakonyvtarba) irja, ezt `.` jelzi."""
    args = [t for t, _sp in toks[argstart:]]
    targets, out_doc, prefix, spider = [], None, None, False
    i = 0
    while i < len(args):
        a = args[i]
        i += 1
        if a == '--':
            break
        val = None
        if a.startswith('--'):
            name, eq, v = a.partition('=')
            if name == '--spider':
                spider = True
            if name in ('--execute',):
                val = v if eq else (args[i] if i < len(args) else '')
                i += 0 if eq else 1
                key = val.split('=', 1)[0].strip()
                if key not in _WGET_E_SAFE:
                    return None, 'wget -e/--execute: a wgetrc-parancs (%s) atiranyithatja az irast' % key[:40]
                continue
            if name in _WGET_LONG_WRITE:
                val = v if eq else (args[i] if i < len(args) else None)
                i += 0 if eq else 1
                if val is None:
                    return None, 'wget %s ertek nelkul' % name
                if name == '--output-document':
                    out_doc = val
                elif name == '--directory-prefix':
                    prefix = val
                else:
                    targets.append(val)
            continue
        if a.startswith('-') and len(a) > 1:
            letters = a[1:]
            for pos, ch in enumerate(letters):
                if ch == 'n':
                    break                                # -nv, -nc, -nd, -nH, -np: ketbetus, ertek nelkuli
                if ch in _WGET_SHORT_VALUE:
                    rest = letters[pos + 1:]
                    if rest:
                        val = rest
                    elif i < len(args):
                        val, i = args[i], i + 1
                    else:
                        return None, 'wget -%s ertek nelkul' % ch
                    if ch == 'O':
                        out_doc = val
                    elif ch == 'P':
                        prefix = val
                    elif ch in 'oa':
                        targets.append(val)
                    elif ch == 'e':
                        key = val.split('=', 1)[0].strip()
                        if key not in _WGET_E_SAFE:
                            return None, 'wget -e: a wgetrc-parancs (%s) atiranyithatja az irast' % key[:40]
                    break
            continue
    if out_doc is not None and out_doc != '-':
        targets.append(out_doc)
    if prefix is not None:
        targets.append(prefix)
    if out_doc is None and not spider:
        targets.append(prefix if prefix is not None else '.')
    return targets, None


_SQLITE_DOT_WRITE = re.compile(
    r'(?:^|[\s\'"])\.(output|once|save|backup|clone|log|trace|excel|www|open|shell|system)\b[ \t]*([^\n\'";]*)')
_SQLITE_VALUE_OPTS = ('-cmd', '-init', '-separator', '-newline', '-nullvalue', '-vfs', '-key', '-mmap', '-maxsize',
                      '-heap', '-pagecache', '-lookaside', '-ascii', '-html')


def _sqlite_write_targets(raw, toks, argstart):
    """(celok, hiba): a sqlite3 altal IRT fajlok. A DB-fajl maga (ha nincs -readonly), es a .output / .once /
    .save / .backup / .clone / .log / .trace / .excel / .open dot-parancsok cele a PARANCS TELJES SZOVEGEBEN
    (argumentum, -cmd, heredoc). A .shell / .system tetszoleges parancsot futtat: ott nincs cel, tehat hiba."""
    targets = []
    for m in _SQLITE_DOT_WRITE.finditer(raw):
        cmd, rest = m.group(1), m.group(2).strip()
        if cmd in ('shell', 'system'):
            return None, 'sqlite3 .%s tetszoleges parancsot futtat' % cmd
        words = [w for w in rest.replace('"', ' ').split() if not (w.startswith('-') and w != '-')]
        if not words:
            continue                                     # `.output` argumentum nelkul: vissza a stdout-ra
        if words[0] in ('stdout', 'off', '-'):
            continue
        targets.append(words[0])
    args = [t for t, _sp in toks[argstart:]]
    readonly = '-readonly' in args
    i, db = 0, None
    while i < len(args):
        a = args[i]
        i += 1
        if a.startswith('-') and len(a) > 1:
            if a in _SQLITE_VALUE_OPTS:
                i += 1
            continue
        db = a
        break
    if db is not None and not readonly and not db.startswith('.') and db not in (':memory:', ''):
        targets.append(db)
    return targets, None


def _check_confined_segment(seg, toks, names, cwd, raw='', known=None):
    """A korlatozott agens (CONFINED_WRITE_AGENTS) egy szegmense: atiranyitas + irast vegzo parancs."""
    for tgt in _redirect_targets(seg):
        ok, why = _confined_write_ok(tgt, cwd, known) if tgt is not None else (False, 'nem eldontheto atiranyitas-cel')
        if not ok:
            block('Iras (atiranyitas), amit a kapu nem engedhet at: %s.\nEz az agens (%s) csak a sajat '
                  'munkateruleten ir. Ha tenyleg kell: szolj a fo agensnek (%s).\n(a teljes szegmens: %s)'
                  % (why, OWN_AGENT, _main_agent_id(), seg[:160]))
    for name, argstart in names:
        base = _cname(name)
        if base in _CONFINED_EDITORS:
            block('Iras, amit a kapu nem engedhet at: a(z) %s a programjat a -c/+parancsbol, a stdin-rol vagy a '
                  'diff fejleceibol veszi, tehat a parancssorbol nem latszik, MIRE ir.\nEz az agens (%s) '
                  'szerkesztot nem hasznalhat: Write/Edit eszkoze van, az a sajat teruleten belul iranyitott. '
                  'Ha tenyleg kell: szolj a fo agensnek (%s).\n(a teljes szegmens: %s)'
                  % (base, OWN_AGENT, _main_agent_id(), seg[:160]))
        if base not in ('dd', 'wget', 'sqlite3') and base not in _WRITE_VERB_VALUE_OPTS:
            continue
        if base == 'wget':
            targets, why = _wget_write_targets(toks, argstart)
        elif base == 'sqlite3':
            targets, why = _sqlite_write_targets(raw or seg, toks, argstart)
        else:
            targets, why = _verb_write_targets(base, toks, argstart, cwd), None
        if targets is None:
            block('Iras (%s), amit a kapu nem engedhet at: %s.\nEz az agens (%s) csak a sajat munkateruleten ir. '
                  'Ha tenyleg kell: szolj a fo agensnek (%s).\n(a teljes szegmens: %s)'
                  % (base, why, OWN_AGENT, _main_agent_id(), seg[:160]))
        if any(_cname(t) == 'xargs' for t, _sp in toks[:argstart]):
            # az utakat a cso adja, a kapu nem latja: nem eldontheto, tehat BLOKK (mint a torlesnel)
            targets = targets + [None]
        for tgt in targets:
            if tgt is None:
                block('Iras (%s xargs-on at), amit a kapu nem engedhet at: nem latszik, MIRE ir (a lista a '
                      'csobol jon).\nEz az agens (%s) csak a sajat munkateruleten ir. Ha tenyleg kell: szolj '
                      'a fo agensnek (%s).\n(a teljes szegmens: %s)' % (base, OWN_AGENT, _main_agent_id(), seg[:160]))
            ok, why = _confined_write_ok(tgt, cwd, known)
            if not ok:
                block('Iras (%s), amit a kapu nem engedhet at: %s.\nEz az agens (%s) csak a sajat '
                      'munkateruleten ir. Ha tenyleg kell: szolj a fo agensnek (%s).\n(a teljes szegmens: %s)'
                      % (base, why, OWN_AGENT, _main_agent_id(), seg[:160]))


# A fleet override switch, or a variable that moves git's hooks or config, SET anywhere on a command line that mentions git (Sam round 1,
# SEVERE 2/3: `export SKIP_SECRET_GATE=1; git commit`, `HOME=/tmp/h; git commit`, `bash -c`/`env` wrappers). The prefix form is judged in
# _git_hook_class; this is the rest. The assignment is found in the SHELL text (data heredocs and prose strings are blanked), a
# `bash -c '...'` body is judged again by the recursion.
_GIT_WORD = re.compile(r'(?<![\w.-])git(?![\w-])')


_IDENT = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*$')
# Round 2 of card f4057869 (Sam msg 3841, HEX 3844): INVERTED PROOF for the environment. Round 3 of dafb69db derived the protected names
# from the hook files' text, and the runtimes that RUN the hooks read their own names outside that text: bash (BASH_ENV, ENV, SHELLOPTS,
# PS4, BASH_FUNC_*), python (PYTHONPATH, PYTHONSTARTUP), node (NODE_OPTIONS, NODE_PATH), the loader (LD_*). Sam measured `BASH_ENV=f git
# commit` switching off every bash hook at once. So nothing is listed as dangerous any more: on a line that runs git, an environment name
# may be given to a child process only if it is on this short allowlist, or is not all upper case (script variables: no runtime above reads
# a lower-case name for its own behaviour; named limit). IFS is allowlisted on a MEASUREMENT (2026-10-14): `IFS=Q git commit` with a bash
# pre-commit hook printing $IFS shows the default ' \t\n', bash ignores IFS from the environment (`while IFS= read -r l` is everywhere). Everything else (PATH, HOME, LD_PRELOAD, BASH_ENV, CLAUDECODE ...) is a deny.
# ff9a0528 round 2 (Sam 1772 SEVERE 1): GIT_EDITOR, GIT_SEQUENCE_EDITOR, GIT_PAGER and GIT_ASKPASS are NOT on this list. Their value is a
# PROGRAM git runs, and they are already exported in a normal session (printenv GIT_EDITOR = true), so ANY way of giving one a value
# reaches the child git: `GIT_EDITOR+='; touch m'`, `printf -v GIT_EDITOR`, `read GIT_EDITOR`, `for GIT_EDITOR in`, ... The earlier
# version read only the `NAME=value` token. Now every binding form is judged by the generic machinery below (the name is "dangerous"),
# and the only thing let through is the plain `NAME=<no-op literal>` word, in the prefix or `export` position (_prog_env_noop_assignment).
_PROG_ENV_NAME = re.compile(r'^GIT_(?:EDITOR|SEQUENCE_EDITOR|PAGER|ASKPASS)$')
_ENV_ALLOW = re.compile(
    r'^(?:GIT_(?:AUTHOR|COMMITTER)_(?:NAME|EMAIL|DATE)|GIT_(?:TERMINAL_PROMPT|MERGE_AUTOEDIT)'
    r'|GH_TOKEN|GITHUB_TOKEN|GH_PROMPT_DISABLED|LANG|LANGUAGE|LC_[A-Z]+|TZ|NO_COLOR|FORCE_COLOR|CI|TERM|COLUMNS|LINES|IFS)$')


def _prog_env_noop_assignment(word):
    """True for exactly `GIT_EDITOR=<no-op literal>` (and the other three names): the one binding of a program-valued name that is
    provably harmless (the value is on _GIT_NOOP_PROGRAMS). `+=`, an array element, an expansion or any other value is not."""
    m = _GIT_PROG_ENV.match(word)
    return bool(m) and m.group(2) in _GIT_NOOP_PROGRAMS


def _env_name_dangerous(name):
    """True when `name` must not reach a child process on a line that runs git (allowlist, see above): export, a prefix assignment,
    `env NAME=`, `unset`, `env -u`. A name with a lower-case letter is a script variable and is free."""
    if _ENV_ALLOW.match(name):
        return False
    return not re.search(r'[a-z]', name)


def _env_name_rebound(name):
    """True when plain (un-exported) binding of `name` can still change a child's environment: the name is dangerous AND it is already
    in the environment this session was started with (this gate process inherits it). A shell variable that is not exported cannot
    reach git, so a script variable like `SP=...` or `B=...` is free unless it names something already exported (CLAUDECODE, PATH ...).
    `set -a` and `export` are denied separately, so a later export cannot turn the plain binding into an exported one."""
    # The four program-valued git names count as bound whether or not THIS session exports them today: what a name holds is a program git
    # runs, and `export` / `set -a` / a prefix on a later segment are the next step away (ff9a0528 round 2: proof, not a look at os.environ).
    return _env_name_dangerous(name) and (name in os.environ or bool(_PROG_ENV_NAME.match(name)))


_ENV_ASSIGN_AT = re.compile(r'(?<![\w$.\-/])([A-Za-z_]\w*)(?:\[[^\]\n]*\])?\+?=')
_ENV_ASSIGN_TOK = re.compile(r'^([A-Za-z_]\w*)(?:\[[^\]]*\])?\+?=')


def _env_set_for_git(text, cmd):
    """`NAME=value` words on a line that runs git, judged by POSITION in their own simple command (bash's rule): an assignment BEFORE the
    command word is a prefix assignment, it goes to that command's environment (and to everything it starts): strict allowlist. A segment
    made only of assignments sets shell variables: denied only when the name is already exported (`_env_name_rebound`). Assignments after
    the command word are arguments (`export NAME=v`, `declare`, `git -c k=v`); the verbs are judged in _env_verbs_for_git."""
    if not _GIT_WORD.search(cmd):
        return None
    for seg in segments(text):
        toks = [t for t, _sp in _bare_tokens(_strip_funcdef(seg))]
        cut = next((k for k, t in enumerate(toks) if t.startswith('#')), None)
        if cut is not None:
            toks = toks[:cut]                  # a trailing `# comment` is not a command word: `OLD=abc  # note` is a plain assignment
        idx = command_index([(t, False) for t in toks])
        prefix = idx is not None
        for pos, t in enumerate(toks if not prefix else toks[:idx]):
            m = _ENV_ASSIGN_TOK.match(t)
            if not m or not _env_name_dangerous(m.group(1)) or _prog_env_noop_assignment(t):
                continue
            if prefix or _env_name_rebound(m.group(1)):
                return m.group(1)
    return None


def _env_target_bad(word, exported=False):
    """A word that names a variable to be created, changed or removed: bad when it is not a plain identifier (computed: `$V`,
    `{A,B}`, quote fragments, `${...}`), or when the identifier is dangerous for what the construct does: `exported=True` for the ones
    that put a name into a child's environment (export, declare -x, unset, env -u), else only for a name that is already exported."""
    name = word.split('=', 1)[0]
    if not _IDENT.match(name):
        return True
    if _prog_env_noop_assignment(word):
        return False                                # `export GIT_EDITOR=true`: the one provably harmless binding
    return _env_name_dangerous(name) if exported else _env_name_rebound(name)


_ENV_DECL_VERBS = {'export', 'declare', 'typeset', 'readonly', 'local'}
_ENV_READ_VERBS = {'read', 'mapfile', 'readarray'}


_ARITH_RE = re.compile(r'\(\((.*?)\)\)', re.S)
_ARITH_ASSIGN = re.compile(r'([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*(?:[-+*/%&|^]|<<|>>)?=(?!=)|(?:\+\+|--)\s*([A-Za-z_]\w*)|([A-Za-z_]\w*)\s*(?:\+\+|--)')
_PARAM_ASSIGN = re.compile(r'\$\{([A-Za-z_]\w*)(?:\[[^\]]*\])?:?=')
_FD_VAR = re.compile(r'(?<![\w$])\{([A-Za-z_]\w*)\}\s*(?:[<>]|&>)')
_CMD_LEAD = {'do', 'then', 'else', 'elif', '{', '(', '!', 'time', '&&', '||', '|', '&', ';', 'builtin', 'command'}


def _sourced_file_unclean(path):
    """A file that is `source`d (or `.`) on a line that runs git can bind anything. Silent only when the file is a literal path the gate
    can read (a leading `~` is expanded) and it assigns or exports no dangerous name, and holds no `set -a` / `export -f`; a path made in
    the same command or an unreadable file is a deny. The content is only matched, never printed."""
    path = os.path.expanduser(path or '')
    if not path:
        return 'no path'
    try:
        if os.path.getsize(path) > 262144:
            return 'a file over 256 KB'
        with open(path, encoding='utf-8', errors='replace') as fh:
            text = fh.read()
    except OSError:
        return 'a file the gate cannot read'
    exported = set(re.findall(r'\b(?:export|(?:declare|typeset)\s+-\w*x\w*)\s+(?:-\w+\s+)*([A-Za-z_]\w*)', text))
    for name in exported:
        if _env_name_dangerous(name):
            return 'a file that exports %s' % name
    for name in set(_ENV_ASSIGN_AT.findall(text)):       # a plain binding reaches git only when the name is already exported
        if _env_name_rebound(name):
            return 'a file that assigns %s' % name
    if re.search(r'\bset\s+-[a-zA-Z]*a|\ballexport\b|\bexport\s+-[a-zA-Z]*f', text):
        return 'a file with set -a / export -f'
    return None


def _env_binding_forms(seg, toks):
    """Round 4 (Sam round 3, card f4057869): every OTHER way bash gives a variable a value, besides `NAME=` and the verbs
    _env_verbs_for_git reads: `for NAME in`, `select NAME in`, `getopts o NAME`, `let NAME=`, `(( NAME=.. ))` / `$(( ))`, `${NAME:=x}`,
    `{NAME}>file` (the fd number), `NAME+=`, `NAME[i]=`, `coproc NAME {`, `wait -p NAME`, a nameref (`declare -n`) and `source`/`.`.
    Sam measured `for CLAUDECODE in ""; do git push ...` with real bash: the loop variable empties the exported name in the child.
    A finite grammar, not a list of spellings: these are the places the bash grammar can bind a name. A hook-read name (or a target that
    is not a plain identifier) in any of them is a deny."""
    n = len(toks)
    for k, w in enumerate(toks):
        lead = k == 0 or toks[k - 1] in _CMD_LEAD
        if lead and w in ('for', 'select') and k + 1 < n and not toks[k + 1].startswith('(('):
            if _env_target_bad(toks[k + 1]):
                return '%s %s' % (w, toks[k + 1][:30])
        elif lead and w == 'getopts' and k + 2 < n:
            if _env_target_bad(toks[k + 2]):
                return 'getopts %s' % toks[k + 2][:30]
        elif lead and w == 'let':
            for a in toks[k + 1:]:
                m = re.match(r'[A-Za-z_]\w*', a)
                if not m or _env_name_rebound(m.group(0)):
                    return 'let %s' % a[:30]
        elif lead and w == 'coproc' and k + 2 < n and toks[k + 2] == '{':
            if _env_target_bad(toks[k + 1]):
                return 'coproc %s' % toks[k + 1][:30]
        elif lead and w == 'wait':
            for a, b in zip(toks[k + 1:], toks[k + 2:]):
                if a == '-p' and _env_target_bad(b):
                    return 'wait -p %s' % b[:30]
        elif lead and w in ('source', '.') and k + 1 < n:
            why = _sourced_file_unclean(toks[k + 1])
            if why:
                return '%s %s (%s)' % (w, toks[k + 1][:40], why)
        elif lead and w == 'set':
            for a, b in zip(toks[k + 1:], toks[k + 2:] + ['']):
                if (a.startswith('-') and not a.startswith('--') and 'a' in a[1:]) or (a == '-o' and b == 'allexport'):
                    return 'set %s (allexport turns every later assignment into a child environment variable)' % a
        elif lead and w == 'exec':
            for a in toks[k + 1:]:
                if not a.startswith('-'):
                    break
                if a == '-c' or (not a.startswith('--') and 'c' in a[1:]):
                    return 'exec %s (starts the command with an empty environment)' % a
        elif lead and _cname(w) in _ENV_DECL_VERBS:
            for a in toks[k + 1:]:
                if a.startswith('-') and not a.startswith('--') and 'n' in a[1:]:
                    return '%s %s (a nameref hides the name it binds)' % (w, a)
                if a.startswith('-') and not a.startswith('--') and 'f' in a[1:] and _cname(w) in ('export', 'declare', 'typeset'):
                    return '%s %s (an exported function becomes BASH_FUNC_name in every child bash)' % (w, a)
    for m in _ARITH_RE.finditer(seg):
        for g in _ARITH_ASSIGN.findall(m.group(1)):
            name = next((x for x in g if x), '')
            if name and _env_name_rebound(name):
                return '(( %s ))' % name
    for rx in (_PARAM_ASSIGN, _FD_VAR):
        for m in rx.finditer(seg):
            if _env_name_rebound(m.group(1)):
                return m.group(0)[:40]
    return None


def _env_verbs_for_git(text, cmd):
    """Round 3 (Sam round 2, SEVERE 2a): the ways to give, change or REMOVE a variable that carry no literal `NAME=` --
    `read NAME`, `printf -v NAME`, `export {A,B}=1`, `export S''KIP...=1`, `V=...; export $V=1`, `unset NAME`, `env -u NAME`, `env -i`.
    Inverted proof (round 2 of f4057869: an allowlist, not a derived list): on a line that runs git, every target of these verbs must be
    a plain identifier that is allowlisted, lower case, or (for a plain binding) not already exported; a computed target is a deny.
    Returns a short description of the first offender, else None."""
    if not _GIT_WORD.search(cmd):
        return None
    for seg in segments(text):
        toks = [t for t, _sp in _bare_tokens(_strip_funcdef(seg))]
        found = _env_binding_forms(seg, toks)
        if found:
            return found
        idx = command_index([(t, False) for t in toks])
        if idx is None:
            continue
        verb = _cname(toks[idx])
        args = toks[idx + 1:]
        envk = next((k for k, w in enumerate(toks[:idx + 1]) if _cname(w) == 'env'), None)
        if envk is not None and verb != 'env':
            verb, args = 'env', toks[envk + 1:]            # `env` is a wrapper: command_index looks through it to the command
        if verb in _ENV_DECL_VERBS:
            # `export` and `declare|typeset -x` put the name into every child's environment (strict allowlist); the rest bind a shell
            # variable (dangerous only when the name is already exported)
            exported = verb == 'export' or any(a.startswith('-') and not a.startswith('--') and 'x' in a[1:] for a in args)
            for w in args:
                if re.match(r'^\[[^\]]*\]=', w):
                    continue                               # an element of `declare -A NAME=( [k]=v ... )` is a value, not a variable
                if not w.startswith('-') and _env_target_bad(w, exported):
                    return '%s %s' % (verb, w[:30])
        elif verb in _ENV_READ_VERBS:
            skip = False
            for w in args:
                if skip:
                    skip = False
                    continue
                if w[:1] in '<>' and w:
                    skip = w in ('<', '<<', '<<<', '>', '>>')
                    continue
                if not w.startswith('-') and _env_target_bad(w):
                    return '%s %s' % (verb, w[:30])
        elif verb == 'unset':
            for w in args:
                if not w.startswith('-') and _env_target_bad(w):      # removing a name that is not in the environment is a no-op
                    return 'unset %s' % w[:30]
        elif verb == 'printf':
            for k, w in enumerate(args[:-1]):
                if w == '-v' and _env_target_bad(args[k + 1]):
                    return 'printf -v %s' % args[k + 1][:30]
            for w in args:
                if w.startswith('-v') and len(w) > 2 and _env_target_bad(w[2:]):
                    return 'printf %s' % w[:30]
        elif verb == 'env':
            k = 0
            while k < len(args):
                w = args[k]
                if w in ('-i', '-', '--ignore-environment') or (w.startswith('-') and not w.startswith('--') and 'i' in w[1:] and not w.startswith('-u')):
                    return 'env %s (empties the environment)' % w
                if w in ('-u', '--unset') and k + 1 < len(args):
                    if _env_target_bad(args[k + 1]):
                        return 'env -u %s' % args[k + 1][:30]
                    k += 2
                    continue
                if w.startswith('--unset=') and _env_target_bad(w[8:]):
                    return 'env %s' % w[:30]
                if w.startswith('-u') and len(w) > 2 and _env_target_bad(w[2:]):
                    return 'env %s' % w[:30]
                if w.startswith('-') or re.match(r'^[A-Za-z_]\w*=', w):
                    k += 1
                    continue
                break
    return None


_RAW_CMD = ''       # the command as typed (quoted values intact), for the few checks that must read inside quotes


def check_bash(cmd, _depth=0, cwd=None):
    global _RAW_CMD
    cmd = _normalize_continuations(cmd)
    saved, _RAW_CMD = _RAW_CMD, cmd
    try:
        return _check_bash(cmd, _depth, cwd)
    finally:
        _RAW_CMD = saved


def _check_bash(cmd, _depth=0, cwd=None):
    text = scannable(cmd)
    # A backslash-newline is a LINE CONTINUATION: the shell reads `git \<NL> push --force` as ONE command. check_bash has already
    # removed the real ones (_normalize_continuations, card 798c3c24); the blind replace that stood here read an escaped backslash, a
    # comment and a single-quoted string as continuations too, and turned `r\<NL>m` into `r  m`.
    _env = _env_set_for_git(_blank_ranges(text, _foreign_code_ranges(cmd) + _script_arg_ranges(text)), cmd)    # a python/node body is not shell text (check_payload judges it)
    if _env:
        block('%s=... egy olyan parancssorban, amely a gitet emliti: a kapukat kikapcsolo felulbiralo, illetve a git hook-/config-kereseset '
              'atiranyito valtozo nem csak a git elotagjakent (export, onallo ertekadas, env, bash -c) tiltott. Nem az ugynok dontese.' % _env)
    _verb = _env_verbs_for_git(_blank_ranges(text, _foreign_code_ranges(cmd) + _script_arg_ranges(text)), cmd)
    if _verb:
        block('%s: egy olyan parancssorban, amely a gitet emliti, a hookok altal olvasott (vagy nem kiolvashato nevu) kornyezeti valtozot '
              'allit, torol vagy uriti. A kapu az ertekadas minden alakjat latja, nem csak a NEV=ertek alakot. Nem az ugynok dontese.' % _verb)
    literal = {}
    if OPAQUE_COMMAND_BLOCK:
        # Csak SHELL-szoveg: az interpreternek adott torzs (python3 - <<PY) es a -c/eval szkriptek
        # nem ide tartoznak (utobbiakat a rekurzio kulon vizsgalja).
        shell_text = _blank_ranges(text, _foreign_code_ranges(cmd) + _script_arg_ranges(text))
        opaque = _opaque_substitution(shell_text)
        if opaque:
            block('A parancsnev behelyettesitesbol jon (%s): a kapu a szoveget latja, nem azt, ami '
                  'kifejtes utan fut, ezert nem tudja eldonteni, MI a parancs, es nem engedi at. '
                  'Ird ki a parancs nevet.' % opaque)
        literal = _literal_assignments(shell_text)
        if not _HM_LOSSY[0]:
            # The brace / glob rule (card 4b42b6b0 round 3) reads the REAL command: the text the loop below segments (`scannable`) has quoted prose and
            # comments blanked, so its quote map and its segment borders are not the shell's. Only what is not shell text at all (the data heredoc
            # bodies and the other languages' bodies) is blanked here; a -c / -e program stays: it is QUOTED, the shell reader says so, and its content is
            # checked on its own by the recursion (blanking it, as `shell_text` does, over-reaches in a nested `"$(python3 -c "..")"`).
            _real = _blank_ranges(cmd, _heredoc_body_ranges(cmd)[0])
            _real = _blank_ranges(_real, _foreign_code_ranges(cmd))
            _proof = _proof_of(_real)
            for seg, seg_pos in segments_pos(_real):
                _seg0 = seg
                seg = _strip_funcdef(seg)
                seg_pos += len(_seg0) - len(seg)
                toks = _bare_tokens(seg)
                idx = command_index(toks)
                if idx is None or (idx > 0 and toks[idx - 1][0] in _CMD_WORD_KW):
                    continue
                why = _unreadable_command_word(_real, seg, seg_pos, idx, _proof)
                if why:
                    block('A parancsnev idezetlen {..} vagy * ? [..] karaktert vagy kifejtest tartalmaz (%s; %s): a shell ebbol kifejtes utan MAS nevet csinal '
                          '(`{rm,-f,x}`, `r{m,}`, `/usr/bin/r[m]`, `${X}rm`, `r$(echo m)`), a kapu a szoveget latja, ezert nem tudja eldonteni, MI a parancs, '
                          'es nem engedi at. Ird ki a parancs nevet.\n(a teljes szegmens: %s)' % (toks[idx][0], why, seg[:160]))
        for seg in segments(shell_text):
            seg = _strip_funcdef(seg)
            toks = _bare_tokens(seg)
            idx = command_index(toks)
            if idx is None or toks[idx][1] or (idx > 0 and toks[idx - 1][0] in _CMD_WORD_KW):
                continue
            vm = _VAR_NAME_RE.match(toks[idx][0])
            if vm and literal.get(vm.group(1) if vm.group(1) is not None else vm.group(2)) is None:
                block('A parancsnev valtozobol jon (%s): a kapu nem tudja, mi az erteke, ezert nem '
                      'tudja eldonteni, MI a parancs, es nem engedi at. Ird ki a parancs nevet.\n'
                      '(a teljes szegmens: %s)' % (toks[idx][0], seg[:160]))
    # A munkakonyvtar szegmensrol szegmensre valtozhat (`cd X && rm y`), ezert
    # vegigvisszuk. Ismeretlen (None) cwd eseten a relativ utak nem eldonthetok, es a
    # nem eldonthetot a kapu nem engedi at.
    if cwd is not None:
        cwd = os.path.normpath(os.path.expanduser(cwd))
    entry_cwd, saw_cd = cwd, False
    # the head-move gate follows the working directory on its own (candidates, literal variables, `pushd` and friends = unknown)
    # (CDPATH changes where a `cd` lands in a way the gate cannot enumerate: it gives up. Physical vs logical `cd ..` it enumerates.)
    hm_cwd = None if (cwd is None or re.search(r'\bCDPATH\b', text)) else [cwd]
    hm_fallback, hm_prev_end = [], None
    # Symlinket LETREHOZO parancs ugyanabban a sorban (`ln -s /cel l && rm -rf l/`): a link a
    # kapu verdiktjekor MEG NEM LETEZIK, tehat a torles celja nem feloldhato. Nem teljes:
    # mas utak is hoznak linket (cp -s, tar, git), azokat nem latjuk -- a kapu a VELETLEN ellen
    # ved, es a mar LETEZO linkeket realpath-szal feloldja.
    if _ENV_SPLIT_RE.search(text):
        block('env -S/--split-string: a kapcsolo erteke egy teljes parancssor, amit a kapu '
              'nem tud vegigkovetni, ezert nem engedi at.')
    makes_links = bool(re.search(r'(?<![\w./-])ln(?=\s)|symlink', text))
    known = {}          # literal valtozok, amelyek egy KORABBI szegmensben kaptak erteket (iras-cel feloldashoz)
    foreign = _foreign_code_ranges(cmd)
    for seg, seg_pos in segments_pos(text):
        _sep = text[hm_prev_end:seg_pos].strip() if hm_prev_end is not None else ''
        hm_prev_end = seg_pos + len(seg)
        if hm_fallback and re.sub(r'\s+', '', _sep) != '&&':
            hm_cwd = None if hm_cwd is None else sorted(set(hm_cwd) | set(hm_fallback))      # a failed `cd` falls through
            hm_fallback = []
        seg0 = seg
        seg = _strip_funcdef(seg)
        toks = _bare_tokens(seg)
        idx = command_index(toks)
        if OPAQUE_COMMAND_BLOCK and idx is not None and not toks[idx][1]:
            vm = _VAR_NAME_RE.match(toks[idx][0])
            val = literal.get(vm.group(1) if vm.group(1) is not None else vm.group(2)) if vm else None
            if val is not None:
                # a literal, ezen a parancssoron egyszer kapott ertek: a FELOLDOTT nev kerul vizsgalatra
                toks[idx] = (val, False)
                idx = command_index(toks)

        # A vizsgalando parancsnevek: a szegmens sajat parancsa, plusz a find -exec
        # utan allo parancs (az nem a szegmens elejen all, ezert kulon). Az argumentumok
        # kezdoindexe is kell, mert a feltetelesen engedett parancsok (rm, git) esetén
        # nem a nev, hanem az ARGUMENTUMOK dontik el a verdiktet.
        if idx is not None and not toks[idx][1]:
            dashed = _dashed_git_sub(toks[idx][0])
            if dashed:
                toks[idx:idx + 1] = [('git', False), (dashed, False)]       # /usr/lib/git-core/git-send-pack == git send-pack
        names = []
        # Az idezojelen belul SZOKOZT tartalmazo szo nem parancsnev, hanem karakterlanc
        # (teszteset-lista, uzenet-szoveg, regex-minta) -- lasd ba856d56.
        if idx is not None and not toks[idx][1]:
            names.append((toks[idx][0], idx + 1))
        for j, (t, _sp) in enumerate(toks):
            if t in _FIND_EXEC and j + 1 < len(toks) and not toks[j + 1][1]:
                names.append((toks[j + 1][0], j + 2))

        if OWN_AGENT in CONFINED_WRITE_AGENTS:
            _check_confined_segment(seg, toks, names, cwd, cmd, known)
        known.update(_standalone_assignments(toks, literal))

        # A git config HELYET (vagy tartalmat) atiranyito kornyezeti valtozok: az atiranyitott fajl
        # barmit mondhat, es a tenyleges-ertek lekerdezes nem latja azt a fajlt, amelyet ugyanez a
        # parancs hoz letre. Sima munkafolyamathoz nem kellenek, ezert maguk tiltottak (Sam, 2. kor).
        if re.search(r'(^|[\s;&|(])(export\s+)?(GIT_CONFIG_(GLOBAL|SYSTEM|NOSYSTEM|COUNT|PARAMETERS'
                     r'|KEY_\d+|VALUE_\d+)|GIT_CONFIG|XDG_CONFIG_HOME)=', seg):
            block('GIT_CONFIG_* / XDG_CONFIG_HOME kornyezeti valtozo: a git config forrasat atiranyito '
                  'alak, a pre-push/pre-commit kapukat kikapcsolhatja. Nem az ugynok dontese.')
        if idx is not None and os.path.basename(toks[idx][0]) == 'git' and any(
                re.match(r'^HOME=', t) for t, _sp in toks[:idx]):
            block('HOME= atiranyitas a git elott: a felhasznaloi gitconfig helyet cserelne le. '
                  'Nem az ugynok dontese.')
        # GIT_EDITOR / GIT_SEQUENCE_EDITOR / GIT_PAGER / GIT_ASKPASS: allowed names, but git runs the VALUE (card ff9a0528)
        if idx is None:
            _git_program_env(toks)
        else:
            _git_program_env(toks[:idx])
            if _cname(toks[idx][0]) in _ENV_DECL_VERBS or _cname(toks[idx][0]) == 'env':
                _git_program_env(toks[idx + 1:])

        for name, argstart in names:
            base = _cname(name)
            _check_hooks_dir(base, toks, argstart, seg, cwd)
            if base == 'git':
                _LITERALS.clear()
                _LITERALS.update(literal)
                _LITERALS.update(known)
                tail = text[seg_pos + len(seg):].lstrip(' \t')
                _check_git(toks, argstart, cwd, idx, in_code=any(a <= seg_pos < b for a, b in foreign),
                           tail_subst=tail.startswith('$(') or tail.startswith('`'), hm_cwd=hm_cwd,
                           hm_raw=_hm_raw_toks(cmd, text, seg_pos, seg0))
                continue
            if base == 'gh':
                _check_gh(toks, argstart)
                continue
            if base == 'find':
                _check_find_delete(toks, argstart, cwd, makes_links, seg)
                continue
            if base in RM_FAMILY or (base == 'rmdir' and OWN_AGENT in NO_DELETE_AGENTS):
                ok, why = _rm_allowed(toks, argstart, cwd, links=makes_links)
                if not ok:
                    if OWN_AGENT in NO_DELETE_AGENTS:
                        extra = ('Ez az agens (%s) nem torolhet semmit, a sajat munkateruleten sem '
                                 '(a terv szerint). Ha tenyleg kell: szolj a fo agensnek (%s).'
                                 % (OWN_AGENT, _main_agent_id()))
                    elif _live_install(PROJECT_ROOT):
                        own = _own_area(OWN_AGENT)
                        own_txt = (('Torolni csak a sajat munkateruleten szabad: %s.' % own)
                                   if own else
                                   'A hivo agens azonositasa nem sikerult, ezert sajat '
                                   'munkaterulete sincs.')
                        if why.startswith('ez ELES'):
                            extra = ('Ez ELES telepites gyokere (%s): itt a munkakonyvtar-szabaly '
                                     'nem all. %s' % (PROJECT_ROOT, own_txt))
                        else:
                            extra = ('Raadasul ez ELES telepites gyokere (%s): itt a '
                                     'munkakonyvtar ALATTI torles sem engedett. %s'
                                     % (PROJECT_ROOT, own_txt))
                    else:
                        extra = ('A munkakonyvtar (%s) ALATTI torles alapbol szabad; ezen '
                                 'kivul, illetve a vedett utvonalakon (%s) nem.'
                                 % (PROJECT_ROOT,
                                    ', '.join('/'.join(p) for p in RM_PROTECTED)))
                    block('Torles, amit a kapu nem engedhet at: %s.\n%s\n'
                          '(a teljes szegmens: %s)' % (why, extra, seg[:160]))
                continue
            if base in BANNED_CMDS:
                block('A tiltott parancs: "%s" (a teljes szegmens: %s)' % (base, seg[:160]))

        # A `cd` a KOVETKEZO szegmensek munkakonyvtarat allitja. Nem eldontheto cel
        # eseten a cwd ismeretlenne valik, ami a kesobbi relativ torleseket blokkolja.
        if idx is not None and not toks[idx][1] and os.path.basename(toks[idx][0]) == 'cd':
            cwd = _cd_target(toks, idx + 1, cwd)
            saw_cd = True
            hm_cwd, _fb = _hm_cd(toks, idx + 1, hm_cwd, dict(literal, **known))
            hm_fallback = sorted(set(hm_fallback) | set(_fb)) if hm_cwd is not None else []
        elif idx is not None and not toks[idx][1] and os.path.basename(toks[idx][0]) in ('pushd', 'popd'):
            hm_cwd = None

        for sub in _sub_scripts(toks, idx):
            if not sub or sub == cmd:
                continue
            if _depth >= _MAX_NEST:
                block('Tul melyen agyazott parancs (%d szint): a kapu nem tudja '
                      'vegigkovetni, ezert nem engedi at.' % _depth)
            check_bash(sub, _depth + 1, cwd)

    # Az ertelmezo-burkon beluli payload (efccadab). A szegmens-ciklus UTAN fut,
    # mert nem a parancsnevrol szol: a burok parancsneve legitim (python3), a
    # payload tartalma nem. A payload a TELJES parancsbol jon, nem egy szegmensbol,
    # ezert ha barhol allt benne `cd`, a munkakonyvtar nem eldontheto -- None.
    for payload in interpreter_payloads(cmd):
        check_payload(payload, _depth, None if saw_cd else entry_cwd)
    for code in shell_stdin_programs(cmd) + dq_subst_programs(cmd):
        if code == cmd:
            continue
        if _depth >= _MAX_NEST:
            block('Tul melyen agyazott parancs (%d szint): a kapu nem tudja '
                  'vegigkovetni, ezert nem engedi at.' % _depth)
        check_bash(code, _depth + 1, None if saw_cd else entry_cwd)

    # A mutalo parancs csovezetekbol kapja a listat: a hook-ut nem az o argumentuma.
    if _HOOKS_PATH.search(' ' + text + ' ') and re.search(r'\b(xargs|parallel)\b', text):
        block('xargs/parallel egy .git/hooks vagy git config utat tartalmazo parancsban: a push/commit '
              'kapuk eltavolitasa vagy atirasa lehet. Nem az ugynok dontese.')

    # Hitelesito fajlok kiolvasasa barmilyen parancson keresztul.
    m = PROTECTED_RE.search(text)
    if m:
        block('Hitelesito adatokat tartalmazo konyvtar: .%s' % m.group(1))
    if ENV_RE.search(text):
        block('.env fajl: hitelesito adatokat tartalmaz.')


def check_read(path):
    m = PROTECTED_RE.search(path if path.endswith('/') else path + '/')
    if m:
        block('Hitelesito adatokat tartalmazo konyvtar: .%s' % m.group(1))
    if os.path.basename(path) == '.env':
        block('.env fajl: hitelesito adatokat tartalmaz.')


def main():
    raw = sys.stdin.read()
    try:
        ev = json.loads(raw)
    except Exception:
        # A tobbi governance-kapu is fail-closed ebben a repoban: ha a kapu nem tudja
        # elolvasni, mit engedelyezne, akkor nem engedelyez.
        sys.stderr.write('DESTRUKTIV-KAPU: a bemenet nem olvashato, ezert BLOKKOL.\n')
        sys.exit(2)
    tool = ev.get('tool_name') or ''
    inp = ev.get('tool_input') or {}
    # FAIL-CLOSED a kapu SAJAT hibajara is. A block() SystemExit-tel lep ki, azt a
    # BaseException-kent az "except Exception" nem fogja meg, tehat a valodi blokkolas
    # atmegy. Minden mas kivetel (rekurzio, regex, elgepeles egy kesobbi javitasban)
    # eddig NEM 2-es kilepessel vegzodott volna, vagyis a muvelet ATMENT volna: egy
    # elhasalt kapu csendben engedelyezove valik. Ez az egyetlen hibamod, amit egy
    # kapunal nem szabad megengedni.
    try:
        global OWN_AGENT
        OWN_AGENT = _agent_from_transcript(ev.get('transcript_path'))
        if tool == 'Bash':
            # A PreToolUse esemeny cwd-je a relativ utak feloldasahoz kell. Ha
            # hianyzik vagy nem a telepites alatt van, NEM helyettesitjuk a gyokerrel:
            # akkor a relativ torlesek egyszeruen nem eldonthetok, es blokkolodnak.
            ev_cwd = ev.get('cwd')
            if not (isinstance(ev_cwd, str) and ev_cwd.strip()):
                ev_cwd = None
            check_bash(str(inp.get('command') or ''), cwd=ev_cwd)
        elif tool in ('Read', 'Edit', 'Write', 'NotebookEdit'):
            # A NotebookEdit az utat `notebook_path`-ban hozza, nem `file_path`-ban.
            tpath = str(inp.get('file_path') or inp.get('notebook_path') or '')
            check_read(tpath)
            if tool != 'Read':
                check_gitcfg_write(tpath)
                check_write(tpath)
    except Exception as exc:
        sys.stderr.write('DESTRUKTIV-KAPU: a kapu maga hibara futott (%s: %s), ezert '
                         'BLOKKOL. Ez a kapu hibaja, nem a tied -- szolj a fo agensnek (%s).\n'
                         % (type(exc).__name__, exc, _main_agent_id()))
        sys.exit(2)
    sys.exit(0)


if __name__ == '__main__':
    main()
