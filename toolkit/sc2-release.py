#!/usr/bin/env python3
"""sc2-release.py -- the automatic release, held by a custodian.

  make   builds the custodian's kit: a letter (English and French), the public release
         note, the inner-envelope label, and YOUR cancellation codes.
  check  applies the cancellation rule to a log of notices and says where things stand:
         cancelled, release due, or waiting. The custodian and you get the same answer.
  code   prints the fingerprint of one code (the one-command check, in Python).

  python3 sc2-release.py make --release 2032-03-01 --published 2026-10-05 \\
          --contact you@example.org --entropy codes-dice.txt \\
          --link https://github.com/you/sc2-xxxx [--link ...] \\
          [--window 30-31] [--codes 24] [--out release-kit]
  python3 sc2-release.py check --start "STARTING VALUE" [--certain "RELEASE-CERTAIN VALUE"] \\
          --release 2032-03-01 [--window 30-31] [--today YYYY-MM-DD] LOGFILE
  python3 sc2-release.py code "PASTED CODE"

THE RULE (one implementation, used by `check`, printed in the letters, tested by the self-test
against a day-by-day simulation written from the letter's wording)
  * A code is ACCEPTED if its SHA-512 (lowercase hex) is the last accepted code -- or, before
    any was accepted, the STARTING VALUE. A code already accepted is ignored if it comes
    again; a rejected code is checked afresh if it comes again; codes arriving the same day
    are checked in arrival order, and rejected ones re-checked after each acceptance.
  * An accepted notice received LO..HI days after the previous accepted one continues the
    series; otherwise it starts a new series as number 1. Three in a row: cancelled.
  * Release day R. Notices received on R or later count as "after the date". On R: if no
    notice was accepted before R, or the last one arrived more than HI days before R,
    release on R. Otherwise a series is in progress: an accepted notice arriving from R on
    continues it if it comes LO..HI days after the previous one (at 3: cancel), and means
    release that day if it comes sooner; if none comes within HI days, release on day HI+1.
  * The RELEASE-CERTAIN code (its SHA-512 is printed in the letter): once accepted, no notice
    counts any more; release on R, or that same day if R has passed.
  So an impulse cannot cancel; a single notice can delay the release by at most HI days,
  and nothing short of a completed cancellation delays it by more than 2*HI days.

THE CODES
  A chain: code N is random; code k = SHA-512(code k+1); STARTING VALUE = SHA-512(code 1).
  Revealing code k tells nobody anything about code k+1. Codes are 512 bits, so forging the
  next one is a SHA-512 preimage search (2^512 classical, 2^256 even for a quantum
  computer). Codes are independent of the sealed record: they say nothing about the answer.
  Code N and the release-certain code mix the OS generator with at least 512 bits of
  PHYSICAL entropy (--entropy, assessed by sc2-nonce.py): from the OS generator alone, a
  quantum search of its ~256-bit state (2^128) would find every code -- below the 2^234 bar.
"""
import argparse, datetime as dt, hashlib, importlib.util, os, re, secrets, sys

H = lambda s: hashlib.sha512(s.encode("ascii")).hexdigest()
CODE_BITS = 512          # physical entropy required in the codes' random material
# A fixed code that belongs to no chain, printed in the letters so that the custodian can
# try the check command at once without using up one of your codes.
PRACTICE = H("SC2 practice code: not a real code")


def norm(code):
    """A code is 128 hexadecimal characters; whitespace (line breaks, spaces) and case are
    ignored. Anything else makes it not a code. Returns the code, or None."""
    c = "".join(code.split()).lower()
    return c if re.fullmatch(r"[0-9a-f]{128}", c) else None


# ----------------------------------------------------------------------------- the rule
def evaluate(events, R, lo, hi):
    """events: ACCEPTED codes in the order they were accepted, as (day_number, kind) with kind
    "notice" or "certain"; R: release day number. Returns (outcome, day, per_event) where
    outcome is 'cancel' or 'release', day is when that happens (given only these events),
    and per_event[i] = (series_count or None, note)."""
    run, last, notes = 0, None, []

    def rest(i, why):
        return [(None, why)] * (len(events) - i - 1)

    for i, (d, kind) in enumerate(events):
        if d >= R:                                     # on or after the release date
            if last is None or last + hi < R:          # nothing was in progress on R
                notes.append((None, "on/after the release date, none in progress: release was due"))
                return "release", R, notes + rest(i, "after the decision")
            if d - last > hi:                          # the series had lapsed
                notes.append((None, "too late: the series had lapsed, release was due"))
                return "release", last + hi + 1, notes + rest(i, "after the decision")
        if kind == "certain":
            notes.append((None, "RELEASE MADE CERTAIN"))
            return "release", max(R, d), notes + rest(i, "after the release was made certain")
        if d >= R and d - last < lo:
            notes.append((None, "too early, on/after the release date: release that day"))
            return "release", d, notes + rest(i, "after the decision")
        run = run + 1 if (last is not None and lo <= d - last <= hi) else 1
        last = d
        notes.append((run, ""))
        if run == 3:
            return "cancel", d, notes + rest(i, "after the cancellation")
    if last is None or last + hi < R:
        return "release", R, notes
    return "release", max(R, last + hi + 1), notes


def log_lines(data):
    """The lines of a log file's bytes. UTF-8 with or without a byte-order mark, or UTF-16 (as
    some Windows tools write); lines end at LF, CRLF or CR and at nothing else."""
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        text = data.decode("utf-16", errors="replace")
    elif b"\x00" in data:
        text = data.decode("utf-16-le" if data[1:2] == b"\x00" else "utf-16-be", errors="replace")
    else:
        text = data.decode("utf-8-sig", errors="replace")
    return text.replace("\r\n", "\n").replace("\r", "\n").split("\n")


def parse_log(data):
    """THE log parser, shared by `check` and by sc2-autorelease.py. Lines: 'YYYY-MM-DD code'
    (a code may continue on the next line); # starts a comment. Returns (entries, problems):
    entries are (date, code, line number), sorted; each problem is (line number, message,
    could_be_a_notice): a line with any digit in it could hold a date or a code."""
    out, problems, cur = [], [], None
    for n, raw in enumerate(log_lines(data), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        m = re.match(r"(\d{4}-\d{2}-\d{2})\s*(.*)$", line)
        if m:
            cur = None
            try:
                cur = [dt.date.fromisoformat(m.group(1)), m.group(2), n]
                out.append(cur)
            except ValueError:
                problems.append((n, "log line %d: %s is not a date" % (n, m.group(1)), True))
        elif cur is not None and re.fullmatch(r"[0-9a-fA-F\s]+", line):
            cur[1] += line                               # second half of a two-line code
        else:
            cur = None
            problems.append((n, "log line %d: expected 'YYYY-MM-DD CODE', got: %s" % (n, raw.strip()[:80]),
                             bool(re.search(r"[0-9]", line))))   # no digit: no date and no code
    out.sort(key=lambda t: (t[0], t[2]))
    return [(d, code, k) for d, code, k in out], problems


def read_log(path):
    entries, problems = parse_log(open(path, "rb").read())
    if problems:
        raise SystemExit(problems[0][1])
    return entries


def accept(start, certain, entries):
    """Applies rule 1 to the log. Returns per-entry status and the accepted events, in order."""
    prev, seen, certain_seen = start, set(), False
    status, events = {}, []
    days = sorted({d for d, _, _ in entries})
    for day in days:
        pending = [(k, norm(c)) for d, c, k in entries if d == day]
        progress = True
        while progress:                                  # re-check rejected codes after
            progress = False                             # each acceptance (same day)
            for k, code in pending:
                if k in status:
                    continue
                if code is None:
                    status[k] = "not a code -- ignored"
                elif code in seen:
                    status[k] = "duplicate -- ignored"
                elif H(code) == prev:
                    seen.add(code); prev = code; status[k] = "valid"
                    events.append((day.toordinal(), "notice", k)); progress = True
                elif certain and not certain_seen and H(code) == certain:
                    seen.add(code); certain_seen = True; status[k] = "RELEASE MADE CERTAIN"
                    events.append((day.toordinal(), "certain", k)); progress = True
        for k, code in pending:
            status.setdefault(k, "INVALID -- ignored")
    return status, events


def check(start, certain, release, lo, hi, entries, today):
    """Chain-checks the log, applies the rule, returns (lines_of_report, outcome, day)."""
    start = norm(start)
    if start is None:
        raise SystemExit("the starting value must be 128 hexadecimal characters (put it in quotes)")
    if certain is not None:
        certain = norm(certain)
        if certain is None:
            raise SystemExit("the release-certain value must be 128 hexadecimal characters")
    for d, _, _ in entries:
        if d > today:
            raise SystemExit("the log has a notice dated %s, after today (%s)" % (d, today))
    R = release.toordinal()
    status, events = accept(start, certain, entries)
    outcome, day, notes = evaluate([(d, kind) for d, kind, _ in events], R, lo, hi)
    note_of, gap_of, lastv = {}, {}, None
    for i, (d, _, k) in enumerate(events):              # gaps in the order codes were accepted
        note_of[k] = notes[i]
        gap_of[k] = "%d" % (d - lastv) if lastv is not None else "-"
        lastv = d
    rep = ["  received     code (start)      status                 gap  series"]
    for d, code, k in entries:
        gap = series = note = ""
        if k in note_of:
            series_n, note = note_of[k]
            gap = gap_of[k]
            series = "%d" % series_n if series_n else ""
        shown = "".join(code.split())[:16] or "(empty)"
        rep.append("  %s   %-16s  %-21s %4s  %-6s %s" % (d, shown, status[k], gap, series, note))
    T = today.toordinal()
    fmt = lambda n: dt.date.fromordinal(n).isoformat()
    rep.append("")
    if outcome == "cancel":
        rep.append("DECISION: CANCELLED on %s (three valid notices in a row). Destroy the inner"
                   " envelope unopened, with everything in it." % fmt(day))
    elif day <= T:
        rep.append("DECISION: RELEASE -- due since %s. Release now." % fmt(day))
    else:
        rep.append("STATUS on %s: release on %s." % (today, fmt(day)))
        if any(kind == "certain" for _, kind, _ in events):
            rep.append("  The release was made certain: no notice counts any more.")
        elif notes and notes[-1][0]:
            last = events[-1][0]
            if last + hi >= T:
                rep.append("  A series is in progress (%d of 3). It continues only if the next valid"
                           " notice arrives between %s and %s." % (notes[-1][0], fmt(last + lo), fmt(last + hi)))
            if day != R:
                rep.append("  (The release date %s is postponed while a series that was in progress"
                           " on it runs its course.)" % release)
        else:
            rep.append("  No series in progress.")
    return rep, outcome, day


# ---------------------------------------------------------------------------- the texts
EN_MONTHS = "January February March April May June July August September October November December".split()
FR_MONTHS = "janvier février mars avril mai juin juillet août septembre octobre novembre décembre".split()
EN_DAYS = "Monday Tuesday Wednesday Thursday Friday Saturday Sunday".split()
FR_DAYS = "lundi mardi mercredi jeudi vendredi samedi dimanche".split()


def en_date(d):
    return "%s %d %s %d" % (EN_DAYS[d.weekday()], d.day, EN_MONTHS[d.month - 1], d.year)


def fr_date(d):
    return "%s %s %s %d" % (FR_DAYS[d.weekday()], "1er" if d.day == 1 else d.day, FR_MONTHS[d.month - 1], d.year)


def en_ord(n):
    return "%d%s" % (n, "th" if 10 <= n % 100 <= 20 else {1: "st", 2: "nd", 3: "rd"}.get(n % 10, "th"))


def window_en(lo, hi):
    return "exactly %d days" % lo if lo == hi else ("%d or %d days" % (lo, hi) if hi == lo + 1
                                                   else "between %d and %d days" % (lo, hi))


def window_fr(lo, hi):
    return "exactement %d jours" % lo if lo == hi else ("%d ou %d jours" % (lo, hi) if hi == lo + 1
                                                       else "entre %d et %d jours" % (lo, hi))


def fill(template, **kv):
    for k, v in kv.items():
        template = template.replace("{{%s}}" % k, v)
    left = re.findall(r"\{\{[A-Z_0-9]+\}\}", template)
    assert not left, left
    return template


def log_rows(head, n=12):
    """Empty log rows whose columns line up with the header line."""
    cells = head.split("|")
    return "\n".join("|".join([("  %2d" % i).ljust(len(cells[0]))] + [" " * len(c) for c in cells[1:-1]] + [""])
                     for i in range(1, n + 1))


PYCHECK = ('python3 -c "import hashlib,sys;print(hashlib.sha512(\'\'.join(sys.argv[1].lower()'
           '.split()).encode()).hexdigest())" "{{PASTE}}"')
LOGHEAD_EN = "   #  | date received | code valid? | days since last valid notice | series"
LOGHEAD_FR = "   n° | reçu le       | valide ? | jours depuis le dernier avis valide | série"

LETTER_EN = """\
{{HEADER}}

Thank you for keeping this envelope. The job is rare and simple: keep it safe,
open it on {{RELEASE_EN}}, and put its contents online -- unless I
cancel in the one way described below. If nothing happens, you release it.
That is the default, and it is what I want.

WHAT YOU ARE KEEPING
  This outer envelope: this letter, the RELEASE NOTE and the sheet
  VERIFY-PUBLIC. Nothing in them is secret.
  The INNER envelope, sealed, signed across the flap and labelled
  "SC2/{{CASE}}": my sealed record (a printed "master sheet", and possibly
  a USB stick). It holds a private answer I sealed on {{SEALED_ISO}}. Nobody
  may read it before the release -- including you.

THE RELEASE DATE: {{RELEASE_EN}}
  If I die or can no longer be reached, release it anyway, as below.

THE ONLY WAY TO CANCEL
  I can cancel only by sending you three notices, each received {{WIN_EN}}
  after the previous one. One notice, or several close together, cannot
  cancel anything. The point: only a decision I keep making for about two
  months can stop the release; a sudden impulse cannot.

  1. A notice counts only if it contains a valid code. Check each code with
     a command below. If the result is exactly the last code you accepted
     -- or, if you have not accepted one yet, the STARTING VALUE -- accept
     the code: it becomes the last code you accepted. Otherwise ignore the
     message completely: it changes nothing. A code you have already
     accepted is ignored if it comes again; a code you rejected is checked
     afresh if it comes again. Several codes on one day: check them in the
     order they arrived, and after accepting one, check again any you
     rejected that day.
  2. Count the days from the previous accepted notice to this one by
     subtracting the dates, as a calendar does (10 January to 9 February
     is 30 days; remember 29 February in leap years). If it is
     {{WIN_EN}}, the notice continues the series. Otherwise it starts a new
     series: it is number 1.
  3. When a series reaches 3, the release is cancelled. Destroy the inner
     envelope unopened, with everything in it, and tell me.
  4. On the release date, decide using only the notices received BEFORE
     that day. If you accepted none, or the last one arrived more than
     {{HI}} days before the release date, release that day. Otherwise a
     series is in progress: wait. From the release date on, take each
     accepted notice as it comes: if it arrives {{WIN_EN}} after the
     previous one, the series continues (at 3, cancel); if it arrives
     sooner, release that same day. If none arrives within {{HI}} days of
     the previous one, release on the {{HI1_EN}} day after it.
  5. If a message contains the code whose result is the RELEASE-CERTAIN
     VALUE below, I have made the release certain: from then on, ignore
     every notice, and release on the release date (or that same day, if
     the date has passed).
  6. Nothing else counts. Not a phone call, a visit, a letter or e-mail
     without a valid code, a plea, an explanation, an illness -- not even
     me asking in person. Never give the envelope back and never open it
     before the release; if rule 3 is met, destroy it unopened.
  7. On the day a notice arrives, please e-mail me at
       {{CONTACT}}
     saying whether its code was valid, the date you counted it under and
     the series count -- for every notice, valid or not.

  "Date received": the day the e-mail arrived in your mailbox (inbox or
  spam) -- the date your mail program shows as RECEIVED, not the date it was
  sent -- in the time zone where you live. If you are away, apply these
  rules when you are back, using those dates. Look in your spam folder from
  time to time.

STARTING VALUE (checks my first notice)
{{START}}

RELEASE-CERTAIN VALUE (see rule 5)
{{CERTAIN}}

HOW TO CHECK A CODE (one command, any computer, no internet needed)
  Copy only the code from my message: 128 characters, 0-9 and a-f, on ONE
  line. Then run one of these:
  macOS:
  printf '%s' 'PASTE CODE' | tr 'A-F' 'a-f' | tr -d '[:space:]' | shasum -a 512
  Linux:
  printf '%s' 'PASTE CODE' | tr 'A-F' 'a-f' | tr -d '[:space:]' | sha512sum
  Windows, or anywhere with Python 3 (on Windows, type py instead of python3):
  python3 sc2-release.py code "PASTE CODE"
    (sc2-release.py is published with my reference: see the links below.
    Without it, this one line does the same:)
  {{PYCHECK_EN}}
  The 128 characters printed must be identical to the value you compare
  with (rule 1 or rule 5). Use one of these commands on your own computer,
  never a website.
  To practise now, check this PRACTICE code (it is not a real code):
{{PRACTICE}}
  The result must be:
{{PRACTICE_H}}
  The same file does the counting, from a log.txt with one line per notice,
  "YYYY-MM-DD the-code" (put each value in quotes; type it on one line):
    python3 sc2-release.py check --start "STARTING VALUE"
    --certain "RELEASE-CERTAIN VALUE" --release {{RELEASE_ISO}}{{WINOPT}} log.txt

YOUR LOG
{{LOGHEAD}}
{{LOGROWS}}

ON THE DAY OF RELEASE (the release date, or the later day rule 4 gives)
  1. Check that the inner envelope is still sealed and signed. Photograph
     it. If the seal is broken, say so on the release note and release
     anyway: the contents are checked by their fingerprints, not the seal.
  2. Open it.
  3. Put these online, publicly, where anyone can find and download them:
       - the RELEASE NOTE (first write your name, or "the custodian", and
         the date at the bottom),
       - the VERIFY-PUBLIC sheet,
       - clear photographs or scans of every page of the master sheet,
       - and, if the USB stick still reads, the file commitment.txt on it.
     A simple way: create a free account at archive.org and upload them as
     one item titled "SC2/{{CASE}} opening". If you can, also add the link to
     that item where my reference was published (as a reply or comment):
{{LINKS}}
  4. Keep the paper.
  You don't need to understand the content, and you are not vouching for
  anything: anyone can check that it is genuine with the instructions on the
  VERIFY-PUBLIC sheet. A single changed character would show.

PLEASE ALSO
  - Keep the envelope somewhere safe and dry. Put two reminders in your
    calendar: {{REMIND_EN}} and {{RELEASE_EN}}.
  - If you move or change e-mail address, tell me.
  - If you can no longer do this yourself, give everything, unopened, with
    this letter, to someone you trust to do it instead, and tell me. If I
    cannot be reached, change nothing: the rules above still apply.
  - Other custodian(s) holding an identical envelope: ____________________

Author:    ______________________   signature ____________   date __________
Custodian: ______________________   signature ____________   date __________
(Sign two copies; each of us keeps one.)
"""

LETTER_FR = """\
{{HEADER}}

Merci de bien vouloir garder cette enveloppe. La tâche est rare et simple : la
conserver en lieu sûr, l'ouvrir le {{RELEASE_FR}} et mettre son contenu en
ligne -- sauf si je l'annule de la seule façon décrite plus bas. S'il ne se
passe rien, vous la publiez. C'est ce qui est prévu par défaut, et c'est ce que
je veux.

CE QUE VOUS GARDEZ
  L'enveloppe extérieure : cette lettre, la NOTE DE PUBLICATION et la feuille
  VERIFY-PUBLIC. Rien de tout cela n'est secret.
  L'enveloppe INTÉRIEURE, scellée, signée en travers du rabat et étiquetée
  « SC2/{{CASE}} » : mon enregistrement scellé (une « feuille maîtresse »
  imprimée, et peut-être une clé USB). Elle contient une réponse privée que
  j'ai scellée le {{SEALED_ISO}}. Personne ne doit la lire avant la
  publication -- vous non plus.

LA DATE DE PUBLICATION : {{RELEASE_FR}}
  Si je meurs ou si l'on ne peut plus me joindre, publiez quand même, selon
  les règles ci-dessous.

LA SEULE FAÇON D'ANNULER
  Je ne peux annuler qu'en vous envoyant trois avis, chacun reçu {{WIN_FR}}
  après le précédent. Un seul avis, ou plusieurs rapprochés, n'annulent rien.
  Le but : seule une décision que je maintiens pendant environ deux mois peut
  arrêter la publication ; une impulsion soudaine ne le peut pas.

  1. Un avis ne compte que s'il contient un code valide. Vérifiez chaque code
     avec une commande ci-dessous. Si le résultat est exactement le dernier
     code que vous avez accepté -- ou, si vous n'en avez encore accepté
     aucun, la VALEUR DE DÉPART --, acceptez le code : il devient le dernier
     code accepté. Sinon, ignorez complètement le message : il ne change
     rien. Un code déjà accepté est ignoré s'il revient ; un code refusé est
     vérifié à nouveau s'il revient. Plusieurs codes le même jour :
     vérifiez-les dans leur ordre d'arrivée et, après en avoir accepté un,
     revérifiez ceux que vous aviez refusés ce jour-là.
  2. Comptez les jours entre l'avis accepté précédent et celui-ci en
     soustrayant les dates, comme un calendrier (du 10 janvier au 9 février :
     30 jours ; pensez au 29 février des années bissextiles). Si c'est
     {{WIN_FR}}, l'avis prolonge la série. Sinon, il commence une
     nouvelle série : c'est le numéro 1.
  3. Quand une série atteint 3, la publication est annulée. Détruisez
     l'enveloppe intérieure sans l'ouvrir, avec tout ce qu'elle contient, et
     prévenez-moi.
  4. Le jour de la date de publication, décidez d'après les seuls avis reçus
     AVANT ce jour. Si vous n'en avez accepté aucun, ou si le dernier est
     arrivé plus de {{HI}} jours avant la date, publiez ce jour-là. Sinon,
     une série est en cours : attendez. À partir de la date, prenez chaque
     avis accepté à son arrivée : s'il arrive {{WIN_FR}} après le
     précédent, la série continue (à 3, c'est annulé) ; s'il arrive plus tôt,
     publiez le jour même. Si aucun n'arrive dans les {{HI}} jours qui
     suivent le précédent, publiez le {{HI1}}e jour après celui-ci.
  5. Si un message contient le code dont le résultat est la VALEUR DE
     PUBLICATION CERTAINE ci-dessous, j'ai rendu la publication certaine :
     dès lors, ignorez tout avis et publiez à la date prévue (ou le jour
     même, si la date est passée).
  6. Rien d'autre ne compte. Ni un appel, ni une visite, ni une lettre ou un
     e-mail sans code valide, ni une supplication, une explication ou une
     maladie -- pas même moi en personne. Ne rendez jamais l'enveloppe et ne
     l'ouvrez jamais avant la publication ; si la règle 3 est remplie,
     détruisez-la sans l'ouvrir.
  7. Le jour où un avis arrive, merci de m'écrire à
       {{CONTACT}}
     en indiquant si son code était valide, la date retenue et le compte de
     la série -- pour chaque avis, valide ou non.

  « Date de réception » : le jour où l'e-mail est arrivé dans votre
  messagerie (boîte de réception ou spams) -- la date que votre messagerie
  affiche comme REÇU, pas celle d'envoi --, dans le fuseau horaire où vous
  habitez. Si vous êtes absent, appliquez ces règles à votre retour, avec ces
  dates. Regardez de temps en temps dans vos spams.

VALEUR DE DÉPART (pour vérifier mon premier avis)
{{START}}

VALEUR DE PUBLICATION CERTAINE (voir la règle 5)
{{CERTAIN}}

VÉRIFIER UN CODE (une commande, n'importe quel ordinateur, sans internet)
  Copiez seulement le code de mon message : 128 caractères, 0-9 et a-f, sur
  UNE seule ligne. Puis lancez une de ces commandes :
  macOS :
  printf '%s' 'CODE COLLE' | tr 'A-F' 'a-f' | tr -d '[:space:]' | shasum -a 512
  Linux :
  printf '%s' 'CODE COLLE' | tr 'A-F' 'a-f' | tr -d '[:space:]' | sha512sum
  Windows, ou tout système avec Python 3 (sous Windows, tapez py au lieu de
  python3) :
  python3 sc2-release.py code "CODE COLLE"
    (sc2-release.py est publié avec ma référence : voir les liens plus bas.
    Sans lui, cette ligne unique fait la même chose :)
  {{PYCHECK_FR}}
  Les 128 caractères affichés doivent être identiques à la valeur de
  comparaison (règle 1 ou règle 5). Utilisez une de ces commandes sur votre
  propre ordinateur, jamais un site web.
  Pour vous entraîner tout de suite, vérifiez ce code d'ESSAI (ce n'est pas
  un vrai code) :
{{PRACTICE}}
  Le résultat doit être :
{{PRACTICE_H}}
  Le même fichier fait le décompte, à partir d'un journal.txt avec une ligne
  par avis, « AAAA-MM-JJ le-code » (chaque valeur entre guillemets ; tapez
  la commande sur une seule ligne) :
    python3 sc2-release.py check --start "VALEUR DE DÉPART"
    --certain "VALEUR DE PUBLICATION CERTAINE" --release {{RELEASE_ISO}}{{WINOPT}} journal.txt

VOTRE JOURNAL
{{LOGHEAD}}
{{LOGROWS}}

LE JOUR DE LA PUBLICATION (la date prévue, ou le jour plus tardif de la règle 4)
  1. Vérifiez que l'enveloppe intérieure est toujours scellée et signée.
     Photographiez-la. Si le scellé est rompu, indiquez-le sur la note de
     publication et publiez quand même : le contenu se vérifie par ses
     empreintes, pas par le scellé.
  2. Ouvrez-la.
  3. Mettez en ligne, publiquement, là où chacun peut les trouver et les
     télécharger :
       - la NOTE DE PUBLICATION (inscrivez d'abord en bas votre nom, ou « le
         dépositaire », et la date),
       - la feuille VERIFY-PUBLIC,
       - des photos ou des scans nets de chaque page de la feuille maîtresse,
       - et, si la clé USB se lit encore, le fichier commitment.txt qu'elle
         contient.
     Une façon simple : créez un compte gratuit sur archive.org et déposez-les
     comme un seul élément intitulé « SC2/{{CASE}} opening ». Si vous le
     pouvez, ajoutez aussi le lien vers cet élément là où ma référence a été
     publiée (en réponse ou en commentaire) :
{{LINKS}}
  4. Gardez les papiers.
  Vous n'avez pas besoin de comprendre le contenu, et vous ne garantissez
  rien : chacun peut vérifier qu'il est authentique avec les instructions de
  la feuille VERIFY-PUBLIC. Un seul caractère modifié se verrait.

MERCI AUSSI
  - Gardez l'enveloppe dans un endroit sûr et sec. Mettez deux rappels dans
    votre agenda : le {{REMIND_FR}} et le {{RELEASE_FR}}.
  - Si vous déménagez ou changez d'adresse e-mail, prévenez-moi.
  - Si vous ne pouvez plus vous en charger vous-même, confiez le tout, fermé,
    avec cette lettre, à une personne de confiance qui le fera à votre place,
    et prévenez-moi. Si l'on ne peut pas me joindre, ne changez rien : les
    règles ci-dessus s'appliquent toujours.
  - Autre(s) dépositaire(s) ayant une enveloppe identique : __________________

Auteur :      ______________________   signature ____________   date __________
Dépositaire : ______________________   signature ____________   date __________
(Signez deux exemplaires ; chacun garde le sien.)
"""

NOTE = """\
OPENING OF SEALED RECORD SC2/{{CASE}}
================================================================================

This is the opening of a sealed record. Its public reference -- two lines,
reproduced on the enclosed VERIFY-PUBLIC sheet -- was published in
{{PUB_EN}}:
{{LINKS}}
Short form, published with it (one line; the breaks here are not part of it):
{{SHORT}}

The sealed record is the file commitment.txt, also printed as a hexadecimal
master sheet with a checksum on every line. Anyone can check that it is
exactly the record the reference referred to, with the five commands on
VERIFY-PUBLIC. Nobody needs to trust the person releasing it: a single
changed byte would fail the check. If only photographs of the master sheet
are available, type them in or run them through OCR, then rebuild the file
with: python3 paperkit.py --decode SHEET.txt commitment.txt
(paperkit.py is published with the reference; it names any line to re-read).

On {{SETUP_ISO}} the author arranged for this record to be released on
{{RELEASE_ISO}} unless they cancelled it, which required three coded notices,
each received {{WIN_EN}} after the previous one. It was not cancelled.

Released by: ______________________________   on: ____-__-__

--------------------------------------------------------------------------------
OUVERTURE DE L'ENREGISTREMENT SCELLÉ SC2/{{CASE}}

Ceci est l'ouverture d'un enregistrement scellé. Sa référence publique -- deux
lignes, reproduites sur la feuille VERIFY-PUBLIC jointe -- a été publiée en
{{PUB_FR}} (liens et forme courte ci-dessus). L'enregistrement scellé est le
fichier commitment.txt, aussi imprimé sous forme de feuille maîtresse
hexadécimale avec une somme de contrôle par ligne. Chacun peut vérifier que
c'est exactement l'enregistrement auquel renvoyait la référence, avec les cinq
commandes de VERIFY-PUBLIC. Personne n'a besoin de faire confiance à la
personne qui le publie : un seul octet modifié ferait échouer la vérification.
S'il n'existe que des photos de la feuille maîtresse, tapez-les ou passez-les
à l'OCR, puis reconstituez le fichier avec la commande ci-dessus
(paperkit.py --decode, publié avec la référence).

Le {{SETUP_ISO}}, l'auteur avait prévu que cet enregistrement serait publié le
{{RELEASE_ISO}} sauf annulation, ce qui exigeait trois avis codés, chacun reçu
{{WIN_FR}} après le précédent. Il n'y a pas eu d'annulation.

Publié par : ______________________________   le : ____-__-__
"""


def make_label(case, release_iso):
    rows = ["", "SC2/%s -- SEALED RECORD / ENREGISTREMENT SCELLÉ" % case, "",
            "DO NOT OPEN BEFORE %s -- possibly later:" % release_iso,
            "only as the letter in the outer envelope says.",
            "NE PAS OUVRIR AVANT LE %s -- peut-être plus tard :" % release_iso,
            "seulement selon la lettre de l'enveloppe extérieure.", ""]
    edge = "#" * 80
    return "\n".join([edge] + ["#   %s#" % r.ljust(75) for r in rows] + [edge]) + "\n"


CODES = """\
{{HEADER}}
Release date: {{RELEASE_EN}}.
Custodian's rule: three notices, each received {{WIN_EN}} after the previous
one, cancel the release.

These codes are the ONLY way to stop the release. They reveal nothing about
your answer, but anyone holding them could cancel the release under the same
slow rule as you -- or make it certain. Keep two copies, apart from each
other, and NOT with the custodian. Lose every copy and the release can no
longer be stopped.

HOW TO SEND A NOTICE
  E-mail each custodian. Subject: "SC2/{{CASE}} notice". Body: the next unused
  code, alone, on ONE line (join its two printed halves) -- no label, no
  number, nothing else. Use the codes strictly in order: the next code is the
  one after the last code your custodian reported as valid.
  Your custodian reports each notice on the day it arrives. No report by the
  next morning? Send the same code again at once (that is harmless: a code
  counts once, on the day it first arrived) and ask for the report -- it
  gives the date that counts.

HOW TO CANCEL (the fastest possible takes {{MINDAYS}} days)
  Begin at least {{MINLEAD}} days before {{RELEASE_ISO}} -- better, several months
  before -- so that all three notices arrive before that date. A first
  notice received on that date or later counts for nothing.
  1. Send the next code. Your custodian reports the date it counts under.
     Call that date D.
  2. Send the next code so that it arrives on D+{{LO}} by your custodian's
     calendar (their time zone), early in their day. {{SPARE}}
  3. Send the next code the same way, {{LO}} days after the date that one
     counted under. Three in a row: cancelled. Ask for written confirmation.
  Before the release date, a notice that counts too early or too late starts
  a new series: it is number 1, and you continue from it -- you lose time,
  nothing else. From the release date on, a mistimed notice means the release
  happens. With two custodians, keep a separate log and D for each.
  Keep your own log ("YYYY-MM-DD code", one line per notice reported valid)
  and check where you stand, with the two values printed below:
    python3 sc2-release.py check --start "STARTING VALUE"
    --certain "RELEASE-CERTAIN VALUE" --release {{RELEASE_ISO}}{{WINOPT}} log.txt
  (type it on one line). Your custodian's copy of this command gives the same
  answer.

TO MAKE THE RELEASE CERTAIN
  Send the RELEASE-CERTAIN code below, alone, like a notice. From then on no
  notice counts, and nobody -- you included -- can cancel. Use it if someone
  else may have seen these codes (your custodian reports every notice to you,
  so a report you did not expect means exactly that), or to bind yourself.
RELEASE-CERTAIN CODE
{{CERTAIN_CODE}}

STARTING VALUE (held by your custodian; for your own checks)
{{START}}
RELEASE-CERTAIN VALUE (held by your custodian; for your own checks)
{{CERTAIN}}

{{NCODES}} CODES. USE THEM IN ORDER.
{{CODELIST}}"""


def header(left, right):
    return left + " " * max(1, 80 - len(left) - len(right)) + right + "\n" + "=" * 80


def block(hexstr, indent="  "):
    return "\n".join(indent + hexstr[i:i + 64] for i in range(0, len(hexstr), 64))


# ---------------------------------------------------------------------------- make
def verify_kit_inputs(pre, ref, title):
    P = open(pre, "rb").read()
    want = {"S3A": hashlib.sha3_512(b"SC2-A\n" + P).hexdigest(),
            "S3B": hashlib.sha3_512(b"SC2-B\n" + P).hexdigest(),
            "B2": hashlib.blake2b(P, digest_size=64).hexdigest(),
            "S5": hashlib.sha512(P).hexdigest()}
    reftext = open(ref, encoding="utf-8").read()
    l2 = reftext.rstrip("\n").split("\n")[-1]
    got = dict(re.findall(r"(S3A|S3B|B2|S5)=([0-9a-f]{128})", l2))
    if got != want:
        raise SystemExit("REFUSING: %s does not match %s -- this kit would release the wrong file." % (ref, pre))
    canon = " ".join(reftext.split())
    short = open(title, encoding="ascii").read().strip()
    if short != "SC2 REF-SHA3-512=" + hashlib.sha3_512(canon.encode("utf-8")).hexdigest():
        raise SystemExit("REFUSING: %s is not the short form of %s." % (title, ref))
    case = re.match(r"SC2/([0-9A-F]{10})\b", reftext)
    if not case:
        raise SystemExit("REFUSING: %s does not start with an SC2 case number." % ref)
    return case.group(1), short


def make(a):
    lo, hi = parse_window(a.window)
    today = dt.date.fromisoformat(a.today) if a.today else dt.date.today()
    release = dt.date.fromisoformat(a.release)
    published = dt.date.fromisoformat(a.published) if a.published else today
    if release <= today + dt.timedelta(days=2 * hi + 31):
        raise SystemExit("the release date must be more than %d days away" % (2 * hi + 31))
    if not 8 <= a.codes <= 200:
        raise SystemExit("--codes must be between 8 and 200")
    if not a.link:
        raise SystemExit("give at least one --link: where the reference was published")
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", a.contact):
        raise SystemExit("--contact must be an e-mail address")
    if os.path.exists(a.out):
        raise SystemExit("REFUSING: %s already exists. Move it aside deliberately." % a.out)
    case, short = verify_kit_inputs(a.preimage, a.reference, a.short)

    phys = open(a.entropy, "rb").read() if os.path.isfile(a.entropy) else b""
    here = os.path.dirname(os.path.abspath(__file__))
    spec = importlib.util.spec_from_file_location("sc2_nonce", os.path.join(here, "sc2-nonce.py"))
    nonce = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(nonce)
    kind, bits, notes, ok = nonce.assess(phys, CODE_BITS)
    if not ok:
        for n in notes:
            print("    " + n)
        raise SystemExit("REFUSING: %s does not give %d bits of assessed physical entropy. Roll "
                         "more dice (350 rolls is enough); never reuse the commitment's." % (a.entropy, CODE_BITS))
    material = os.urandom(64) + secrets.token_bytes(64) + b"|" + phys
    root = hashlib.shake_256(b"SC2-CANCEL-ROOT|" + material).hexdigest(64)
    certain = hashlib.shake_256(b"SC2-RELEASE-CERTAIN|" + material).hexdigest(64)
    chain = [root]
    for _ in range(a.codes - 1):
        chain.append(H(chain[-1]))
    codes = chain[::-1]                       # codes[0] is code 1, the first to send
    start = H(codes[0])
    for k in range(1, len(codes)):            # self-check of the chain
        assert H(codes[k]) == codes[k - 1]
    assert certain not in codes and H(certain) != start

    win_opt = "" if (lo, hi) == (30, 31) else " --window %d-%d" % (lo, hi)
    links = "\n".join("       " + l for l in a.link)
    common = dict(
        CASE=case, SETUP_ISO=today.isoformat(), SEALED_ISO=published.isoformat(),
        RELEASE_ISO=release.isoformat(), RELEASE_EN=en_date(release), RELEASE_FR=fr_date(release),
        REMIND_EN=en_date(release - dt.timedelta(days=7)), REMIND_FR=fr_date(release - dt.timedelta(days=7)),
        WIN_EN=window_en(lo, hi), WIN_FR=window_fr(lo, hi), LO=str(lo), HI=str(hi),
        HI1=str(hi + 1), HI1_EN=en_ord(hi + 1), CONTACT=a.contact, START=block(start),
        CERTAIN=block(H(certain)), WINOPT=win_opt, LINKS=links,
        PRACTICE=block(PRACTICE), PRACTICE_H=block(H(PRACTICE)))
    letter_en = fill(LETTER_EN, PYCHECK_EN=PYCHECK.replace("{{PASTE}}", "PASTE CODE"),
                     LOGHEAD=LOGHEAD_EN, LOGROWS=log_rows(LOGHEAD_EN),
                     HEADER=header("SC2/%s -- LETTER TO THE CUSTODIAN" % case, "written " + today.isoformat()),
                     **common)
    letter_fr = fill(LETTER_FR, PYCHECK_FR=PYCHECK.replace("{{PASTE}}", "CODE COLLE"),
                     LOGHEAD=LOGHEAD_FR, LOGROWS=log_rows(LOGHEAD_FR),
                     HEADER=header("SC2/%s -- LETTRE AU DÉPOSITAIRE" % case, "écrite le " + today.isoformat()),
                     **common)
    note = fill(NOTE, PUB_EN="%s %d" % (EN_MONTHS[published.month - 1], published.year),
                PUB_FR="%s %d" % (FR_MONTHS[published.month - 1], published.year),
                SHORT="  SC2 REF-SHA3-512=\n" + block(short.split("=", 1)[1]), **common)
    label = make_label(case, release.isoformat())
    codelist = "\n".join("CODE %02d  %s\n         %s" % (i + 1, c[:64], c[64:]) for i, c in enumerate(codes)) + "\n"
    codes_txt = fill(CODES, NCODES=str(a.codes), CODELIST=codelist, MINDAYS=str(2 * lo), MINLEAD=str(2 * hi + 1),
                     CERTAIN_CODE=block(certain),
                     HEADER=header("SC2/%s -- YOUR CANCELLATION CODES -- SECRET" % case, "made " + today.isoformat()),
                     SPARE=("D+%d is your spare day." % hi) if hi > lo else "There is no spare day.",
                     **{k: v for k, v in common.items() if k in
                        ("CASE", "RELEASE_EN", "RELEASE_ISO", "WIN_EN", "LO", "START", "CERTAIN", "WINOPT")})

    old = os.umask(0o077)
    try:
        os.mkdir(a.out, 0o700)
        files = [("CUSTODIAN-LETTER-EN.txt", letter_en), ("CUSTODIAN-LETTER-FR.txt", letter_fr),
                 ("RELEASE-NOTE.txt", note), ("INNER-ENVELOPE-LABEL.txt", label),
                 ("CANCEL-CODES-SECRET.txt", codes_txt)]
        for name, text in files:
            p = os.path.join(a.out, name)
            with open(p, "w", encoding="utf-8") as f:
                f.write(text)
            os.chmod(p, 0o400 if "SECRET" in name else 0o600)
    finally:
        os.umask(old)
    print("wrote %s/ for SC2/%s -- release on %s, cancel window %s" % (a.out, case, release, window_en(lo, hi)))
    for name, _ in files:
        print("  %-26s %s" % (name, "SECRET: keep two copies, never with the custodian"
                              if "SECRET" in name else ""))
    print("codes: %.0f bits of assessed physical entropy (%d required)" % (bits, CODE_BITS))
    print("starting value (custodian holds it): %s..." % start[:24])
    print("Now delete %s: while it exists, it is as sensitive as the codes." % a.entropy)
    print("Assemble the envelope as described in RUNBOOK step 10.")


def parse_window(w):
    m = re.fullmatch(r"(\d+)-(\d+)", w)
    if not m or not (1 <= int(m.group(1)) <= int(m.group(2)) <= 365):
        raise SystemExit("--window must look like 30-31")
    return int(m.group(1)), int(m.group(2))


def main(argv):
    ap = argparse.ArgumentParser(description="SC2 automatic release held by a custodian")
    sub = ap.add_subparsers(dest="cmd", required=True)
    m = sub.add_parser("make")
    m.add_argument("--release", required=True, help="release date, YYYY-MM-DD")
    m.add_argument("--published", help="date the reference was published (default: today)")
    m.add_argument("--contact", required=True, help="your e-mail, for the custodian's reports")
    m.add_argument("--entropy", required=True, help="FRESH dice rolls (350 is enough), assessed like sc2-nonce.py")
    m.add_argument("--link", action="append", default=[], help="where the reference was published (repeat)")
    m.add_argument("--window", default="30-31", help="days between notices, LO-HI (default 30-31)")
    m.add_argument("--codes", type=int, default=24)
    m.add_argument("--out", default="release-kit")
    m.add_argument("--today", help=argparse.SUPPRESS)
    m.add_argument("--preimage", default="commitment.txt")
    m.add_argument("--reference", default="commitment-reference.txt")
    m.add_argument("--short", default="commitment-title.txt")
    c = sub.add_parser("check")
    c.add_argument("--start", required=True, help="the starting value (128 hex, in quotes)")
    c.add_argument("--certain", help="the release-certain value (128 hex, in quotes)")
    c.add_argument("--release", required=True)
    c.add_argument("--window", default="30-31")
    c.add_argument("--today")
    c.add_argument("log")
    k = sub.add_parser("code")
    k.add_argument("code")
    a = ap.parse_args(argv)
    if a.cmd == "make":
        make(a)
    elif a.cmd == "check":
        lo, hi = parse_window(a.window)
        today = dt.date.fromisoformat(a.today) if a.today else dt.date.today()
        rep, outcome, day = check(a.start, a.certain, dt.date.fromisoformat(a.release), lo, hi,
                                  read_log(a.log), today)
        print("\n".join(rep))
        return 10 if outcome == "cancel" else (0 if day > today.toordinal() else 20)
    else:
        c = norm(a.code)
        if c is None:
            raw = "".join(a.code.split())
            print("not a code: expected 128 characters 0-9 a-f on one line, got %d characters%s"
                  % (len(raw), "" if re.fullmatch(r"[0-9a-fA-F]*", raw) else " (some not 0-9 a-f)"))
            return 2
        print(H(c))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
