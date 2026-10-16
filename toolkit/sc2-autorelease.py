#!/usr/bin/env python3
"""sc2-autorelease.py -- the second, automated release path (RUNBOOK step 10A).

A scheduled job in a PRIVATE GitHub repository -- and, with --gitlab, a second, independent one
on GitLab (RUNBOOK 10A-h) -- publishes your sealed record on the release date unless the log
shows a completed cancellation. It runs ALONGSIDE the custodian, never instead of them: same
date, same codes, same rule -- the `check` of sc2-release.py, imported here, not re-implemented.

  make      writes the private repository's files, the first files of a dedicated public
            OPENING repository (the only one the job may write to), and, in a SEPARATE
            folder, what you store as GitHub secrets: the key half, and the deploy key.
  run       what the job does at each run, once a month: decide from the log and the date,
            check its own health, publish when the release is due.
  rehearse  the same kit around SYNTHETIC data, due tomorrow (--days N) and locked like the
            real one: try the whole path on GitHub, the schedule included, first.
  notice    logs one notice your custodian reported valid: checks the code, commits the line,
            pushes it to every copy of the private repository, and reads each one back.
  probe     a live time-lock round trip with drand from this computer.
  decrypt   opens a job's copy by hand, once the time-lock has opened.

  python3 sc2-autorelease.py make --opening-repo git@github.com:you/sc2-xxxxxxxxxx-opening.git \\
          --entropy auto-dice.txt [--timezone Europe/Paris] [--opening-repo ...] \\
          [--letter release-kit/CUSTODIAN-LETTER-EN.txt] [--branch main] \\
          [--out autorelease-repo] [--secrets autorelease-secrets] [--no-check-in] \\
          [--gitlab --private-repo git@github.com:you/REPO.git --gitlab-repo git@gitlab.com:you/REPO.git
           [--no-peer-key]]
  python3 sc2/tools/sc2-autorelease.py notice YYYY-MM-DD CODE      (from your working copy)
  python3 sc2-autorelease.py run --kit DIR
  python3 sc2-autorelease.py rehearse --opening-repo git@github.com:you/sc2-rehearsal-target.git
  python3 sc2-autorelease.py probe
  python3 sc2-autorelease.py decrypt --kit DIR --key-file SC2_KEY -o opened.txt

WHAT GITHUB HOLDS, AND WHO CAN OPEN IT
  The record, padded to 16384 bytes so that its length says nothing, XORed with a SHAKE256
  keystream whose key is made of two independent 512-bit halves:
    K_s  from 350 fresh dice and the OS generator, stored ONLY as the GitHub secret SC2_KEY;
    K_t  from the OS generator, time-locked with drand's tlock to the first League of
         Entropy "quicknet" round at or after 00:00 on the release date in the custodian's
         time zone, and stored in the repository.
  Before that round nobody can open the copy -- not GitHub, not anyone who can push to the
  repository (and so read its secrets) -- unless a threshold of League of Entropy members
  collude, a quantum computer breaks drand's BLS12-381 signatures (drand: "does not use
  quantum-resistant algorithms"), or someone spends about 2^128 operations on tlock's inner
  128-bit key (age's file key; 2^64 for a quantum search). The repository's files without the
  secret reveal nothing even then: K_s remains, 2^256 for a quantum search, because it comes
  from dice. From that round on, whoever holds the files AND the secret can open them,
  whether or not the release happens: a cancellation stops the publication; it cannot recall
  a copy already taken.

THE JOB'S RULES
  It decides with sc2-release.py's own parser and `check` on sc2/log.txt, where you add,
  the day your custodian reports it, each notice they found valid ("YYYY-MM-DD code"). A
  line that may be a notice and cannot be evaluated blocks the publication until fixed: a
  publication cannot be undone, and the custodian still covers the release. It publishes to
  every target with that target's deploy key, never overwrites anything, and checks the
  decrypted record against the published reference first: a copy that does not match all
  four digests and the short form is never published. It runs no third-party GitHub Action
  and no tle but the pinned build, prints no secret, and stops retrying in time to report.
  A red run means: read it (the platform e-mails you).
"""
import argparse, base64, datetime as dt, hashlib, importlib.util, json, os, platform, re
import secrets, shlex, shutil, subprocess, sys, tempfile, time, urllib.parse, urllib.request

FORMAT = "SC2-AUTORELEASE-1"
SIZE = 16384                    # every record is padded to this many bytes before encryption
KEY_BITS = 512                  # assessed physical entropy required in K_s
CHAIN = "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971"   # quicknet
GENESIS, PERIOD = 1692803367, 3
RELAYS = ["https://api.drand.sh", "https://drand.cloudflare.com", "https://api2.drand.sh",
          "https://api3.drand.sh"]
TLE_MODULE, TLE_VERSION = "github.com/drand/tlock/cmd/tle", "v1.2.0"
TLE_SHA256 = {   # built with go1.27.1: CGO_ENABLED=0 go install -trimpath -ldflags='-s -w'
    "amd64": "69157d8c14a1d390d1b7744946288f83d4b10748471d5447f9abb77a5902c541",
    "arm64": "6278c97892e90eb8129c95a4ee522b8c1eaa7422294902a27a45bbbea74f5471"}
RUN_AT = {"GitHub": (17, 17)}   # GitHub alone: 17:17 in the custodian's zone (given in UTC, date by date)
RUN_AT_TWO = {"GitLab": (17, 17), "GitHub": (21, 17)}   # with GitLab, GitLab first: GitHub's run the
                                # same evening can use the key half GitLab releases (GitLab keeps local time)
WAIT_NEXT = 35                  # a due release waits for an unreadable copy of the log only if a run is this near
UA = "sc2-autorelease/1"
HERE = os.path.dirname(os.path.abspath(__file__))
ON_GITHUB = os.environ.get("GITHUB_ACTIONS") == "true"
IDENT = ["-c", "user.name=SC2 automatic release", "-c", "user.email=sc2-autorelease@example.invalid",
         "-c", "commit.gpgsign=false", "-c", "init.defaultBranch=main"]
SAID = []
BUDGET = 25 * 60               # seconds a run may spend before it stops retrying (the job allows 45 min)
DEADLINE = [None]


def time_left():
    return float("inf") if DEADLINE[0] is None else DEADLINE[0] - time.time()


def capped(timeout):
    """A network timeout that never runs past the run's deadline."""
    return max(5, min(timeout, time_left() - 60))





def platform_name():
    """Where this run happens. SC2_PLATFORM lets the self-test play either part."""
    if os.environ.get("GITHUB_ACTIONS") == "true":
        return "GitHub"
    if os.environ.get("GITLAB_CI") == "true":
        return "GitLab"
    return os.environ.get("SC2_PLATFORM") or "local"


def manual_run():
    return (os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
            or os.environ.get("CI_PIPELINE_SOURCE") == "web")


def secret_value(name):
    """A secret from the environment. On GitLab a "File" variable holds a path to the value."""
    v = os.environ.get(name, "")
    p = v.strip()
    if p and "\n" not in p and not p.startswith("-----") and len(p) < 4096 and os.path.isfile(p):
        try:
            v = open(p, encoding="utf-8").read()
        except OSError:
            pass
    return v


def say(s=""):
    SAID.append(s)
    print(s, flush=True)


def sibling(modname, filename):
    sys.dont_write_bytecode = True                     # no __pycache__ beside your files or in the kit
    path = os.path.join(HERE, filename)
    if not os.path.isfile(path):
        raise SystemExit("%s must be beside %s" % (filename, os.path.basename(__file__)))
    spec = importlib.util.spec_from_file_location(modname, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ------------------------------------------------------------------------ the encryption
def shake(tag, *parts, n=64):
    h = hashlib.shake_256(tag.encode("ascii") + b"|")
    for p in parts:
        h.update(p)
    return h.digest(n)


def xor(a, b):
    return (int.from_bytes(a, "big") ^ int.from_bytes(b, "big")).to_bytes(len(a), "big")


def keystream(ks, kt, n):
    return shake("SC2-AUTO-STREAM", shake("SC2-AUTO-DATA-KEY", ks, kt), n=n)


def seal(record, ks, kt):
    if len(record) > SIZE - 8:
        raise SystemExit("REFUSING: the record is longer than %d bytes" % (SIZE - 8))
    padded = len(record).to_bytes(8, "big") + record + bytes(SIZE - 8 - len(record))
    return xor(padded, keystream(ks, kt, SIZE))


def unseal(sealed, ks, kt):
    """The record, or None if the keys or the copy are wrong."""
    if len(sealed) != SIZE:
        return None
    p = xor(sealed, keystream(ks, kt, SIZE))
    n = int.from_bytes(p[:8], "big")
    if n > SIZE - 8 or any(p[8 + n:]):
        return None
    return p[8:8 + n]


def key_check(ks):
    """Lets the job confirm the secret is this kit's, without revealing anything about it."""
    return hashlib.sha3_512(b"SC2-AUTO-KEY-CHECK|" + ks).hexdigest()


def sha512_file(path):
    return hashlib.sha512(open(path, "rb").read()).hexdigest()


# ------------------------------------------------------------------- time and drand rounds
def round_at(t):
    """The first quicknet round emitted at or after Unix time t."""
    return max(1, -(-(t - GENESIS) // PERIOD) + 1)


def round_time(r):
    return GENESIS + (r - 1) * PERIOD


def current_round(now=None):
    return (int(time.time() if now is None else now) - GENESIS) // PERIOD + 1


def iso(t):
    return dt.datetime.fromtimestamp(t, dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def zone(name):
    from zoneinfo import ZoneInfo           # Python 3.9+, with the system's time zone data
    return ZoneInfo(name)


def local_today(tzname, table=None):
    """Today in the custodian's zone: from the system's time zone data, or else from the table
    of UTC offsets that make wrote into config.json (some runner images have no tzdata)."""
    try:
        return dt.datetime.now(zone(tzname)).date()
    except Exception:
        if not table:
            raise
    now = dt.datetime.now(dt.timezone.utc)
    off = table[0][1]
    for day, minutes in table:
        if dt.date.fromisoformat(day) <= now.date():
            off = minutes
    return (now + dt.timedelta(minutes=off)).date()


def tz_table(tzname, start, end):
    """[[first UTC day, offset in minutes], ...] for every change of offset between two dates."""
    z, out, d = zone(tzname), [], start
    while d <= end:
        off = int(z.utcoffset(dt.datetime(d.year, d.month, d.day, 12)).total_seconds() // 60)
        if not out or out[-1][1] != off:
            out.append([d.isoformat(), off])
        d += dt.timedelta(days=1)
    return out


def local_midnight(day, tzname):
    return int(dt.datetime(day.year, day.month, day.day, tzinfo=zone(tzname)).timestamp())


def month_day(year, month, day):
    """That day of the month, or the month's last day if the month is shorter -- 28 February in
    every year, so that each date exists every year."""
    last = 28 if month == 2 else (dt.date(year + month // 12, month % 12 + 1, 1) - dt.timedelta(days=1)).day
    return dt.date(year, month, min(day, last))


def run_dates(release):
    """The days the jobs run, every year: the release date's day of every month (the month's last
    day when it is shorter), so that the public heartbeats show that day of the month and nothing
    of the month itself (RUNBOOK 10A-g). The list starts a month before the release date, the
    yearly check-in, and holds the release date itself; a release date of 29 February adds
    28 February, for the years without one. Nothing runs on other days."""
    out = []
    for k in range(-1, 11):
        m = release.month - 1 + k
        out.append(release if k == 0 else month_day(release.year + m // 12, m % 12 + 1, release.day))
    if (release.month, release.day) == (2, 29):
        out.append(dt.date(release.year + 1, 2, 28))
    return out


def run_times(platforms):
    return dict(RUN_AT_TWO) if "GitLab" in platforms else dict(RUN_AT)


def kit_years(made, release):
    """The years a kit's GitHub schedule is checked for: from the year it is made to two years
    after the release date, and at least four, so that a leap year is among them."""
    return list(range(made.year, max(made.year + 4, release.year + 3)))


def on_day(y, d):
    """d's day of the year in year y, or None (29 February outside a leap year)."""
    try:
        return dt.date(y, d.month, d.day)
    except ValueError:
        return None


def utc_fires(line, day, z):
    """The local time (zone z) at which the UTC cron line (minute, hour, day, month) fires on the
    local date `day`, or None if it does not fire that day."""
    mi, h, dd, mo = line
    for y in (day.year - 1, day.year, day.year + 1):          # the UTC day may be in another year
        try:
            t = dt.datetime(y, mo, dd, h, mi, tzinfo=dt.timezone.utc).astimezone(z)
        except ValueError:                                      # 29 February outside a leap year
            continue
        if t.date() == day:
            return t
    return None


def github_crons(dates, tzname, hm, years):
    """GitHub's schedule: [(line, [run dates], note)], in UTC (cron has no year), for hm in the
    custodian's zone on each run date in every one of `years`. One line per date is the rule --
    summer time moves a run by an hour, not to another day -- and dates at the same UTC day and
    time then share one line, with a list of months. But at UTC-3 or further west at 21:17 (UTC-7
    or further west at 17:17), the evening of 28 February falls on 29 February in UTC in leap
    years and on 1 March in other years: that date gets a line for each, and in leap years the
    second one also runs on 29 February. The note names the years a line is for, and any other
    day it fires on."""
    z, out, where = zone(tzname), [], {}
    leap = lambda y: on_day(y, dt.date(2000, 2, 29)) is not None
    for d in dates:
        lines = []
        for day in [d] + [x for x in (on_day(y, d) for y in years) if x]:
            if not any(utc_fires(l, day, z) for l in lines):
                t = dt.datetime(day.year, day.month, day.day, *hm, tzinfo=z).astimezone(dt.timezone.utc)
                lines.append((t.minute, t.hour, t.day, t.month))
        for l in lines:
            parts = []
            if len(lines) > 1:
                ys = [y for y in years if on_day(y, d) and utc_fires(l, on_day(y, d), z)]
                parts.append("in leap years" if all(leap(y) for y in ys) else
                             "in other years" if not any(leap(y) for y in ys) else
                             "in %s" % ", ".join(map(str, ys)))
            if l in where:                 # one line for two run dates (a release date of 29 February)
                c, ds, note = out[where[l]]
                run = "the run of %d %s%s" % (d.day, EN_MONTHS[d.month - 1], (" " + parts[0]) if parts else "")
                out[where[l]] = (c, ds, note[:-1] + "; also " + run + ")" if note else " (also %s)" % run)
                continue
            where[l] = len(out)
            extra = github_also([("%d %d %d %d *" % l, [d], "")], dates, tzname, years)
            if extra:
                parts.append("also on " + extra)
            out.append(("%d %d %d %d *" % l, [d], " (%s)" % "; ".join(parts) if parts else ""))
    merged, at = [], {}                # plain lines at the same UTC day and time: one line, its months listed
    for c, ds, note in out:
        mi, h, dd, mo = c.split()[:4]
        if note or (mi, h, dd) not in at:
            if not note:
                at[(mi, h, dd)] = len(merged)
            merged.append((c, ds, note))
            continue
        c0, ds0, _ = merged[at[(mi, h, dd)]]
        months = sorted({int(x) for x in c0.split()[3].split(",")} | {int(mo)})
        merged[at[(mi, h, dd)]] = ("%s %s %s %s *" % (mi, h, dd, ",".join(map(str, months))), ds0 + ds, "")
    return merged


def github_also(crons, dates, tzname, years):
    """The days, other than the run dates, on which GitHub's UTC lines also fire in the custodian's
    zone, in words ("29 February in leap years"), or "" when there are none."""
    z, want, extra = zone(tzname), {(d.month, d.day) for d in dates}, {}
    for line, _, _ in crons:
        f = line.split()
        mi, h, dd = int(f[0]), int(f[1]), int(f[2])
        for mo in (int(x) for x in f[3].split(",")):
            for y in years:
                try:
                    t = dt.datetime(y, mo, dd, h, mi, tzinfo=dt.timezone.utc).astimezone(z)
                except ValueError:
                    continue
                if (t.month, t.day) not in want:
                    extra.setdefault((t.month, t.day), set()).add(y)
    words = []
    for (m, d), ys in sorted(extra.items()):
        when = (" in leap years" if all(on_day(y, dt.date(2000, 2, 29)) for y in ys) else
                " in years without a 29 February" if not any(on_day(y, dt.date(2000, 2, 29)) for y in ys) else
                " in some years")
        words.append("%d %s%s" % (d, EN_MONTHS[m - 1], when))
    return " and ".join(words)


def gitlab_crons(dates, hm):
    """GitLab's schedule, in local time: one pattern per day of the month, with its months ("*" for
    all twelve), the longest list first."""
    h, days = "%d %d" % (hm[1], hm[0]), {}
    for d in dates:
        days.setdefault(d.day, set()).add(d.month)
    return ["%s %d %s *" % (h, day, "*" if len(ms) == 12 else ",".join(map(str, sorted(ms))))
            for day, ms in sorted(days.items(), key=lambda kv: (-len(kv[1]), -kv[0]))]


def en_ord(n):
    return "%d%s" % (n, "th" if 10 <= n % 100 <= 20 else {1: "st", 2: "nd", 3: "rd"}.get(n % 10, "th"))


def run_words(dates):
    """The run days in words: "the 1st of every month", the shorter months named if need be."""
    days = {}
    for d in dates:
        days.setdefault(d.day, set()).add(d.month)
    main = max(days, key=lambda k: (len(days[k]), k))
    rest = sorted((k for k in days if k != main), reverse=True)
    if not rest:
        return "the %s of every month" % en_ord(main)
    names = lambda ms: (lambda w: w[0] if len(w) == 1 else ", ".join(w[:-1]) + " and " + w[-1])(
        [EN_MONTHS[m - 1] for m in sorted(ms)])
    if any(days[k] & days[main] for k in rest):            # 29 February, and 28 February in other years
        return "the %s of every month, and the %s" % (en_ord(main), " and the ".join(
            "%s of %s" % (en_ord(k), names(days[k])) for k in rest))
    return "the %s of every month (%s)" % (en_ord(main), "; ".join(
        "the %s in %s" % (en_ord(k), names(days[k])) for k in rest))


def date_words(dates):
    w = ["%d %s%s" % (d.day, EN_MONTHS[d.month - 1], " (in leap years)" if (d.month, d.day) == (2, 29) else "")
         for d in dates]
    return w[0] if len(w) == 1 else ", ".join(w[:-1]) + " and " + w[-1]


def next_run(dates, after):
    """The first run date strictly after `after`, these dates repeating every year."""
    for y in range(after.year, after.year + 2):
        for d in sorted(dates, key=lambda x: (x.month, x.day)):
            try:
                c = dt.date(y, d.month, d.day)
            except ValueError:
                continue
            if c > after:
                return c
    return None


# ----------------------------------------------------------------------------- tle
def arch():
    return {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(
        platform.machine().lower())


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def tle_ways(tools):
    """The pinned tle build for this machine, and only if its SHA-256 is the pinned one: tle
    runs with this process's secrets readable (/proc), so no other code is ever run."""
    if os.environ.get("SC2_TLE"):                                  # the self-test's stand-in
        return [("SC2_TLE", shlex.split(os.environ["SC2_TLE"]))], []
    ways, notes, a = [], [], arch()
    if platform.system() == "Linux" and a:
        p = os.path.join(tools, "tle-linux-" + a)
        if not os.path.isfile(p):
            notes.append("no %s" % p)
        elif sha256_file(p) != TLE_SHA256[a]:
            notes.append("%s is not the pinned build (SHA-256 differs): not used" % os.path.basename(p))
        else:
            try:
                os.chmod(p, 0o755)
            except OSError:
                pass
            ways.append(("tle %s linux-%s" % (TLE_VERSION, a), [p]))
    else:
        notes.append("no pinned tle build for %s %s" % (platform.system(), platform.machine()))
    return ways, notes


def run_tle(cmd, args, data, timeout=120):
    """Runs tle without the secrets in its environment (a hostile build could still read this
    process's, which is why only the pinned build runs). Returns (stdout or None, stderr)."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("SC2_")}
    try:
        r = subprocess.run(cmd + args, input=data, capture_output=True, env=env, timeout=capped(timeout))
    except (OSError, subprocess.SubprocessError) as e:
        return None, "%s: %s" % (type(e).__name__, e)
    err = " ".join(l.strip() for l in r.stderr.decode("utf-8", "replace").splitlines()
                   if l.strip() and "non-default network endpoint" not in l and "custom chainhash" not in l)
    return (r.stdout if r.returncode == 0 else None), err


def armor_header(armored):
    """(round, chain) of a tlock age file in armor, or None. Exactly one recipient: tlock."""
    m = re.search(rb"-----BEGIN AGE ENCRYPTED FILE-----(.*?)-----END AGE ENCRYPTED FILE-----", armored, re.S)
    if not m:
        return None
    try:
        raw = base64.b64decode(b"".join(m.group(1).split()), validate=True)
    except ValueError:
        return None
    lines = raw.partition(b"\n---")[0].split(b"\n")
    stanzas = [l.split() for l in lines[1:] if l.startswith(b"-> ")]
    if lines[0] != b"age-encryption.org/v1" or len(stanzas) != 1:
        return None
    f = stanzas[0]
    if len(f) != 4 or f[1] != b"tlock" or not f[2].isdigit():
        return None
    return int(f[2]), f[3].decode("ascii", "replace")


ATTEMPTS, PAUSE = 3, 15        # every relay, every way, three times: networks have bad minutes


def timelock_encrypt(ways, relays, chain, rnd, data):
    tried = []
    for attempt in range(ATTEMPTS):
        if attempt:
            time.sleep(PAUSE)
        for label, cmd in ways:
            for relay in relays:
                if time_left() < 90:
                    raise SystemExit("could not time-lock anything in time:\n  " + "\n  ".join(tried))
                out, err = run_tle(cmd, ["-e", "-n", relay, "-c", chain, "-r", str(rnd), "-a"], data)
                if out:
                    if armor_header(out) != (rnd, chain):
                        raise SystemExit("REFUSING: tle's output is not a time-lock to round %d of %s" % (rnd, chain))
                    return out, label, relay
                tried.append("%s via %s: %s" % (label, relay, err[:300]))
    raise SystemExit("could not time-lock anything:\n  " + "\n  ".join(tried))


def timelock_decrypt(ways, relays, chain, armored):
    """(plaintext or None, what was tried). Stops at the first 'too early': if the round has
    not come, no relay and no retry can say otherwise."""
    tried = []
    for attempt in range(ATTEMPTS):
        if attempt:
            time.sleep(PAUSE)
        for label, cmd in ways:
            for relay in relays:
                if time_left() < 90:
                    tried.append("gave up: this run's time is spent")
                    return None, tried
                out, err = run_tle(cmd, ["-d", "-n", relay, "-c", chain], armored)
                if out is not None:
                    return out, tried
                tried.append("%s via %s: %s" % (label, relay, err[:300]))
                if "too early" in err:
                    return None, tried
    return None, tried


def http(url, data=None, method=None, timeout=20):
    req = urllib.request.Request(url, data=data, method=method, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=capped(timeout)) as f:
        return f.status, f.read()


def drand_latest(relays, chain):
    tried = []
    for attempt in range(ATTEMPTS):
        if attempt:
            time.sleep(PAUSE)
        for relay in relays:
            if time_left() < 90:
                tried.append("gave up: this run's time is spent")
                return None, None, tried
            try:
                _, body = http("%s/%s/public/latest" % (relay.rstrip("/"), chain))
                return int(json.loads(body)["round"]), relay, tried
            except Exception as e:                           # any failure: try the next relay
                tried.append("%s: %s" % (relay, str(e)[:200]))
    return None, None, tried


# ----------------------------------------------------------------------------- git
def is_local(repo):
    return repo.startswith("/") or repo.startswith("file://")


def repo_key(u):
    """(host family, path) of a repository address, to compare addresses written differently:
    SSH with or without a user, a port or a host alias (github-sc2:...), ssh://, HTTPS in any
    case, with or without .git or a final slash; the real path of a local one."""
    u = u.strip()
    if is_local(u) or not re.search(r"[:@]", u):
        return ("local", os.path.realpath(u[len("file://"):] if u.startswith("file://") else u))
    m = re.match(r"(?i)^(?:[a-z+]+://)?(?:[^@/]+@)?([^/:]+)(?::\d+)?[:/]/*(.+?)(?:\.git)?/*$", u)
    if not m:
        return ("other", u.lower())
    host, path = m.group(1).lower(), m.group(2).lower()
    return ("github" if "github" in host else "gitlab" if "gitlab" in host else host, path)


def web_of(repo):
    """https address of an SSH repository URL (git@host:owner/repo.git, ssh://...)."""
    m = re.fullmatch(r"(?:ssh://)?[^@/\s]+@([^:/\s]+)(?::\d+)?[:/]([^\s]+?)(?:\.git)?/?", repo)
    return "https://%s/%s" % (m.group(1), m.group(2)) if m else None


def git(args, cwd=None, ssh=None, timeout=300, extra_env=None):
    env = {k: v for k, v in os.environ.items() if not k.startswith("SC2_")}
    env.update(GIT_TERMINAL_PROMPT="0", GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull, LC_ALL="C")
    env.update(extra_env or {})
    if ssh:
        env["GIT_SSH_COMMAND"] = ssh
    try:
        r = subprocess.run(["git"] + IDENT + args, cwd=cwd, env=env, capture_output=True, timeout=capped(timeout))
    except (OSError, subprocess.SubprocessError) as e:
        return 1, b"", "%s: %s" % (type(e).__name__, e)
    return r.returncode, r.stdout, " ".join(r.stderr.decode("utf-8", "replace").split())


def git_init(d):
    """A SHA-1 repository whatever git's default: the hosts speak SHA-1, and Git 3.0 is to
    default to SHA-256, which would break every fetch into an empty repository. A git older
    than 2.29 knows no --object-format, and makes SHA-1 anyway."""
    if git(["init", "-q", "--object-format=sha1"], cwd=d)[0]:
        git(["init", "-q"], cwd=d)


def ssh_for(key, tmp):
    """SSH with this deploy key only. accept-new: whatever an impostor host could see is
    either nothing (the probe) or the record at the moment it is being published anyway."""
    if not key:
        return None
    return ("ssh -i %s -o IdentitiesOnly=yes -o BatchMode=yes -o ConnectTimeout=30 "
            "-o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=%s"
            % (shlex.quote(key), shlex.quote(os.path.join(tmp, "known_hosts"))))


def deploy_keys(cfg, tmp):
    """Each target's deploy key, from its environment variable, in a private file."""
    keys = []
    for i, t in enumerate(cfg["targets"]):
        v = secret_value(t["secret"]).replace("\r\n", "\n").replace("\r", "\n").strip()
        if not v:
            keys.append(None)
            continue
        p = os.path.join(tmp, "deploy-key-%d" % i)
        with os.fdopen(os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as f:
            f.write(v + "\n")                  # a key pasted without its last newline fails in ssh
        keys.append(p)
    return keys


def probe_write(t, key, tmp):
    """Write access, without writing: a dry-run push of an empty commit to a new branch.
    The server checks the key's permission before the dry run stops."""
    d = tempfile.mkdtemp(prefix="probe-", dir=tmp)
    git_init(d)
    rc, _, err = git(["commit", "-q", "--allow-empty", "-m", "probe"], cwd=d)
    if rc:
        return False, "local git: " + err[:200]
    rc, _, err = git(["push", "--dry-run", "-q", t["repo"], "HEAD:refs/heads/sc2-autorelease-probe"],
                     cwd=d, ssh=ssh_for(key, tmp), timeout=120)
    return rc == 0, err[:300]


def fetch(url, ref, d, ssh=None, depth=None):
    """git fetch of one branch into d, tried three times, 20 s apart: a network has bad minutes,
    and a run comes only once a month. Returns (git's return code, its error)."""
    args = ["fetch", "-q"] + (["--depth", str(depth)] if depth else []) + [url, ref]
    for attempt in range(3):
        rc, _, err = git(args, cwd=d, ssh=ssh, timeout=180)
        if rc == 0 or attempt == 2 or time_left() < 300:
            return rc, err
        time.sleep(20)


def anon_fetch(t, tmp):
    """What an anonymous reader gets: the branch fetched over HTTPS with no credentials."""
    d = tempfile.mkdtemp(prefix="anon-", dir=tmp)
    git_init(d)
    rc, err = fetch(t["web"] + ".git", "refs/heads/" + t["branch"], d, depth=1)
    return (d, "") if rc == 0 else (None, err[:200])


def check_target(t, key, tmp, cfg, base, rel):
    """What a dry run cannot see. The branch exists (an empty mirror would fail only on the
    date); it holds this record's reference at its root (a wrong repository holding a deploy
    key would get your record); it has no other opening/commitment.txt in the way; and,
    for a real kit, anonymous readers can fetch it (a target made private publishes nothing)."""
    d = tempfile.mkdtemp(prefix="tgt-", dir=tmp)
    git_init(d)
    rc, err = fetch(t["repo"], "refs/heads/" + t["branch"], d, ssh_for(key, tmp), depth=1)
    if rc:
        return "its branch %s cannot be fetched (%s): push the opening repository's first files to it" % (t["branch"], err[:200])
    ref, title = os.path.join(base, "commitment-reference.txt"), os.path.join(base, "commitment-title.txt")
    if not cfg.get("rehearsal"):
        rc, got, _ = git(["show", "FETCH_HEAD:commitment-reference.txt"], cwd=d)
        if rc or got != open(ref, "rb").read():
            return "its branch %s does not hold this record's commitment-reference.txt at its root" % t["branch"]
    rc, there, _ = git(["show", "FETCH_HEAD:opening/commitment.txt"], cwd=d)
    if rc == 0:
        p = os.path.join(d, "present.txt")
        write(p, there, 0o600)
        if not matches(p, ref, title, rel):
            return "it holds an opening/commitment.txt that is not this record: the job could not publish there"
    if t.get("web") and not cfg.get("rehearsal"):
        ad, err = anon_fetch(t, tmp)
        if not ad:
            return "an anonymous reader cannot fetch %s (%s): is the repository public?" % (t["web"], err)
    return None


def kit_tag(cfg):
    """The kit's own name in its heartbeats: a random id made with the kit (none in older kits)."""
    return " of kit %s" % cfg["kit_id"] if cfg.get("kit_id") else ""


def job_tag(cfg, plat=None):
    """A platform's public name in heartbeats -- job A, job B -- since the opening repository is
    public and need not say where the other copies live."""
    plats = cfg.get("platforms") or ["GitHub"]
    p = plat or platform_name()
    return "job " + "ABCDEFGH"[plats.index(p)] if p in plats else "job " + re.sub(r"\W", "", p)


def write_test(t, key, tmp, cfg, today, manual):
    """A real push: an empty commit on the branch. Only a real push meets the server's own
    rules (a protected branch, a ruleset that requires pull requests, a GitLab default). From
    a scheduled, healthy run it is also the platform's heartbeat for the run date; a run by hand
    says so, and does not count. Its time is set to noon UTC: it need not tell when the job runs."""
    d, ssh, err = clone(t, key, tmp)
    if not d:
        return False, "clone failed: " + err
    noon = "%sT12:00:00Z" % today
    rc, _, err = git(["commit", "-q", "--allow-empty", "-m", "SC2/%s: write test by automatic-opening %s%s%s, %s"
                      % (cfg["case"], job_tag(cfg), kit_tag(cfg), " (by hand)" if manual else "", today)], cwd=d,
                     extra_env={"GIT_AUTHOR_DATE": noon, "GIT_COMMITTER_DATE": noon})
    if rc:
        return False, "local git: " + err[:200]
    return push_head(d, ssh, t)


def heartbeats(t, key, tmp, cfg, today):
    """{platform: date of its latest heartbeat} on the target's branch, or None if unreadable.
    Each job pushes one per run date, from a healthy scheduled run: the jobs watch each other."""
    d = tempfile.mkdtemp(prefix="hb-", dir=tmp)
    git_init(d)
    rc, _ = fetch(t["repo"], "refs/heads/" + t["branch"], d, ssh_for(key, tmp))
    if rc:
        return None
    rc, out, _ = git(["log", "--format=%s", "FETCH_HEAD"], cwd=d)
    tags = {job_tag(cfg, p): p for p in cfg.get("platforms") or ["GitHub"]}
    seen, mine = {}, re.compile(r"SC2/%s: write test by automatic-opening (job \w+)%s, (\d{4}-\d{2}-\d{2})$"
                                % (re.escape(cfg["case"]), re.escape(kit_tag(cfg))))
    for line in out.decode("utf-8", "replace").splitlines():
        m = mine.fullmatch(line)
        if not m or m.group(1) not in tags:
            continue
        try:
            day = dt.date.fromisoformat(m.group(2))
        except ValueError:
            continue
        if day <= today and day > seen.get(tags[m.group(1)], dt.date.min):   # a future date fools no one
            seen[tags[m.group(1)]] = day
    return seen


def clone(t, key, tmp):
    ssh = ssh_for(key, tmp)
    for attempt in range(3):
        d = os.path.join(tempfile.mkdtemp(prefix="pub-", dir=tmp), "r")
        rc, _, err = git(["clone", "-q", "--branch", t["branch"], t["repo"], d], ssh=ssh)
        if rc == 0:
            return d, ssh, ""
        if time_left() < 300:
            break
        time.sleep(20)
    return None, None, err[:300]


def push_head(d, ssh, t):
    """Push, and if the other job pushed meanwhile, rebase on its commit and push again."""
    err = ""
    for attempt in range(4):
        rc, _, err = git(["push", "-q", "origin", "HEAD:refs/heads/" + t["branch"]], cwd=d, ssh=ssh)
        if rc == 0:
            return True, ""
        if attempt < 3:
            time.sleep(5 * (attempt + 1))
            git(["pull", "-q", "--rebase", "origin", t["branch"]], cwd=d, ssh=ssh)
    return False, err[:300]


def release_half(d, ssh, t, half, peer, case, today):
    """Publish the other platform's key half into opening/: from the date on it is harmless,
    and it lets that platform open its copy even if drand cannot."""
    path = os.path.join(d, *peer["file"].split("/"))
    if os.path.exists(path) and "".join(open(path).read().split()).lower() == half:
        return True, "already there"
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(half + "\n")
    for args in (["add", peer["file"]],
                 ["commit", "-q", "-m", "SC2/%s: half of %s's key, released by %s, %s"
                  % (case, peer["copy"], peer["holder"], today)]):
        rc, _, err = git(args, cwd=d)
        if rc:
            return False, "git %s: %s" % (args[0], err[:200])
    good, err = push_head(d, ssh, t)
    return (True, "released %s" % peer["file"]) if good else (False, "push refused: " + err)


def fetch_half(cfg, state, peer):
    """The half another platform released, from any target, if it checks against config.json."""
    for t, st in zip(cfg["targets"], state):
        if not st:
            continue
        d, ssh = st[0], st[1]
        if git(["fetch", "-q", "origin", t["branch"]], cwd=d, ssh=ssh)[0]:
            continue
        rc, out, _ = git(["show", "FETCH_HEAD:" + peer["file"]], cwd=d)
        v = "".join(out.decode("ascii", "replace").split()).lower()[:128] if rc == 0 else ""
        if half_ok(v, peer):
            return v
    return None


def push_record(d, ssh, t, record, note, case, today, rehearsal=False, plat="GitHub"):
    os.makedirs(os.path.join(d, "opening"), exist_ok=True)
    for name, data in (("commitment.txt", record), ("RELEASE-NOTE-AUTOMATIC.txt", note.encode("utf-8"))):
        with open(os.path.join(d, "opening", name), "wb") as f:
            f.write(data)
    for args in (["add", "opening/commitment.txt", "opening/RELEASE-NOTE-AUTOMATIC.txt"],
                 ["commit", "-q", "-m", "SC2/%s: automatic opening, %s, by the job on %s" % (case, today, plat)]):
        rc, _, err = git(args, cwd=d)
        if rc:
            return False, "git %s: %s" % (args[0], err[:200])
    good, err = push_head(d, ssh, t)
    if not good:
        return False, "push refused: " + err
    rc, _, err = git(["fetch", "-q", "origin", t["branch"]], cwd=d, ssh=ssh)
    rc2, back, _ = git(["show", "FETCH_HEAD:opening/commitment.txt"], cwd=d)
    if rc or rc2 or back != record:
        return False, "pushed, but reading it back did not give the record (%s)" % err[:200]
    if t.get("web") and not rehearsal:
        for attempt in range(3):                       # "published" must mean: anyone can read it
            ad, aerr = anon_fetch(t, os.path.dirname(os.path.dirname(d)))
            if ad:
                rc, back, _ = git(["show", "FETCH_HEAD:opening/commitment.txt"], cwd=ad)
                if rc == 0 and back == record:
                    return True, "published, and read back anonymously: opening/commitment.txt"
            time.sleep(10)
        return False, "pushed, but an anonymous reader cannot fetch it (%s): is the repository public?" % aerr
    return True, "published and read back: opening/commitment.txt"


def file_urls(t):
    """The published file's pages, for the Wayback Machine, on the common hosts."""
    web, b = t.get("web"), t["branch"]
    if not web:
        return []
    u = urllib.parse.urlparse(web)
    host, path = u.netloc.lower(), u.path.strip("/")
    if host == "github.com":
        return [web + "/blob/%s/opening/commitment.txt" % b,
                "https://raw.githubusercontent.com/%s/%s/opening/commitment.txt" % (path, b)]
    if "gitlab" in host:
        return [web + "/-/blob/%s/opening/commitment.txt" % b, web + "/-/raw/%s/opening/commitment.txt" % b]
    if host == "codeberg.org":
        return [web + "/src/branch/%s/opening/commitment.txt" % b, web + "/raw/branch/%s/opening/commitment.txt" % b]
    return []


def archive(t):
    """Best effort: ask Software Heritage to visit the repository and the Wayback Machine to
    capture the published file. A failure is reported, never fatal: redo it by hand."""
    notes, web = [], t.get("web")
    if not web:
        return ["%s: no web address, nothing to archive" % t["repo"]]
    try:
        q = urllib.parse.urlencode({"visit_type": "git", "origin_url": web})
        st, body = http("https://archive.softwareheritage.org/api/1/origin/save/?" + q,
                        data=b"", method="POST", timeout=60)
        notes.append("Software Heritage: save request %s for %s"
                     % (json.loads(body).get("save_request_status", "sent"), web))
    except Exception as e:
        notes.append("Software Heritage: request failed (%s); save %s by hand" % (str(e)[:150], web))
    for u in [web] + file_urls(t):
        try:
            st, _ = http("https://web.archive.org/save/" + u, timeout=180)
            notes.append("Wayback Machine: HTTP %d for %s" % (st, u))
        except Exception as e:
            notes.append("Wayback Machine: failed (%s); save %s by hand" % (str(e)[:150], u))
    return notes


# ----------------------------------------------------------------------- the custodian kit
def read_letter(path):
    """The values the custodian's letter holds: the job must apply exactly the same rule."""
    try:
        s = open(path, encoding="utf-8").read()
    except OSError as e:
        raise SystemExit("cannot read the custodian's letter %s (%s). Build the custodian's kit "
                         "first (RUNBOOK step 10c): this path runs alongside it." % (path, e))
    two = r"((?:  [0-9a-f]{64}\n){2})"
    case = re.match(r"SC2/([0-9A-F]{10}) -- LETTER TO THE CUSTODIAN", s)
    start = re.search(r"STARTING VALUE \(checks my first notice\)\n" + two, s)
    certain = re.search(r"RELEASE-CERTAIN VALUE \(see rule 5\)\n" + two, s)
    cmd = re.search(r'--certain "RELEASE-CERTAIN VALUE" --release (\d{4}-\d{2}-\d{2})'
                    r'(?: --window (\d+)-(\d+))? log\.txt', s)
    sealed = re.search(r"sealed on (\d{4}-\d{2}-\d{2})\.", s)
    if not (case and start and certain and cmd and sealed):
        raise SystemExit("%s is not an English custodian's letter made by sc2-release.py" % path)
    return dict(case=case.group(1), start="".join(start.group(1).split()),
                certain="".join(certain.group(1).split()), release=cmd.group(1),
                window=[int(cmd.group(2) or 30), int(cmd.group(3) or 31)], sealed=sealed.group(1))


# --------------------------------------------------------------------------- the texts
EN_MONTHS = "January February March April May June July August September October November December".split()
FR_MONTHS = "janvier février mars avril mai juin juillet août septembre octobre novembre décembre".split()


def fill(template, **kv):
    for k, v in kv.items():
        template = template.replace("{{%s}}" % k, v)
    left = re.findall(r"\{\{[A-Z_0-9]+\}\}", template)
    assert not left, left
    return template


WORKFLOW = """\
# SC2/{{CASE}} automatic release{{REHEARSAL_TAG}} -- see README.md. No third-party code runs here:
# only the runner's own git, ssh and python3, and the pinned time-lock tool in sc2/tools.
# It runs only on the days below, once a month (RUNBOOK 10A-e): each run decides from sc2/log.txt and
# the date, checks its own health, and publishes when the release is due. A red run e-mails
# you: read it.
name: sc2-autorelease
on:
  schedule:
{{CRONS}}
  workflow_dispatch:
permissions:
  contents: read
concurrency:
  group: sc2-autorelease
  cancel-in-progress: false
jobs:
  sc2:
    runs-on: ubuntu-latest
    timeout-minutes: 45
    steps:
      - name: Get this repository
        env:
          TOKEN: ${{ github.token }}
        run: |
          set -eu
          git init -q "$RUNNER_TEMP/kit"
          cd "$RUNNER_TEMP/kit"
          AUTH=$(printf 'x-access-token:%s' "$TOKEN" | base64 | tr -d '\\n')
          git -c "http.extraheader=AUTHORIZATION: basic $AUTH" fetch -q --depth 1 "$GITHUB_SERVER_URL/$GITHUB_REPOSITORY" "$GITHUB_SHA"
          git checkout -q FETCH_HEAD
      - name: Decide, check, publish when due
        env:
          SC2_KEY: ${{ secrets.SC2_KEY }}
{{SECRET_ENV}}        run: python3 "$RUNNER_TEMP/kit/sc2/tools/sc2-autorelease.py" run --kit "$RUNNER_TEMP/kit"
"""

GITLAB_CI = """\
# SC2/{{CASE}} automatic release{{REHEARSAL_TAG}}: the SECOND scheduler -- see README.md and RUNBOOK 10A-h.
# The same job as .github/workflows/sc2-autorelease.yml, run by GitLab's own clock. Its schedule is
# set in GitLab, not here: Build > Pipeline schedules, {{GL_CRON}}, time zone {{TZ}},
# branch main. That is 17:17 there, four hours before GitHub's run (so that GitHub's job can use,
# the same evening, the key half this one releases), on {{DATES}}, and on no other
# day.
# GitLab clones this repository. The job runs python3, git and ssh from the image below, and the
# pinned tle in sc2/tools; nothing else is fetched or run. The image is Docker's official Python
# image, which GitLab's hosted runners pull through Google Cloud's pull-through cache. This job trusts
# its maintainers as GitHub's job trusts GitHub's runner image: a hostile image could read the
# secrets. It is not pinned to a digest: a frozen image would keep an old git, ssh and TLS, which
# GitHub, GitLab or drand's relays may refuse years from now.
sc2-autorelease:
  image: python:3
  timeout: 45 minutes
  resource_group: sc2-autorelease      # one run at a time, like GitHub's concurrency group
  rules:
    - if: '$CI_PIPELINE_SOURCE == "schedule" || $CI_PIPELINE_SOURCE == "web"'
  script:
    - python3 sc2/tools/sc2-autorelease.py run --kit "$CI_PROJECT_DIR"
"""

GITLAB_SETUP = """\

THE SECOND SCHEDULER, ON GITLAB  (RUNBOOK 10A-h): G1 to G6, then steps 7 to 9 for both
--------------------------------------------------------------------------------
G1. Create a PRIVATE, blank project on GitLab (no README), at the address you gave
    --gitlab-repo: {{GL_REPO}}
    GitLab may ask you to verify the account (a phone number or a card) before it runs
    pipelines. {{GL_CRED}}
G2. Make one push update both copies of the kit. In "{{OUT}}":
      git remote set-url --add --push origin "$(git remote get-url origin)"
      git remote set-url --add --push origin {{GL_REPO}}
      git push -u origin main
    The first line keeps GitHub's address (the one step 3 gave origin): once origin has a
    push address, git pushes only to its push addresses. "git remote -v" must now show two push lines. From then on, every push
    from this folder goes to both, and the notice command checks that both got it.
G3. Its variables. With GitLab's command-line tool (glab 1.63 or later, for --hidden; sign in
    first: glab auth login), which never puts a value on your clipboard:
{{GL_CMDS}}
    Or on the web page: the project > Settings > CI/CD > Variables > Add variable, for each
    one: tick "Protect variable", Key exactly as below, Value = the whole file:
{{GL_LIST}}
G4. Its keys. GitLab's job writes to the opening repositories with its own deploy key(s)
    and reads GitHub's copy of the log with a read-only key; GitHub's job reads GitLab's
    copy with another read-only key.
{{GL_PUB}}
G5. Its clock: Build > Pipeline schedules > New schedule: {{GL_SCHEDULES}},
    cron time zone {{TZ}}, target branch main, Activated. That is 17:17, four hours before
    GitHub's run, on {{DATES}}, and on no other day.
G6. Its e-mail for failed runs: on the project's page, the notification menu next to the bell
    > Custom > tick "Pipeline fails". The e-mail address of that GitLab account must be one
    you read.
"""

README = """\
# SC2/{{CASE}} -- automatic release{{REHEARSAL_TAG}}

This private repository publishes a sealed record on **{{RELEASE_EN}}** unless its author
cancels it, under the same rule as the custodian who holds a paper copy. It was set up on
{{MADE}} with `sc2-autorelease.py` (RUNBOOK step 10A).
{{REHEARSAL_NOTE}}
**Keep it private. Never fork it, make it public, or add collaborators.**

## What it does

On {{DATES}}{{ONLY}}, the job runs
`sc2/tools/sc2-autorelease.py run` at about {{LOCAL}}, {{TZ}} time, on {{PLATFORMS_TEXT}}.{{ALSO}}
Its first scheduled run after setup: {{NEXT_RUN}}.

1. It reads `sc2/log.txt` and applies the custodian's rule -- the `check` of
   `sc2/tools/sc2-release.py`, the same code the custodian's letter prints.
2. Before the release date it checks its own health: the secret, the copy, the time-lock tool,
   the drand network, and each deploy key's write access. Anything wrong turns the run red, and
   the platform e-mails you. It also turns red on purpose once a year (a check-in: it still runs)
   and, as a reminder, on a run that comes within {{REMIND}} days of the release.
3. When the release is due it opens its copy, checks it against the published reference
   (all four digests and the short form), adds `opening/commitment.txt` and
   `opening/RELEASE-NOTE-AUTOMATIC.txt` to {{TARGETS}}, reads them back, and asks Software
   Heritage and the Wayback Machine to archive them.

## To cancel

Exactly as with the custodian: three notices, each received {{WIN_EN}} after the previous
one. Log each notice your custodian reports valid **the same day**, from your working copy of
this repository:

    python3 sc2/tools/sc2-autorelease.py notice <the date the custodian counted it under> <the code>

It checks that the code is the next valid one, adds the line to `sc2/log.txt` (the date, a
space, the code), pushes it to {{PUSH_TO}}, and checks that {{GOT_IT}}.

When the log shows a completed cancellation, the job never opens its copy. {{FIRST}}Then delete
{{DELETE_WHAT}}, and remove {{THEIR}} deploy keys from the opening repositories. Until you
do, {{HOLDS}} a copy that opens on the date below.

## What GitHub holds

`sc2/sealed.bin` is the record, padded to {{SIZE}} bytes and encrypted with a key made of two
halves: the secret `SC2_KEY`, and a value time-locked with drand to round {{ROUND}}
({{ROUND_TIME}} UTC). Nobody can open it before then -- not GitHub, not anyone who can push to
this repository (and so read its secrets) -- unless a threshold of the League of Entropy
colludes, a quantum computer breaks drand's BLS12-381 signatures, or someone spends about
2^128 operations on the time-lock's 128-bit inner key. From then on, whoever holds these files
and the secret can open them, whether or not the release happens.
{{COPIES_NOTE}}
## By hand, after {{ROUND_TIME}} UTC

This needs the secret `SC2_KEY`, which you deleted after setup and which neither platform shows
again: it is here for completeness, and it is what anyone who holds the files and the secret
can do. Work in a folder OUTSIDE this repository (here `~/sc2-open`), so that neither the secret
nor the record can ever be committed. With the secret in `~/sc2-open/SC2_KEY`:

    python3 sc2/tools/sc2-autorelease.py decrypt --kit . --key-file ~/sc2-open/SC2_KEY -o ~/sc2-open/commitment.txt

or, with any tle and Python 3:

    tle -d -n https://api.drand.sh -c {{CHAIN}} sc2/key-timelock.age > ~/sc2-open/kt.txt
    python3 -c "{{BYHAND}}" ~/sc2-open/SC2_KEY ~/sc2-open/kt.txt sc2/sealed.bin > ~/sc2-open/commitment.txt

then check `commitment.txt` with the five commands of VERIFY-PUBLIC.txt.
"""

BYHAND = ("import hashlib,sys;k=lambda f:bytes.fromhex(open(f).read().strip());"
          "S=lambda t,*p,n=64:hashlib.shake_256(t+b'|'+b''.join(p)).digest(n);"
          "c=open(sys.argv[3],'rb').read();"
          "s=S(b'SC2-AUTO-STREAM',S(b'SC2-AUTO-DATA-KEY',k(sys.argv[1]),k(sys.argv[2])),n=len(c));"
          "p=bytes(a^b for a,b in zip(c,s));sys.stdout.buffer.write(p[8:8+int.from_bytes(p[:8],'big')])")

LOG = """\
# SC2/{{CASE}} -- the notices your custodian reported VALID, one per line:
#     YYYY-MM-DD CODE
# The date is the one the custodian's report gives (the date the notice counted under);
# the code is the one you sent, on one line. Log each one the SAME DAY the report arrives:
#     python3 sc2/tools/sc2-autorelease.py notice YYYY-MM-DD CODE
# checks the code, adds the line, commits, pushes and reads it back (RUNBOOK 10A-f). The job
# decides from this file as it stands when it runs: on {{DATES}}, at
# about {{LOCAL}}, {{TZ}} time. Lines starting with # are comments.
"""

SETUP = """\
SC2/{{CASE}} -- SETTING UP THE AUTOMATIC RELEASE{{REHEARSAL_TAG}}   (RUNBOOK step 10A)
================================================================================
{{HEADER}}
{{PEER_WARNING}}
1. Create a PRIVATE, empty repository (no README, no licence) on GitHub -- under your
   account, or under a separate machine account (RUNBOOK 10A-a).
{{PRIVATE_NAME}}
   With a machine account, do steps 1, 3, 4, 6{{G4B}} signed in as that account
   (steps 2 and 5 concern the opening repository, under your own account). Keep its
   password and two-factor recovery codes {{CRED_GH}}: without them you could
   not log a cancellation, and the job would publish.

{{OPENING_STEP}}

3. Push the kit to the private repository:
     cd "{{OUT}}" && git init -q
     git config user.name "<name or pseudonym>" && git config user.email "<e-mail or no-reply address>"
     git add -A && git commit -q -m "SC2/{{CASE}} automatic release"
     git branch -M main && git remote add origin {{PRIVATE_URL}}
     git push -u origin main
   Check on GitHub that it shows the lock icon (Private). This folder stays your working
   copy of it: you log notices here (RUNBOOK 10A-f).

4. The secrets (private repository: Settings > Secrets and variables > Actions >
   New repository secret). With the GitHub command-line tool, which never puts the
   value on your clipboard:
{{GH_SECRETS}}
   Or on the web page: name exactly as below, value = the whole content of the file
   (open it in a text editor). The clipboard is a leak: on Windows, turn off clipboard
   history and cloud clipboard (Settings > System > Clipboard) before you copy.
{{SECRET_LIST}}

5. The deploy key(s), on the repository each target names (step 2): Settings > Deploy keys
   > Add deploy key, title "sc2-autorelease GitHub", key = the .pub file below, and TICK
   "Allow write access" (on GitLab: Settings > Repository > Deploy keys > Add new key, and
   tick "Grant write permissions to this key"):
{{PUB_LIST}}
   Then add a ruleset to that repository (Settings > Rules > Rulesets > New branch ruleset
   > target the default branch > tick "Restrict deletions" and "Block force pushes" >
   Active). The key then cannot delete main or rewrite its history; it can still push
   ordinary commits, each one visible. On GitLab, a protected branch refuses a deploy key
   unless you allow it: Settings > Repository > Branch rules > View details (next to main) >
   Allowed to push and merge > Edit > Deploy keys: add the key > Save changes.

6. E-mail for red runs, on the account that pushed the workflow (GitHub sends a scheduled
   workflow's notices to "the user who initially created the workflow"): Settings >
   Notifications > System > Actions: change "Don't notify" to Email, choose "Only notify
   for failed workflows", Save. That account's e-mail address must be one you read.{{CHECKIN_NOTE}}
{{GITLAB_STEPS}}
{{STEP_RUN}}

8. Today, as soon as step 7 is done, delete this folder -- this file with it, so read step 9
   first (RUNBOOK 10A-d repeats it):
     rm -rf "{{SECRETS}}"
   then check:   ls "{{SECRETS}}"   (it must say "No such file or directory"). Nothing
   in it is needed again; to change anything, build a new kit.

{{STEP_LATER}}
"""

PEER_WARNING = """\
WITH GITLAB'S SHARED HALF, THIS FOLDER OPENS YOUR RECORD AT ONCE: SC2_KEY and
gitlab/SC2_PEER_KEY are the two halves of GitHub's key, and the kit holds GitHub's copy.
Until step 8 deletes it, treat this folder exactly like commitment.txt: on this machine
only, never synced or backed up, and finish the setup in one sitting if you can.
"""

OPENING_STEP_REAL = """\
2. Create the PUBLIC opening repository -- the only one the job may write to -- empty,
   e.g. sc2-{{CASE_LOWER}}-opening, under your own account, and push its first files:
     cd "{{OPENING}}" && git init -q
     git config user.name "<name or pseudonym>" && git config user.email "<e-mail or no-reply address>"
     git add -A && git commit -q -m "SC2/{{CASE}}: reference, for the automatic opening"
     git branch -M main && git remote add origin {{FIRST_TARGET}}
     git push -u origin main{{MORE_TARGETS}}
   Your Step 6a repository stays yours alone: the job never touches it."""

OPENING_STEP_REHEARSAL = """\
2. Your stand-in target(s) must exist already: PRIVATE repositories with one commit on main
   (ask the host to add a README when you create one). Nothing synthetic ever becomes public."""

STEP_RUN_REAL = """\
7. Run it once by hand: private repository > Actions > sc2-autorelease > Run workflow.
   It must end green, with one "ok" line per check: the secret, drand, the time-lock test,
   and, for each target, write access, its branch (with this record's reference, nothing
   in the way, readable anonymously) and a real push (an empty commit). If GitHub asks you
   to enable Actions or workflows for this repository, do so. Then test the e-mail: add a
   line that says only  test  to sc2/log.txt, commit, push, run it by hand again: it must
   turn red, and GitHub must e-mail you. Remove the line, commit, push."""

STEP_LATER_REAL = """\
9. On {{NEXT_RUN}}, the job's first scheduled date (nothing runs before it; no secret needed),
   a run marked "scheduled" must appear in the Actions tab. Put that date in your calendar
   now: this file goes at step 8 (the kit's README.md keeps it).
   {{FIRST_RUN}}"""

STEP_RUN_REAL_GL = """\
7. Run both once by hand. GitHub: private repository > Actions > sc2-autorelease > Run
   workflow. GitLab: the project > Build > Pipelines > New pipeline, branch main. Each must
   end green, with one "ok" line per check: the secret(s), the other platform's copy of the
   log ("readable, and the same as this one"), drand, the time-lock test, and, for each
   target, write access, its branch (with this record's reference, nothing in the way,
   readable anonymously) and a real push (an empty commit). If GitHub asks you to enable
   Actions or workflows for this repository, do so. Then test the e-mails: add a line that
   says only  test  to sc2/log.txt, commit, push, run both by hand again: both must turn
   red, and each platform must e-mail you. Remove the line, commit, push."""

STEP_LATER_REAL_GL = """\
9. On {{NEXT_RUN}}, the jobs' first scheduled date (nothing runs before it; no secret
   needed), a scheduled run must appear on each platform. Put that date in your calendar
   now: this file goes at step 8 (the kit's README.md keeps it).
   {{FIRST_RUN}}"""

STEP_RUN_REHEARSAL = """\
7. Run it once by hand: Actions > sc2-autorelease > Run workflow. It must end green, every
   health line "ok". Then test the e-mail: add a line that says only  test  to sc2/log.txt,
   commit, push, and run it by hand again: it must turn red, and GitHub must e-mail you.
   Remove the line, commit, push."""

STEP_LATER_REHEARSAL = """\
9. Then do nothing. On {{DUE}}, at about {{LOCAL}} ({{TZ}}),
   the SCHEDULED run must publish opening/commitment.txt to the stand-in target by itself.
   That evening, check the target, and the Actions tab: a run marked "scheduled" that ended
   green. Then delete both repositories, the deploy key and the rehearsal's kit folder."""

STEP_RUN_REHEARSAL_GL = """\
7. Run both once by hand -- GitHub: Actions > sc2-autorelease > Run workflow; GitLab: Build >
   Pipelines > New pipeline, branch main. Each must end green, every health line "ok". Then
   test the e-mails: add a line that says only  test  to sc2/log.txt, commit, push, and run
   both by hand again: both must turn red, and each platform must e-mail you. Remove the
   line, commit, push."""

STEP_LATER_REHEARSAL_GL = """\
9. Then do nothing. On {{DUE}} the SCHEDULED runs must publish opening/commitment.txt to
   the stand-in target(s) by themselves: GitLab's at 17:17 ({{TZ}}), which publishes it{{GL_HALF}},
   then GitHub's at 21:17, which finds it done. That evening, check the targets, and both
   platforms' runs: a scheduled run that ended green on each. Then delete all the rehearsal's
   repositories, their deploy keys and the rehearsal's kit folder."""

OPENING_README = """\
# SC2/{{CASE}} -- opening

This repository holds the public reference of a sealed record, SC2/{{CASE}}: its two lines in
`commitment-reference.txt` and their short form in `commitment-title.txt`, the same as those
published in {{PUB_EN}} and archived since. If its author does not open the record themselves,
an automatic job may publish it here one day, as `opening/commitment.txt` with a release note.
Anyone can then check it against the reference with five standard commands; nobody needs to
trust this repository, its owner or the job.
"""

NOTE = """\
AUTOMATIC OPENING OF SEALED RECORD SC2/{{CASE}}{{REHEARSAL_TAG}}
================================================================================

This is the opening of a sealed record, published automatically on {{TODAY}} by a
scheduled job that its author set up on {{MADE}}; this copy was opened by the job on
{{PLATFORM}}. Its public reference -- two lines, commitment-reference.txt at the root of
this repository -- was published in {{PUB_EN}}. Short form (one line; the breaks here are
not part of it):
{{SHORT}}

The sealed record is opening/commitment.txt. Anyone can check that it is exactly the
record the reference referred to; nobody needs to trust this job, {{PLATFORM}} or drand,
because a single changed byte would fail the check. From the repository's root:

  { printf 'SC2-A\\n'; cat opening/commitment.txt; } | openssl dgst -sha3-512
  { printf 'SC2-B\\n'; cat opening/commitment.txt; } | openssl dgst -sha3-512
  openssl dgst -blake2b512 opening/commitment.txt
  sha512sum opening/commitment.txt                 (macOS: shasum -a 512)
  tr -s '[:space:]' ' ' < commitment-reference.txt | sed 's/^ *//; s/ *$//' | tr -d '\\n' | openssl dgst -sha3-512

The first four must equal S3A, S3B, B2 and S5 on line 2 of commitment-reference.txt;
the fifth must equal the short form above. VERIFY-PUBLIC.txt explains each step.

The author had arranged for this record to be released on {{RELEASE}} unless they
cancelled it, which required three coded notices, each received {{WIN_EN}} after the
previous one. The job's log showed no completed cancellation. A person the author chose
(the custodian) holds a sealed paper copy under the same rule and may publish it too:
it is the same record. Until then, the job's copy was encrypted twice: with a key held
as a {{PLATFORM}} secret, and with a time-lock set to round {{ROUND}} of the drand
network (League of Entropy, quicknet), at {{ROUND_TIME}} UTC.{{HALF_EN}}

--------------------------------------------------------------------------------
OUVERTURE AUTOMATIQUE DE L'ENREGISTREMENT SCELLÉ SC2/{{CASE}}{{REHEARSAL_TAG}}

Ceci est l'ouverture d'un enregistrement scellé, publiée automatiquement le {{TODAY}}
par une tâche programmée que son auteur a mise en place le {{MADE}} ; cette copie a été
ouverte par la tâche sur {{PLATFORM}}. Sa référence publique -- deux lignes,
commitment-reference.txt à la racine de ce dépôt -- a été publiée en {{PUB_FR}} (forme
courte ci-dessus).

L'enregistrement scellé est opening/commitment.txt. Chacun peut vérifier que c'est
exactement l'enregistrement auquel renvoyait la référence, avec les cinq commandes
ci-dessus ; personne n'a besoin de faire confiance à cette tâche, à {{PLATFORM}} ou à drand :
un seul octet modifié ferait échouer la vérification.

L'auteur avait prévu que cet enregistrement serait publié le {{RELEASE}} sauf
annulation, ce qui exigeait trois avis codés, chacun reçu {{WIN_FR}} après le
précédent. Le journal de la tâche ne montrait aucune annulation complète. Une personne
choisie par l'auteur (le dépositaire) détient une copie papier scellée sous la même
règle et peut aussi la publier : c'est le même enregistrement. Jusque-là, la copie de
la tâche était chiffrée deux fois : avec une clé conservée comme secret {{PLATFORM}}, et
avec un verrou temporel réglé sur le tour {{ROUND}} du réseau drand (League of Entropy,
quicknet), à {{ROUND_TIME}} UTC.{{HALF_FR}}
"""


def release_note(cfg, today, rel, via=None):
    pub = dt.date.fromisoformat(cfg["sealed"])
    lo, hi = cfg["window"]
    short = open(cfg["_title"], encoding="ascii").read().strip()
    return fill(NOTE, CASE=cfg["case"], REHEARSAL_TAG=" -- REHEARSAL, SYNTHETIC DATA" if cfg.get("rehearsal") else "",
                TODAY=today.isoformat(), MADE=cfg["made"], RELEASE=cfg["release"], PLATFORM=my_copy(cfg)[0],
                PUB_EN="%s %d" % (EN_MONTHS[pub.month - 1], pub.year),
                PUB_FR="%s %d" % (FR_MONTHS[pub.month - 1], pub.year),
                SHORT="  SC2 REF-SHA3-512=\n" + "\n".join("  " + short[17:][i:i + 64] for i in range(0, 128, 64)),
                WIN_EN=rel.window_en(lo, hi), WIN_FR=rel.window_fr(lo, hi),
                ROUND=str(cfg["drand"]["round"]), ROUND_TIME=iso(round_time(cfg["drand"]["round"])),
                HALF_EN=("\ndrand did not open that lock: the job used instead the copy of its half that the\n"
                         "author's other job, on %s, held and released once the release was due." % via) if via else "",
                HALF_FR=("\ndrand n'a pas ouvert ce verrou : la tâche a utilisé à la place la copie de cette\n"
                         "moitié de clé que détenait l'autre tâche de l'auteur, sur %s, et qu'elle a\n"
                         "publiée une fois la publication due." % via) if via else "")


# --------------------------------------------------------------------------- make
def check_dirs(*dirs):
    ps = [os.path.abspath(d) for d in dirs if d]
    for p in ps:
        if os.path.exists(p):
            raise SystemExit("REFUSING: %s already exists. Move it aside deliberately." % p)
    for i, x in enumerate(ps):
        for j, y in enumerate(ps):
            if i != j and (x == y or y.startswith(x + os.sep)):
                raise SystemExit("REFUSING: %s and %s must be separate folders, neither inside the other" % (x, y))


def write(path, data, mode):
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as f:
        f.write(data if isinstance(data, bytes) else data.encode("utf-8"))
    os.chmod(path, mode)


def build(rel, record, ref_path, title_path, letter, targets, tz, out, secrets_dir, opening_dir, phys_bits,
          ks_material, lock_time, rehearsal, today, canary_rounds, check_in, gitlab=False, peer=True,
          privs=None):
    """Writes the repository folder, the opening repository's first files, and the secrets
    folder. Everything is checked first."""
    case = letter["case"]
    lo, hi = letter["window"]
    release = dt.date.fromisoformat(letter["release"])
    ways, notes = tle_ways(HERE)
    if not ways:
        raise SystemExit("no tle to run: %s. On a Mac, install Go and the same version:\n"
                         "  go install %s@%s   and run this with SC2_TLE=$(go env GOPATH)/bin/tle"
                         % ("; ".join(notes), TLE_MODULE, TLE_VERSION))
    for n in notes:
        say("  note: " + n)
    if not shutil.which("ssh-keygen") and any(not is_local(t["repo"]) for t in targets):
        raise SystemExit("ssh-keygen is needed to make the deploy key(s)")

    # One copy per platform, each with its own two key halves: no platform's secrets open the
    # other's copy. K_s of each comes from the same dice, separated by name (SHAKE256).
    platforms = ["GitHub"] + (["GitLab"] if gitlab else [])
    peer = bool(peer and gitlab)
    halves = {}
    for plat in platforms:
        ks_p = shake("SC2-AUTO-KEY-S" if plat == "GitHub" else "SC2-AUTO-KEY-S|" + plat, ks_material)
        kt_p = os.urandom(64)
        sealed_p = seal(record, ks_p, kt_p)
        assert unseal(sealed_p, ks_p, kt_p) == record and unseal(sealed_p, ks_p, os.urandom(64)) is None
        halves[plat] = (ks_p, kt_p, sealed_p)
    if gitlab:      # GitLab's secret, and even GitHub's time-locked half, do not open GitHub's copy
        assert unseal(halves["GitHub"][2], halves["GitLab"][0], halves["GitHub"][1]) is None
    ks = halves["GitHub"][0]
    rnd = round_at(lock_time)
    if round_time(rnd) <= time.time():
        raise SystemExit("REFUSING: the time-lock would already be open (%s UTC)" % iso(round_time(rnd)))
    locks = {}
    for plat in platforms:
        say("time-locking %s's key half to round %d (%s UTC)..." % (plat, rnd, iso(round_time(rnd))))
        locks[plat], label, relay = timelock_encrypt(ways, RELAYS, CHAIN, rnd, halves[plat][1].hex().encode())
        say("  ok   with %s via %s" % (label, relay))

    canary = secrets.token_hex(32).encode()
    crnd = current_round() + max(1, canary_rounds)
    clocked, _, _ = timelock_encrypt(ways, RELAYS, CHAIN, crnd, canary)
    early, tried = timelock_decrypt(ways, RELAYS, CHAIN, clocked)
    if early is not None or not any("too early" in t for t in tried):
        raise SystemExit("REFUSING: this tle does not time-lock: a test value either opened before its round "
                         "or could not be asked at all:\n  " + "\n  ".join(tried or ["it opened at once"]))
    say("  ok   a test value time-locked to round %d refuses to open before it" % crnd)
    wait = round_time(crnd) + 2 - time.time()
    if wait > 0:
        say("checking the time-lock end to end: waiting %d s for round %d..." % (wait, crnd))
        time.sleep(wait)
    opened, tried = timelock_decrypt(ways, RELAYS, CHAIN, clocked)
    if opened != canary:
        raise SystemExit("REFUSING: a test time-lock did not open as it should:\n  " + "\n  ".join(tried))
    say("  ok   a test value time-locked to round %d opened, and matches" % crnd)

    check_dirs(out, secrets_dir, opening_dir)          # again: nothing may have appeared meanwhile
    old = os.umask(0o077)
    try:
        os.makedirs(os.path.join(out, "sc2", "tools"))
        os.makedirs(os.path.join(out, ".github", "workflows"))
        os.makedirs(secrets_dir)
        os.chmod(secrets_dir, 0o700)
        for plat in platforms:                         # one key per target AND per platform:
            kdir = secrets_dir if plat == "GitHub" else os.path.join(secrets_dir, plat.lower())
            if not os.path.isdir(kdir):                # revoking one platform's never stops the other
                os.makedirs(kdir, 0o700)
            for i, t in enumerate(targets):
                if is_local(t["repo"]):
                    continue
                base = os.path.join(kdir, t["secret"])
                r = subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C",
                                    "sc2-autorelease %s SC2/%s" % (plat, case), "-f", base], capture_output=True)
                if r.returncode:
                    raise SystemExit("ssh-keygen failed: %s" % r.stderr.decode(errors="replace"))
                os.rename(base + ".pub", base + ".pub.txt")
                os.chmod(base, 0o400)
        # Each job READS the other platform's copy of the log with a read-only key, so that a
        # notice pushed to one copy only cannot let the other publish (RUNBOOK 10A-h).
        for plat in (platforms if privs else []):
            other = [p for p in platforms if p != plat][0]
            if is_local(privs[other]):
                continue
            base = os.path.join(secrets_dir if plat == "GitHub" else os.path.join(secrets_dir, plat.lower()),
                                "SC2_READ_KEY")
            r = subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C",
                                "sc2-log-read %s SC2/%s" % (plat, case), "-f", base], capture_output=True)
            if r.returncode:
                raise SystemExit("ssh-keygen failed: %s" % r.stderr.decode(errors="replace"))
            os.rename(base + ".pub", base + ".pub.txt")
            os.chmod(base, 0o400)
        for plat in platforms:
            kdir = secrets_dir if plat == "GitHub" else os.path.join(secrets_dir, plat.lower())
            write(os.path.join(kdir, "SC2_KEY"), halves[plat][0].hex() + "\n", 0o400)
        if peer:            # GitLab holds GitHub's time-locked half, to release it on the date
            write(os.path.join(secrets_dir, "gitlab", "SC2_PEER_KEY"), halves["GitHub"][1].hex() + "\n", 0o400)

        S = lambda *p: os.path.join(out, "sc2", *p)
        shutil.copyfile(ref_path, S("commitment-reference.txt"))
        shutil.copyfile(title_path, S("commitment-title.txt"))
        copies = {}
        for plat in platforms:
            sfx = "" if plat == "GitHub" else "-" + plat.lower()
            copies[plat] = dict(sealed="sealed%s.bin" % sfx, timelock="key-timelock%s.age" % sfx,
                                key_check=key_check(halves[plat][0]), secret="SC2_KEY")
            write(S(copies[plat]["sealed"]), halves[plat][2], 0o644)
            write(S(copies[plat]["timelock"]), locks[plat], 0o644)
        write(S("canary-timelock.age"), clocked, 0o644)
        dates = run_dates(release)
        times = run_times(platforms)
        hhmm = {p: "%02d:%02d" % t for p, t in times.items()}
        years = kit_years(today, release)
        gh_crons = github_crons(dates, tz, times["GitHub"], years)
        also = github_also(gh_crons, dates, tz, years)
        local = ("%s (GitLab) and %s (GitHub)" % (hhmm["GitLab"], hhmm["GitHub"])) if gitlab else hhmm["GitHub"]
        common = dict(CASE=case, CASE_LOWER=case.lower(), TZ=tz, LOCAL=local, MADE=today.isoformat(),
                      DATES=run_words(dates), REHEARSAL_TAG=" -- REHEARSAL, SYNTHETIC DATA" if rehearsal else "")
        write(S("log.txt"), fill(LOG, CASE=case, TZ=tz, DATES=common["DATES"], LOCAL=local), 0o644)
        for name in ("sc2-autorelease.py", "sc2-release.py"):
            shutil.copyfile(os.path.join(HERE, name), S("tools", name))
        for a, want in TLE_SHA256.items():
            src = os.path.join(HERE, "tle-linux-" + a)
            if not os.path.isfile(src) or sha256_file(src) != want:
                raise SystemExit("REFUSING: tle-linux-%s beside this script is missing or is not the pinned build" % a)
            shutil.copyfile(src, S("tools", "tle-linux-" + a))
            os.chmod(S("tools", "tle-linux-" + a), 0o755)

        cfg = dict(format=FORMAT, case=case, rehearsal=rehearsal, made=today.isoformat(),
                   sealed=letter["sealed"], release=letter["release"], timezone=tz, window=[lo, hi],
                   start=letter["start"], certain=letter["certain"], key_check=key_check(ks), copies=copies,
                   peer=(dict(copy="GitHub", holder="GitLab", secret="SC2_PEER_KEY",
                              file="opening/key-for-GitHub.txt",
                              check=hashlib.sha3_512(b"SC2-AUTO-PEER-CHECK|" + halves["GitHub"][1]).hexdigest())
                         if peer else None),
                   physical_entropy_bits=round(phys_bits), size=SIZE,
                   drand=dict(chain=CHAIN, genesis=GENESIS, period=PERIOD, round=rnd,
                              round_time_utc=iso(round_time(rnd)), relays=RELAYS),
                   canary=dict(round=crnd, sha512=hashlib.sha512(canary).hexdigest()),
                   tle=dict(module=TLE_MODULE, version=TLE_VERSION, sha256=TLE_SHA256),
                   check_in=bool(check_in), runs=[d.isoformat() for d in dates], run_at=hhmm, platforms=platforms,
                   kit_id=secrets.token_hex(4),
                   also_runs={"GitHub": also} if also else {},
                   private_repos=privs,
                   tz_offsets=tz_table(tz, today - dt.timedelta(days=2), release + dt.timedelta(days=400)),
                   targets=targets, files={})
        for name in [c[k] for c in copies.values() for k in ("sealed", "timelock")] + [
                "canary-timelock.age", "commitment-reference.txt", "commitment-title.txt"]:
            cfg["files"][name] = sha512_file(S(name))
        write(S("config.json"), json.dumps(cfg, indent=1) + "\n", 0o644)

        envs = "".join("          %s: ${{ secrets.%s }}\n" % (n, n)
                       for n in [t["secret"] for t in targets if not is_local(t["repo"])]
                       + (["SC2_READ_KEY"] if privs and not is_local(privs["GitLab"]) else []))
        crons = "\n".join("    - cron: '%s'   # %s, %s in %s%s" % (c, date_words(sorted(ds, key=lambda x: (x.month, x.day))),
                                                                  hhmm["GitHub"], tz, n) for c, ds, n in gh_crons)
        write(os.path.join(out, ".github", "workflows", "sc2-autorelease.yml"),
              fill(WORKFLOW, CRONS=crons, SECRET_ENV=envs, **{k: common[k] for k in ("CASE", "REHEARSAL_TAG")}), 0o644)
        if gitlab:
            write(os.path.join(out, ".gitlab-ci.yml"), fill(
                GITLAB_CI, GL_CRON=" and ".join("'%s'" % c for c in gitlab_crons(dates, times["GitLab"])),
                **{k: common[k] for k in ("CASE", "TZ", "DATES", "REHEARSAL_TAG")}), 0o644)
        write(os.path.join(out, ".gitattributes"), "* -text\n", 0o644)
        write(os.path.join(out, ".gitignore"), "# never commit a secret or an opened record here\n"
              "SC2_KEY*\nSC2_DEPLOY_KEY*\nSC2_READ_KEY*\nSC2_PEER_KEY*\nkt.txt\n/commitment.txt\nopened*\n", 0o644)
        pub = dt.date.fromisoformat(letter["sealed"])
        if opening_dir:
            os.makedirs(opening_dir)
            shutil.copyfile(ref_path, os.path.join(opening_dir, "commitment-reference.txt"))
            shutil.copyfile(title_path, os.path.join(opening_dir, "commitment-title.txt"))
            write(os.path.join(opening_dir, "README.md"), fill(
                OPENING_README, CASE=case, PUB_EN="%s %d" % (EN_MONTHS[pub.month - 1], pub.year)), 0o644)
            write(os.path.join(opening_dir, ".gitattributes"), "* -text\n", 0o644)
        write(os.path.join(out, "README.md"), fill(
            README, RELEASE_EN=release.strftime("%d %B %Y").lstrip("0"), REMIND=str(max(2 * hi, 62)),
            ONLY="" if also else ", and on no other day",
            ALSO=("\nGitHub's job also runs on %s, because its schedule is in UTC (see the workflow\nfile)." % also
                  if also else ""),
            NEXT_RUN=str(next_run(dates, today)),
            TARGETS=", ".join(t.get("web") or t["repo"] for t in targets), WIN_EN=rel.window_en(lo, hi),
            SIZE=str(SIZE), ROUND=str(rnd), ROUND_TIME=iso(round_time(rnd)), CHAIN=CHAIN, BYHAND=BYHAND,
            REHEARSAL_NOTE=("\n**REHEARSAL: the record here is SYNTHETIC. Delete this repository, and what "
                            "it published, when you are done.**\n" if rehearsal else ""),
            COPIES_NOTE=(("\nWith GitLab, `sc2/sealed-gitlab.bin` is GitLab's own copy, under GitLab's own `SC2_KEY` and its\n"
                          "own time-locked half (`sc2/key-timelock-gitlab.age`): neither platform's secrets open the other's\n"
                          "copy.%s\n" % (" GitLab also holds the half of GitHub's key that drand locks (`SC2_PEER_KEY`) and\n"
                                          "releases it into `opening/key-for-GitHub.txt` once the release is due, so that GitHub's job can open its\n"
                                          "copy even if drand is gone. GitHub and GitLab together, before the date, could therefore\n"
                                          "open GitHub's copy without breaking drand (RUNBOOK 10A-h)." if peer else ""))
                         if gitlab else ""),
            PLATFORMS_TEXT=("GitLab (`.gitlab-ci.yml`) first, then GitHub (`.github/workflows/`): two "
                            "independent\nclocks, each reading the other's copy of the log and watching its "
                            "heartbeat" if gitlab else "GitHub"),
            PUSH_TO="both private repositories, GitHub's and GitLab's" if gitlab else "this repository",
            GOT_IT="each one got it" if gitlab else "it got there",
            DELETE_WHAT=("both private repositories: this one (Settings, General, Delete this repository), "
                         "and GitLab's (on its page, Actions, Delete; then again Actions, Delete permanently: "
                         "otherwise GitLab keeps it 30 days)" if gitlab else
                         "this repository (Settings, General, Delete this repository)"),
            THEIR="their" if gitlab else "its", HOLDS="each platform keeps" if gitlab else "GitHub keeps",
            FIRST=("First make sure both copies hold every\nnotice (`notice` ended `every copy has it`): a job that can no "
                   "longer read the other copy goes\nby its own. " if gitlab else ""),
            **{k: common[k] for k in ("CASE", "MADE", "LOCAL", "TZ", "DATES", "REHEARSAL_TAG")}), 0o644)

        sd = os.path.abspath(secrets_dir)     # step 2 of SETUP.txt changes directory
        gh_repo, gl_web = "OWNER/REPO", None
        if privs and web_of(privs["GitHub"]):
            host_path = web_of(privs["GitHub"])[len("https://"):]
            gh_repo = host_path[len("github.com/"):] if host_path.startswith("github.com/") else host_path
        if privs and web_of(privs["GitLab"]):
            gl_web = web_of(privs["GitLab"])
        ghs = ["     gh secret set SC2_KEY --repo %s < \"%s/SC2_KEY\"" % (gh_repo, sd)]
        lst = ["     SC2_KEY            <- %s/SC2_KEY" % sd]
        pubs = []
        for t in targets:
            if is_local(t["repo"]):
                continue
            ghs.append("     gh secret set %s --repo %s < \"%s/%s\"" % (t["secret"], gh_repo, sd, t["secret"]))
            lst.append("     %-18s <- %s/%s" % (t["secret"], sd, t["secret"]))
            pubs.append("     %s  <- %s/%s.pub.txt" % (t.get("web") or t["repo"], sd, t["secret"]))
        if privs and not is_local(privs["GitLab"]):
            ghs.append("     gh secret set SC2_READ_KEY --repo %s < \"%s/SC2_READ_KEY\"" % (gh_repo, sd))
            lst.append("     %-18s <- %s/SC2_READ_KEY  (reads GitLab's copy of the log)" % ("SC2_READ_KEY", sd))
        remote = [t for t in targets if not is_local(t["repo"])]
        gl_cmds, gl_list = [], []
        R = " -R %s" % gl_web if gl_web else ""
        for name, kind, what in ([("SC2_KEY", "masked", "GitLab's own, not GitHub's")]
                                 + ([("SC2_PEER_KEY", "masked", "the half of GitHub's key, RUNBOOK 10A-h")] if peer else [])
                                 + [(t["secret"], "file", "writes to %s" % (t.get("web") or t["repo"])) for t in remote]
                                 + ([("SC2_READ_KEY", "file", "reads GitHub's copy of the log")]
                                    if privs and not is_local(privs["GitHub"]) else [])):
            flags = "--masked --hidden --protected" if kind == "masked" else "--type file --protected"
            gl_cmds.append("      glab variable set %s %s%s < \"%s/gitlab/%s\"" % (name, flags, R, sd, name))
            gl_list.append("      %-17s Type \"%s\", Visibility \"%s\" -- %s:\n"
                           "                        %s/gitlab/%s"
                           % (name, "Variable" if kind == "masked" else "File",
                              "Masked and hidden" if kind == "masked" else "Visible", what, sd, name))
        gl_pub = ["    a. On each opening repository, title \"sc2-autorelease GitLab\", with write access, as in"
                  "\n       step 5:"]
        gl_pub += ["         %s  <- %s/gitlab/%s.pub.txt" % (t.get("web") or t["repo"], sd, t["secret"])
                   for t in remote] or ["         (none: local targets only)"]
        if privs and not is_local(privs["GitHub"]):
            gl_pub.append("    b. On GitHub's private repository: Settings > Deploy keys > Add deploy key, title\n"
                          "       \"sc2-log-read GitLab\", key = %s/gitlab/SC2_READ_KEY.pub.txt,\n"
                          "       and do NOT tick \"Allow write access\": this key only reads." % sd)
        if privs and not is_local(privs["GitLab"]):
            gl_pub.append("    c. On this GitLab project: Settings > Repository > Deploy keys > Add new key, title\n"
                          "       \"sc2-log-read GitHub\", key = %s/SC2_READ_KEY.pub.txt, and do NOT\n"
                          "       tick \"Grant write permissions to this key\": this key only reads." % sd)
        gl_pub.append("    On a GitLab opening repository, let both jobs' keys push to main: Settings > Repository >\n"
                      "    Branch rules > View details (next to main) > Allowed to push and merge > Edit >\n"
                      "    Deploy keys: add each > Save changes (step 5).")

        write(os.path.join(secrets_dir, "SETUP.txt"), fill(
            SETUP, OUT=os.path.abspath(out), SECRETS=os.path.abspath(secrets_dir), GH_SECRETS="\n".join(ghs),
            HEADER=("This folder holds SECRETS: SC2_KEY, SC2_DEPLOY_KEY* and SC2_READ_KEY for GitHub, and in\n"
                    "gitlab/ GitLab's own%s. Never commit them, never put them in a\n"
                    "repository folder, never send them by e-mail or chat. Paste them into GitHub and\n"
                    "GitLab only, then delete this folder (step 8)." % (", with SC2_PEER_KEY" if peer else "")
                    if gitlab else
                    "This folder holds SECRETS: SC2_KEY and the deploy key(s) SC2_DEPLOY_KEY*. Never commit\n"
                    "them, never put them in a repository folder, never send them by e-mail or chat. Paste\n"
                    "them into GitHub only, then delete this folder (step 8)."),
            PEER_WARNING=("\n" + PEER_WARNING) if peer else "",
            PRIVATE_NAME=("   Its address must be the one you gave --private-repo:\n     %s" % privs["GitHub"]
                          if privs else "   A neutral name, e.g. sc2-auto-%s." % case.lower()),
            SECRET_LIST="\n".join(lst), PUB_LIST="\n".join(pubs) or "     (none: local targets only)",
            STEP_RUN=fill({(False, False): STEP_RUN_REAL, (False, True): STEP_RUN_REAL_GL,
                           (True, False): STEP_RUN_REHEARSAL, (True, True): STEP_RUN_REHEARSAL_GL}[(rehearsal, gitlab)],
                          DUE=release.isoformat(), **{k: common[k] for k in ("LOCAL", "TZ")}),
            STEP_LATER=fill({(False, False): STEP_LATER_REAL, (False, True): STEP_LATER_REAL_GL,
                             (True, False): STEP_LATER_REHEARSAL, (True, True): STEP_LATER_REHEARSAL_GL}[(rehearsal, gitlab)],
                            DUE=release.isoformat(), NEXT_RUN=str(next_run(dates, today)),
                            GL_HALF="\n   after releasing GitHub's key half" if peer else "", FIRST_RUN=(
                                ("GitLab's (it runs first) is red on purpose: the yearly check-in, whose\n"
                                 "   message begins \"YEARLY CHECK-IN, not a fault\" (a REMINDER instead if the\n"
                                 "   release is that close). GitHub's must be green." if gitlab else
                                 "It is red on purpose: the yearly check-in, whose message begins \"YEARLY\n"
                                 "   CHECK-IN, not a fault\" (a REMINDER instead if the release is that close).")
                                if check_in else ("Both must be green." if gitlab else "It must be green.")),
                            **{k: common[k] for k in ("LOCAL", "TZ")}),
            G4B=", 7 and G4 b" if gitlab else " and 7",
            PRIVATE_URL=(privs["GitHub"] + "\n     (with a machine account through gh, its HTTPS address instead, 10A-a)"
                         if privs else "<SSH or HTTPS URL of the private repository>"),
            CRED_GH=("with one printed copy of your cancellation\n"
                     "   codes, and GitLab's with the other, never both in one place (step G1)" if peer
                     else "with your cancellation codes"),
            GITLAB_STEPS=fill(GITLAB_SETUP, OUT=os.path.abspath(out), TZ=tz, DATES=common["DATES"],
                              GL_SCHEDULES=(("interval pattern \"%s\"" % gitlab_crons(dates, times["GitLab"])[0])
                                            if len(gitlab_crons(dates, times["GitLab"])) == 1 else
                                            "one schedule for each interval pattern: %s"
                                            % ", ".join('"%s"' % c for c in gitlab_crons(dates, times["GitLab"]))),
                              GL_CRED=("Keep this account's password and recovery codes with ONE printed copy of\n"
                                       "    your cancellation codes, and GitHub's with the OTHER, never both in one\n"
                                       "    place: with both sign-ins, someone could make each job reveal its secret and\n"
                                       "    open your record before the date (RUNBOOK 10A-h). Either account is enough to\n"
                                       "    log a notice: each job reads the other's copy of the log." if peer else
                                       "Keep this account's password and recovery codes with your cancellation\n"
                                       "    codes too: without them you could not log a cancellation there."),
                              GL_REPO=privs["GitLab"], GL_CMDS="\n".join(gl_cmds), GL_LIST="\n".join(gl_list),
                              GL_PUB="\n".join(gl_pub)) if gitlab else "",
            OPENING_STEP=(OPENING_STEP_REHEARSAL if rehearsal else fill(
                OPENING_STEP_REAL, OPENING=os.path.abspath(opening_dir or "."), CASE=case, CASE_LOWER=case.lower(),
                FIRST_TARGET=targets[0]["repo"],
                MORE_TARGETS="".join(["\n   Create each other opening repository the same way, public and empty (an ordinary\n"
                                      "   repository: do not turn on the host's mirroring feature), and push the same\n"
                                      "   folder to it:"] + ["\n     git push %s main" % t["repo"] for t in targets[1:]])
                if len(targets) > 1 else "")),
            CHECKIN_NOTE=("\n   You will also get one red run a year, on purpose: the yearly check-in, at the run of\n"
                          "   %s%s. If a year passes without it, the runs have stopped (RUNBOOK 10A-g)."
                          % (date_words(dates[:1]), " (sent from GitLab, which runs first)" if gitlab else "")
                          if check_in else ""),
            **{k: common[k] for k in ("CASE", "CASE_LOWER", "REHEARSAL_TAG")}), 0o600)
    finally:
        os.umask(old)
    return cfg, [b for h in halves.values() for b in h[:2]]


def leak_scan(out, record, keys, secrets_dir, opening_dir=None):
    """Nothing in the repository folders may hold the answer as the record writes it, any
    part of the nonce, the record's size, a key, or a deploy key. The reference and the short
    form are public copies, and the answer may be an ordinary word (Paris, March): searched as
    the record's own line A=..., it cannot be confused with the templates."""
    text = record.decode("utf-8", "replace")
    a = re.search(r"^A=(.*)$", text, re.M)
    n = re.search(r"^N=([0-9a-f]+)$", text, re.M)
    needles = [x for k in keys for x in (k.hex(), k.hex()[:32])]
    if a:
        needles.append("A=" + a.group(1))
    if n:
        needles += [n.group(1)[i:i + 24] for i in range(0, len(n.group(1)) - 23, 8)]
    for root, _, names in os.walk(secrets_dir):
        for name in names:
            if name.startswith(("SC2_DEPLOY_KEY", "SC2_READ_KEY")) and not name.endswith(".pub.txt"):
                body = "".join(open(os.path.join(root, name)).read().splitlines()[1:-1])
                needles += [body[i:i + 32] for i in range(0, max(1, len(body) - 31), 32)]
    found = []
    tools = os.path.join(out, "sc2", "tools")
    for root, _, files in [w for d in (out, opening_dir) if d for w in os.walk(d)]:
        for f in files:
            p = os.path.join(root, f)
            if root == tools:                      # the public toolkit, byte for byte: never searched
                if open(p, "rb").read() != open(os.path.join(HERE, f), "rb").read():
                    found.append("sc2/tools/%s differs from the toolkit's" % f)
                continue
            if (f.startswith("sealed") and f.endswith(".bin")) or f in ("commitment-reference.txt", "commitment-title.txt"):
                continue                           # ciphertext; public copies
            data = open(p, "rb").read().decode("utf-8", "replace")
            hits = [x for x in needles if x and x in data]
            if f in ("README.md", "log.txt", "sc2-autorelease.yml") and re.search(r"\b%d\b" % len(record), data):
                hits.append("the record's size")      # config.json holds only fields listed in build()
            if hits:
                found.append("%s (%d)" % (p, len(hits)))
    return found


def make_targets(repos, branch):
    targets = []
    for i, r in enumerate(repos):
        if not (is_local(r) or web_of(r)):
            raise SystemExit("--opening-repo %s: give the SSH address (git@host:owner/repo.git); a "
                             "deploy key works over SSH only" % r)
        targets.append(dict(repo=r, web=None if is_local(r) else web_of(r), branch=branch,
                            secret="SC2_DEPLOY_KEY" + ("" if i == 0 else "_%d" % (i + 1))))
    if not targets or len(targets) > 3:
        raise SystemExit("give one to three --opening-repo")
    return targets


def make_private_repos(a, targets):
    """The two private repositories, for --gitlab: each job reads the other's copy of the log."""
    if not a.gitlab:
        if a.gitlab_repo or a.private_repo:
            raise SystemExit("--private-repo and --gitlab-repo go with --gitlab")
        return None
    if not (a.private_repo and a.gitlab_repo):
        raise SystemExit("with --gitlab, give --private-repo (the GitHub private repository's SSH address) and "
                         "--gitlab-repo (the GitLab project's): each job reads the other's copy of the log, so "
                         "that a notice that reached one copy only cannot let the other publish")
    for r in (a.private_repo, a.gitlab_repo):
        if not (is_local(r) or web_of(r)):
            raise SystemExit("%s: give the SSH address (git@host:owner/repo.git)" % r)
        if repo_key(r) in [repo_key(t["repo"]) for t in targets]:
            raise SystemExit("REFUSING: %s is also an opening repository: the private repositories must "
                             "never be the ones the job publishes to" % r)
    if repo_key(a.private_repo) == repo_key(a.gitlab_repo):
        raise SystemExit("--private-repo and --gitlab-repo must be two different repositories")
    return {"GitHub": a.private_repo, "GitLab": a.gitlab_repo}


def cmd_make(a):
    rel = sibling("sc2_release", "sc2-release.py")
    try:
        today = dt.date.fromisoformat(a.today) if a.today else local_today(a.timezone)
    except Exception as e:
        raise SystemExit("time zone %s: %s (Python 3.9+ with time zone data is needed)" % (a.timezone, e))
    targets = make_targets(a.opening_repo, a.branch)
    privs = make_private_repos(a, targets)
    check_dirs(a.out, a.secrets, a.opening)
    case, _ = rel.verify_kit_inputs(a.preimage, a.reference, a.short)
    letter = read_letter(a.letter)
    if letter["case"] != case:
        raise SystemExit("REFUSING: the letter is for SC2/%s, the record is SC2/%s" % (letter["case"], case))
    release = dt.date.fromisoformat(letter["release"])
    if release <= today:
        raise SystemExit("REFUSING: the release date %s is not in the future" % release)
    if (release.month, release.day) == (2, 29):
        raise SystemExit("REFUSING: a release date of 29 February would show itself in the public heartbeats: "
                         "February would have two runs in leap years (RUNBOOK 10A-g). Choose another day with your "
                         "custodian, which means a new custodian's kit (Step 10).")
    if (release - today).days <= 93:
        say("note: the release date is only %d days away" % (release - today).days)
    nonce = sibling("sc2_nonce", "sc2-nonce.py")
    phys = open(a.entropy, "rb").read() if os.path.isfile(a.entropy) else b""
    kind, bits, notes, ok = nonce.assess(phys, KEY_BITS)
    if not ok:
        for n in notes:
            say("    " + n)
        raise SystemExit("REFUSING: %s does not give %d bits of assessed physical entropy. Roll 350 "
                         "FRESH dice; never reuse the commitment's or the codes'." % (a.entropy, KEY_BITS))
    record = open(a.preimage, "rb").read()
    lock = local_midnight(release, a.timezone)
    say("SC2/%s: automatic release on %s (from 00:00 %s), %d target(s)" % (case, release, a.timezone, len(targets)))
    cfg, keys = build(rel, record, a.reference, a.short, letter, targets, a.timezone, a.out, a.secrets,
                        a.opening, bits, os.urandom(64) + secrets.token_bytes(64) + b"|" + phys, lock, False,
                        today, a.canary_rounds, not a.no_check_in, a.gitlab, not a.no_peer_key, privs)
    finish_make(a.out, a.secrets, a.opening, record, keys, cfg, bits)
    say("Now delete %s: while it exists it is as sensitive as the key." % a.entropy)


def finish_make(out, secrets_dir, opening_dir, record, keys, cfg, bits):
    leaks = leak_scan(out, record, keys, secrets_dir, opening_dir)
    if leaks:
        for d in (out, opening_dir, secrets_dir):
            if d:
                shutil.rmtree(d, ignore_errors=True)
        raise SystemExit("REFUSING: a repository folder would hold secret material: %s. Removed all three "
                         "folders, the secrets folder included." % ", ".join(leaks))
    say("  ok   the repository folders hold no answer, nonce fragment, size, key or deploy key")
    say("wrote %s/ (the private repository's files), %s%s/ (SECRETS: SC2_KEY, deploy key(s), SETUP.txt)"
        % (out, ("%s/ (the public opening repository's first files) and " % opening_dir) if opening_dir else "",
           secrets_dir))
    say("K_s: %.0f bits of assessed physical entropy (%d required)" % (bits, KEY_BITS) if bits else
        "K_s: OS generator only (rehearsal)")
    say("Next: follow %s/SETUP.txt, step by step." % secrets_dir)


# ------------------------------------------------------------------------- rehearse
def cmd_rehearse(a):
    rel = sibling("sc2_release", "sc2-release.py")
    targets = make_targets(a.opening_repo, a.branch)
    privs = make_private_repos(a, targets)
    check_dirs(a.out, a.secrets)
    if a.days < 1:
        raise SystemExit("--days must be 1 or more: the first day exercises the health checks")
    today = local_today(a.timezone)
    due = today + dt.timedelta(days=a.days)
    w = tempfile.mkdtemp(prefix="sc2-rehearsal-")
    rnd = secrets.SystemRandom()
    for name, text in (("q.txt", "REHEARSAL: which colour is the rehearsal sky, as declared by nobody?"),
                       ("a.txt", "REHEARSAL GREEN"), ("t.txt", "REHEARSAL anchor only, %s" % today),
                       ("note.txt", "REHEARSAL record, synthetic: it proves nothing")):
        write(os.path.join(w, name), text, 0o600)
    for attempt in range(3):
        write(os.path.join(w, "dice%d.txt" % attempt), "".join(rnd.choice("123456") for _ in range(1600)), 0o600)
        r = subprocess.run(["sh", os.path.join(HERE, "sc2-make.sh"), "q.txt", "a.txt", "t.txt",
                            "commitment.txt", "dice%d.txt" % attempt, "note.txt"], cwd=w, capture_output=True)
        if r.returncode == 0:
            break
    else:
        raise SystemExit("could not build the synthetic record: %s" % r.stderr.decode(errors="replace")[-400:])
    pre = os.path.join(w, "commitment.txt")
    case, _ = rel.verify_kit_inputs(pre, os.path.join(w, "commitment-reference.txt"),
                                    os.path.join(w, "commitment-title.txt"))
    H = lambda s: hashlib.sha512(s.encode()).hexdigest()
    letter = dict(case=case, start=H(secrets.token_hex(64)), certain=H(secrets.token_hex(64)),
                  release=due.isoformat(), window=[30, 31], sealed=today.isoformat())
    lock = local_midnight(due, a.timezone)
    say("REHEARSAL SC2/%s: synthetic record, due %s, time-locked until 00:00 that day (%s)" % (case, due, a.timezone))
    cfg, keys = build(rel, open(pre, "rb").read(), os.path.join(w, "commitment-reference.txt"),
                        os.path.join(w, "commitment-title.txt"), letter, targets, a.timezone, a.out,
                        a.secrets, None, 0, os.urandom(128), lock, True, today, a.canary_rounds, False, a.gitlab,
                        not a.no_peer_key, privs)
    finish_make(a.out, a.secrets, None, open(pre, "rb").read(), keys, cfg, 0)
    shutil.rmtree(w)
    say("Rehearsal: set it up as %s/SETUP.txt says. Today a run by hand must be green, and red with a"
        % a.secrets)
    say("'test' line in the log; on %s the SCHEDULED run must publish the synthetic record by itself." % due)


# ----------------------------------------------------------------------------- run
def read_log(path, today, rel, earliest=None):
    try:
        data = open(path, "rb").read()
    except OSError as e:
        return [], [], ["sc2/log.txt cannot be read (%s)" % e]
    return read_log_bytes(data, today, rel, earliest)


def read_log_bytes(data, today, rel, earliest=None):
    """The custodian's own parser (sc2-release.py parse_log), and what the job may not ignore.
    Returns (entries, warnings, blockers). A blocker is anything that might be a notice and
    cannot be evaluated: a line with a digit in it that is not 'YYYY-MM-DD CODE', a date that
    does not exist, a date after today or before the record was sealed (`earliest`: a mistyped
    year), a code inside a comment (a notice joined to the line above it), text that is not
    plain (a change of encoding garbles a notice), an unreadable file. While one stands, the job
    never publishes: a publication cannot be undone, and the custodian still covers the release.
    A plain line with no digit (such as the drill's "test") can be no notice: a warning."""
    blockers, warnings, kept = [], [], []
    utf16 = data[:2] in (b"\xff\xfe", b"\xfe\xff")
    if b"\x00" in data and not utf16:
        blockers.append("sc2/log.txt mixes text encodings (NUL bytes without a UTF-16 mark, as when Windows "
                        "PowerShell's >> appends to it), so a notice in it may be unreadable: save it again as "
                        "plain text (UTF-8), one notice per line")
    for n, raw in enumerate(rel.log_lines(data), 1):
        comment = raw.partition("#")[2]
        hexrun = re.search(r"[0-9a-fA-F]{32,}", comment)
        if hexrun:
            blockers.append("log line %d: a comment holds what looks like a code (%s...), as when a notice is "
                            "joined to a line with no line end: put each notice on a line of its own"
                            % (n, hexrun.group(0)[:16]))
        if any(ch == "\ufffd" or (ord(ch) < 32 and ch != "\t") or (utf16 and ord(ch) > 126) for ch in raw):
            blockers.append("log line %d holds characters that are not plain text%s, as a notice garbled by a "
                            "change of encoding does: save the log as plain text (UTF-8), one notice per line"
                            % (n, " (in a UTF-16 file)" if utf16 else ""))
    entries, problems = rel.parse_log(data)
    for _, m, notice in problems:
        if notice:
            blockers.append(m)
        else:
            warnings.append(m + " (no digit in it, so no notice): ignored")
    for d, code, n in entries:
        if d > today:
            blockers.append("log line %d: dated %s, after today (%s)" % (n, d, today))
        elif earliest and d < earliest:
            blockers.append("log line %d: dated %s, before the record was even sealed (%s): a mistyped year"
                            % (n, d, earliest))
        else:
            kept.append((d, code, n))
    return kept, warnings, blockers


def date_conflicts(logs, rel, names):
    """A code under more than one date, in one copy or across copies: which date counts is a
    guess (the custodian's rule would take the first), so it blocks. `logs` are entry lists."""
    when = {}
    for name, log_ in zip(names, logs):
        for d, c, _ in log_:
            if rel.norm(c):
                when.setdefault(rel.norm(c), {}).setdefault(name, set()).add(d)
    out = []
    for code, by in sorted(when.items()):
        if len(set().union(*by.values())) > 1:
            out.append("the code %s... is logged under more than one date (%s): keep only the line with the date "
                       "your custodian gave" % (code[:16], "; ".join("%s: %s" % (k, ", ".join(sorted(map(str, v))))
                                                                      for k, v in sorted(by.items()))))
    return out


def run_at(cfg, plat):
    t = (cfg.get("run_at") or {}).get(plat)
    if t:
        return tuple(int(x) for x in t.split(":"))
    return (17, 17) if plat == "GitHub" else (21, 17)          # a kit made before run_at was recorded


def scheduled(cfg, frm, to):
    """The scheduled run dates d with frm <= d <= to, from the yearly days in config.json."""
    days = [(d.month, d.day) for d in (dt.date.fromisoformat(x) for x in cfg.get("runs") or [])]
    out = set()
    for y in range(frm.year, to.year + 1):
        for m, dd in days:
            try:
                c = dt.date(y, m, dd)
            except ValueError:                                  # 29 February outside a leap year
                continue
            if frm <= c <= to:
                out.add(c)
    return sorted(out)


def latest_run(cfg, today):
    """The latest scheduled run date since the kit was made, on or before today; None before the first."""
    made = dt.date.fromisoformat(cfg["made"])
    c = scheduled(cfg, made + dt.timedelta(days=1), today)
    return c[-1] if c else None


def last_expected(cfg, plat, me, today, manual=False):
    """The day of plat's latest scheduled run that should have happened by this run of today (a
    platform that runs later in the day has not run yet today, and a run by hand may come before
    any); None before its first one."""
    made = dt.date.fromisoformat(cfg["made"])
    c = scheduled(cfg, made + dt.timedelta(days=1), today)
    if c and c[-1] == today and (manual or run_at(cfg, plat) >= run_at(cfg, me)):
        c = c[:-1]
    return c[-1] if c else None


def beat_due(cfg, hb, me, today):
    """Whether this platform owes a heartbeat: it has none from the latest run date on. A run
    delayed past midnight still counts for its date; a second run the same day owes none."""
    mine, last = (hb or {}).get(me), latest_run(cfg, today)
    return hb is None or mine is None or (last is not None and mine < last)


def cycle_start(cfg, today):
    """The latest day, on or before today, of the yearly check-in's run date (a month before the
    release date): the yearly check-in comes with the first heartbeat from that day on."""
    first = dt.date.fromisoformat((cfg.get("runs") or [cfg["release"]])[0])
    for y in (today.year, today.year - 1):
        c = on_day(y, first)
        if c and c <= today:
            return c
    return None


def checkin_due(cfg, hb, today):
    """No platform has left a heartbeat since this year's cycle began: whichever platform speaks
    first in the cycle sends the check-in, and the other does not repeat it."""
    latest, start = max((hb or {}).values(), default=None), cycle_start(cfg, today)
    return latest is None or (start is not None and latest < start)


def speaks(cfg, hb, missed):
    """Whether this run sends the reminders and the check-in: the platform that runs first on a run
    day does; another one does if the first missed its latest run, or if this run cannot read the
    heartbeats to tell (a duplicate reminder is the safe side)."""
    first = sorted(cfg.get("platforms") or ["GitHub"], key=lambda p: run_at(cfg, p))[0]
    return platform_name() == first or first in missed or hb is None


def wait_until(cfg, due):
    """The scheduled run at which a due release stops waiting for an unreadable copy of the other
    log: the first one at least 25 days after the first scheduled run from the due day on (a
    29 February release date puts two run dates in February, the 28th and the 29th).
    So the first scheduled run since the release became due waits about a month, and a run by
    hand or a run delayed past midnight in between waits too. None (no wait) if that run is more
    than WAIT_NEXT days after the first (it never is, with a run every month: the cap guards a
    config.json edited by hand)."""
    s = scheduled(cfg, due, due + dt.timedelta(days=800))
    later = [d for d in s[1:] if (d - s[0]).days >= 25]
    if not later or (later[0] - s[0]).days > WAIT_NEXT:
        return None
    return later[0]


def my_copy(cfg):
    """(platform, its copy). Each platform opens only its own copy, with its own secret."""
    copies = cfg.get("copies") or {"GitHub": dict(sealed="sealed.bin", timelock="key-timelock.age",
                                                  key_check=cfg["key_check"], secret="SC2_KEY")}
    me = platform_name()
    name = me if me in copies else next(iter(copies))
    return name, copies[name]


def other_log(cfg, tmp):
    """(other platform, its copy of sc2/log.txt as bytes -- or a message saying why it could
    not be read), read with this platform's read-only key; (None, None) with one platform.
    A notice pushed to one copy and not the other must not let that other publish."""
    privs = cfg.get("private_repos") or {}
    me = my_copy(cfg)[0]
    others = [p for p in privs if p != me]
    if not others:
        return None, None
    other, url = others[0], privs[others[0]]
    key = None
    if not is_local(url):
        v = secret_value("SC2_READ_KEY").replace("\r\n", "\n").replace("\r", "\n").strip()
        if not v:
            return other, "the secret SC2_READ_KEY (to read %s's copy of the log) is not set" % other
        key = os.path.join(tmp, "read-key")
        write(key, v + "\n", 0o600)
    d = tempfile.mkdtemp(prefix="other-log-", dir=tmp)
    git_init(d)
    rc, err = fetch(url, "refs/heads/main", d, ssh_for(key, tmp), depth=1)
    if rc:
        return other, "cannot read %s's copy of the log (%s)" % (other, err[:200])
    rc, data, _ = git(["show", "FETCH_HEAD:sc2/log.txt"], cwd=d)
    return (other, data) if rc == 0 else (other, "%s's copy has no sc2/log.txt" % other)


def env_key(cfg, problems):
    name, copy = my_copy(cfg)
    v = "".join(secret_value(copy["secret"]).split()).lower()
    if not v:
        problems.append("the secret SC2_KEY is not set (GitHub: Settings > Secrets and variables > Actions; "
                        "GitLab: Settings > CI/CD > Variables)")
    elif not re.fullmatch(r"[0-9a-f]{128}", v):
        problems.append("the secret SC2_KEY is not 128 hexadecimal characters")
    elif key_check(bytes.fromhex(v)) != copy["key_check"]:
        problems.append("the secret SC2_KEY is not this kit's key for %s's copy" % name)
    else:
        return bytes.fromhex(v)
    return None


def half_ok(v, peer):
    return bool(re.fullmatch(r"[0-9a-f]{128}", v)) and hashlib.sha3_512(
        b"SC2-AUTO-PEER-CHECK|" + bytes.fromhex(v)).hexdigest() == peer["check"]


def peer_half(cfg, problems):
    """The half of another platform's key that this platform releases on the date, if it is
    the one holding it: checked against config.json, or None."""
    peer = cfg.get("peer")
    if not peer or peer["holder"] != my_copy(cfg)[0]:
        return None
    v = "".join(secret_value(peer["secret"]).split()).lower()
    if not half_ok(v, peer):
        problems.append("the secret %s (the half of %s's key that this platform releases on the date) is "
                        "missing or wrong" % (peer["secret"], peer["copy"]))
        return None
    return v


def matches(path, ref, title, rel):
    try:
        rel.verify_kit_inputs(path, ref, title)
        return True
    except SystemExit:
        return False


def health(cfg, base, problems, offline, rel, today, sound=True):
    """Returns (whether this run left the platform's heartbeat, the heartbeats seen before it,
    the platforms that missed their latest run). Only a run with no health problem at all -- an intact kit (sound), the secrets, tle, drand, the
    test lock, every target -- leaves a heartbeat, so that a broken job never looks alive."""
    ok = lambda s: say("    ok   " + s)
    n0 = len(problems)                                   # this run's own health problems start here
    if env_key(cfg, problems):
        ok("secret SC2_KEY present, and it is this kit's key for %s's copy" % my_copy(cfg)[0])
    ways, notes = tle_ways(os.path.join(base, "tools"))
    for n in notes:
        say("    note " + n)
    if not ways:
        problems.append("no tle to run: the pinned build for this machine is missing or altered")
    d = cfg["drand"]
    if not offline:
        latest, relay, tried = drand_latest(d["relays"], d["chain"])
        if latest is None:
            problems.append("drand: no relay answered (%s)" % "; ".join(tried))
        elif abs(latest - current_round()) > 40:
            problems.append("drand: latest round %d (%s UTC), expected about %d -- has the network stopped?"
                            % (latest, iso(round_time(latest)), current_round()))
        else:
            ok("drand: round %d via %s, current" % (latest, relay))
    if ways:
        out, tried = timelock_decrypt(ways, d["relays"], d["chain"], open(os.path.join(base, "canary-timelock.age"), "rb").read())
        if out is None:
            problems.append("time-lock: the test lock (round %d) did not open: %s" % (cfg["canary"]["round"], " | ".join(tried[-3:])))
        elif hashlib.sha512(out).hexdigest() != cfg["canary"]["sha512"]:
            problems.append("time-lock: the test lock opened to the wrong value")
        else:
            ok("time-lock: the test lock (round %d) opens with %s, and matches" % (cfg["canary"]["round"], ways[0][0]))
    tmp = tempfile.mkdtemp(prefix="sc2-")
    me, manual, hb, beat, missed = platform_name(), manual_run(), None, False, set()
    if peer_half(cfg, problems):
        ok("secret %s present: the half of %s's key that this platform releases on the date"
           % (cfg["peer"]["secret"], cfg["peer"]["copy"]))
    try:
        keys = deploy_keys(cfg, tmp)
        checked = []
        for t, key in zip(cfg["targets"], keys):
            if not key and not is_local(t["repo"]):
                problems.append("the secret %s (deploy key for %s) is not set" % (t["secret"], t["repo"]))
                continue
            good, err = probe_write(t, key, tmp)
            if not good:
                time.sleep(10)
                good, err = probe_write(t, key, tmp)
            if not good:
                problems.append("no write access to %s with %s: %s" % (t["repo"], t["secret"], err))
                continue
            ok("write access to %s (dry run, nothing written)" % t["repo"])
            bad = check_target(t, key, tmp, cfg, base, rel)
            if bad:
                problems.append("%s: %s" % (t["repo"], bad))
                continue
            ok("%s: branch %s is there%s, nothing in the way%s" % (
                t["repo"], t["branch"], "" if cfg.get("rehearsal") else ", with this record's reference",
                ", readable anonymously" if t.get("web") and not cfg.get("rehearsal") else ""))
            checked.append((t, key))
            got = heartbeats(t, key, tmp, cfg, today)    # merged over every target
            if got is not None:
                hb = hb or {}
                for plat, day in got.items():
                    hb[plat] = max(day, hb.get(plat, dt.date.min))
        if checked and hb is None:
            problems.append("the heartbeats in the opening repositories (their history) could not be read: this "
                            "run leaves none of its own, sends no check-in and cannot watch the other job; the "
                            "next run tries again")
        # Once per run date and platform -- on a scheduled run that finds no heartbeat of its own
        # from the latest run date on -- a real push to each target, which is this platform's
        # heartbeat; only a run with no health problem leaves one, so a broken job does not look
        # alive. A run by hand also pushes, to test write access, but its commit does not count.
        beat = beat_due(cfg, hb, me, today) and not manual and sound and len(problems) == n0
        if beat or manual:
            for t, key in checked:
                good, err = write_test(t, key, tmp, cfg, today, manual)
                if good:
                    ok("%s: a real push went through (an empty commit%s)"
                       % (t["repo"], ", by hand" if manual else ": the heartbeat of %s" % job_tag(cfg)))
                else:
                    problems.append("%s: a real push did not go through (%s): check the deploy key's write "
                                    "access and the branch protection" % (t["repo"], err))
        # The jobs on other platforms leave heartbeats too, at their scheduled runs: one missing from
        # the latest run that should have happened means a dropped run or a stopped job.
        for other in cfg.get("platforms", []):
            exp = None if other == me or hb is None else last_expected(cfg, other, me, today, manual)
            if exp is None:
                continue
            last = hb.get(other)
            if last is None or last < exp:
                missed.add(other)
                problems.append("the job on %s left no heartbeat at its scheduled run of %s (its last: %s): that "
                                "run may have been dropped, or the job may have stopped. Look at its Actions or "
                                "pipelines page; while it is down, only the other paths remain."
                                % (other, exp, last or "none since it was set up"))
            else:
                ok("the job on %s is alive: its last heartbeat is from %s" % (other, last))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return beat, hb, missed


def target_states(cfg, base, rel, tmp, problems):
    """Each target as (clone, ssh, "absent" or "done"), or None where it cannot be used."""
    ref, title = os.path.join(base, "commitment-reference.txt"), os.path.join(base, "commitment-title.txt")
    keys = deploy_keys(cfg, tmp)
    state = []
    for t, key in zip(cfg["targets"], keys):
        if not key and not is_local(t["repo"]):
            problems.append("cannot publish to %s: the secret %s is not set" % (t["repo"], t["secret"]))
            state.append(None)
            continue
        dirp, ssh, err = clone(t, key, tmp)
        if not dirp:
            problems.append("cannot publish to %s: clone failed: %s" % (t["repo"], err))
            state.append(None)
            continue
        p = os.path.join(dirp, "opening", "commitment.txt")
        if not os.path.exists(p):
            state.append((dirp, ssh, "absent"))
        elif matches(p, ref, title, rel):
            say("    ok   %s already holds the record (opening/commitment.txt matches the reference)" % t["repo"])
            state.append((dirp, ssh, "done"))
        else:
            problems.append("%s: opening/commitment.txt exists and is NOT this record -- left alone" % t["repo"])
            state.append(None)
    return state


def released_everywhere(cfg, base, rel):
    tmp = tempfile.mkdtemp(prefix="sc2-")
    try:
        st = target_states(cfg, base, rel, tmp, [])
        return bool(st) and all(x and x[2] == "done" for x in st)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def release(cfg, base, rel, today, problems, offline):
    ref, title = os.path.join(base, "commitment-reference.txt"), os.path.join(base, "commitment-title.txt")
    d = cfg["drand"]
    tmp = tempfile.mkdtemp(prefix="sc2-")
    try:
        state = target_states(cfg, base, rel, tmp, problems)
        todo = [i for i, s in enumerate(state) if s and s[2] == "absent"]
        if not todo:
            if all(s and s[2] == "done" for s in state):
                say("    Released already. Nothing left to do; you may delete this repository.")
            return
        name, copy = my_copy(cfg)
        peer = cfg.get("peer")
        half = peer_half(cfg, problems)
        if half:                                   # released first: it must not wait on drand
            for i in todo:
                good, msg = release_half(state[i][0], state[i][1], cfg["targets"][i], half, peer, cfg["case"], today)
                if good:
                    say("    ok   %s: %s" % (cfg["targets"][i]["repo"], msg))
                else:
                    problems.append("%s: could not release %s's key half: %s" % (cfg["targets"][i]["repo"], peer["copy"], msg))
        ks = env_key(cfg, problems)
        if not ks:
            return
        ways, notes = tle_ways(os.path.join(base, "tools"))
        for n in notes:
            say("    note " + n)
        out, tried = timelock_decrypt(ways, d["relays"], d["chain"], open(os.path.join(base, copy["timelock"]), "rb").read())
        kth = out.decode("ascii", "replace").strip() if out is not None else None
        if kth is not None and not re.fullmatch(r"[0-9a-f]{128}", kth):
            problems.append("the time-lock opened to something that is not a key half")
            return
        via = None
        if kth is None and peer and peer["copy"] == name:
            kth = fetch_half(cfg, state, peer)
            if kth:
                via = peer["holder"]
                say("    ok   drand did not open the lock; %s's released half did" % peer["holder"])
        if kth is None:
            problems.append("the time-lock did not open (round %d, %s UTC): %s%s"
                            % (d["round"], iso(round_time(d["round"])), " | ".join(tried[-3:]) or "no tle",
                               "; and %s has not released its half yet" % peer["holder"]
                               if peer and peer["copy"] == name else ""))
            return
        record = unseal(open(os.path.join(base, copy["sealed"]), "rb").read(), ks, bytes.fromhex(kth))
        if record is None:
            problems.append("REFUSING: the copy does not decrypt (a key or the copy is damaged)")
            return
        rp = os.path.join(tmp, "commitment.txt")
        write(rp, record, 0o600)
        if not matches(rp, ref, title, rel):
            problems.append("REFUSING to publish: the decrypted copy does not match the reference")
            return
        say("    ok   opened the copy; it matches all four digests and the short form")
        note = release_note(cfg, today, rel, via)
        published = []
        for i in todo:                                  # every target first, archives after
            t = cfg["targets"][i]
            good, msg = push_record(state[i][0], state[i][1], t, record, note, cfg["case"], today,
                                    bool(cfg.get("rehearsal")), name)
            if good:
                say("    ok   %s: %s" % (t["repo"], msg))
                published.append(t)
            else:
                problems.append("%s: %s" % (t["repo"], msg))
        if not offline and not cfg.get("rehearsal"):    # never ask an archive to keep a rehearsal
            for t in published:
                if time_left() < 300:
                    say("    note no time left to ask the archives: save %s by hand" % (t.get("web") or t["repo"]))
                    continue
                for line in archive(t):
                    say("         " + line)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def cmd_run(a):
    DEADLINE[0] = time.time() + BUDGET
    rel = sibling("sc2_release", "sc2-release.py")
    kit = os.path.abspath(a.kit)
    base = os.path.join(kit, "sc2")
    cfg = json.load(open(os.path.join(base, "config.json"), encoding="utf-8"))
    if cfg.get("format") != FORMAT:
        raise SystemExit("%s/config.json is not an %s kit" % (base, FORMAT))
    cfg["_title"] = os.path.join(base, "commitment-title.txt")
    problems = []
    tz = cfg["timezone"]
    try:
        today = dt.date.fromisoformat(a.today) if a.today else local_today(tz, cfg.get("tz_offsets"))
    except Exception as e:
        today = dt.datetime.now(dt.timezone.utc).date()
        problems.append("time zone %s unavailable (%s): this run used the UTC date" % (tz, e))
    R = dt.date.fromisoformat(cfg["release"])
    lo, hi = cfg["window"]
    say("SC2/%s automatic release%s -- run of %s (%s), %s UTC" % (
        cfg["case"], " -- REHEARSAL, SYNTHETIC DATA" if cfg.get("rehearsal") else "", today, tz, iso(time.time())))
    say("  release date %s; time-lock opens at round %d (%s UTC)" % (R, cfg["drand"]["round"], iso(round_time(cfg["drand"]["round"]))))
    for name, want in cfg["files"].items():
        p = os.path.join(base, name)
        if not os.path.isfile(p) or sha512_file(p) != want:
            problems.append("sc2/%s is missing or has changed since the kit was made" % name)
    for c in (cfg.get("copies") or {"GitHub": {"timelock": "key-timelock.age"}}).values():
        if armor_header(open(os.path.join(base, c["timelock"]), "rb").read()) != (cfg["drand"]["round"], cfg["drand"]["chain"]):
            problems.append("sc2/%s is not a time-lock to round %d" % (c["timelock"], cfg["drand"]["round"]))
    sound = not any(p.startswith("sc2/") for p in problems)

    sealed = dt.date.fromisoformat(cfg["sealed"])
    entries, warnings, blockers = read_log(os.path.join(base, "log.txt"), today, rel, sealed)
    problems += warnings
    tmp = tempfile.mkdtemp(prefix="sc2-")
    try:
        other, odata = other_log(cfg, tmp)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    unread, alone, only_other = None, [], set()
    if other is not None and not isinstance(odata, bytes):
        unread = odata
        problems.append(odata)
    elif other is not None:
        own = entries
        oe, _, ob = read_log_bytes(odata, today, rel, sealed)
        same = lambda e: (e[0], rel.norm(e[1]) or " ".join(e[1].split()))
        mine, theirs = {same(e) for e in entries}, {same(e) for e in oe}
        if mine != theirs:
            problems.append("the two copies of the log differ: %d notice line(s) only here, %d only on %s. Log "
                            "notices with sc2-autorelease.py notice, which pushes to both and checks. Until the "
                            "copies agree, this job counts the notices of both, and will not publish if they "
                            "disagree on a code's date or on a cancellation."
                            % (len(mine - theirs), len(theirs - mine), other))
            extra = [(d, c, k + 100000) for d, c, k in oe if same((d, c, k)) not in mine]
            only_other = {(d.isoformat(), "".join(c.split())[:16]) for d, c, _ in extra}
            entries = sorted(entries + extra, key=lambda e: (e[0], e[2]))
        # Each copy alone: if one shows a completed cancellation and the two together do not
        # (a code dated differently, a missing line), the job does not publish on a guess.
        alone = [(name, rel.check(cfg["start"], cfg["certain"], R, lo, hi, log_, today)[1])
                 for name, log_ in (("this copy", own), ("%s's copy" % other, oe))]
        blockers += ["%s's copy of the log: %s" % (other, b) for b in ob]
        blockers += date_conflicts([own, oe], rel, ["this copy", "%s's copy" % other])
        if mine == theirs and not ob:
            say("  ok   %s's copy of the log is readable, and the same as this one" % other)
    if other is None or unread:
        blockers += date_conflicts([entries], rel, ["this copy"])
    rep, outcome, day = rel.check(cfg["start"], cfg["certain"], R, lo, hi, entries, today)
    say("  the log and the rule (sc2-release.py check):")
    for line in rep:
        say("    " + line)
    for line in rep:
        if re.search(r"\b(INVALID|not a code)\b", line):
            blockers.append("log: the line of %s is not a valid notice (a mistyped code, or one your custodian "
                            "did not accept)%s" % (" ".join(line.split()[:2]), " -- it is only in %s's copy" % other
                                                   if tuple(line.split()[:2]) in only_other else ""))
    blockers += ["%s alone shows a completed cancellation, and the two copies together do not: which is "
                 "right? Make both copies hold exactly the notices your custodian reported" % name
                 for name, out in alone if out == "cancel" and outcome != "cancel"]
    for b in blockers:
        problems.append(b + ". While this stands, the job will not publish: correct or remove the line.")
    T = today.toordinal()
    if outcome == "cancel" and len(cfg.get("platforms") or []) > 1:
        problems.append("CANCELLED: this job (on %s) will never open its copy. First make sure that both copies "
                        "of the log hold every notice (notice ends 'every copy has it'): a job that can no longer "
                        "read the other copy goes by its own. Then, the same day, delete BOTH private "
                        "repositories, GitHub's and GitLab's (GitLab: Delete, then Delete permanently), and "
                        "remove both jobs' deploy keys from the opening repositories: until you do, each "
                        "platform keeps a copy that opens on %s (RUNBOOK 10A-f)." % (my_copy(cfg)[0], R))
    elif outcome == "cancel":
        problems.append("CANCELLED: this job will never open its copy. Now delete this private repository, and "
                        "remove its deploy key(s) from the opening repositories: until you do, GitHub keeps a "
                        "copy that opens on %s (RUNBOOK 10A-f)." % R)
    elif day <= T and blockers:
        problems.append("RELEASE DUE, NOT PUBLISHED: the log holds something this job cannot settle (above). It "
                        "could belong to a cancellation, and a publication cannot be undone. Fix it; the next run "
                        "decides again. The custodian is not affected.")
    elif day <= T and unread and wait_until(cfg, dt.date.fromordinal(day)) \
            and today < wait_until(cfg, dt.date.fromordinal(day)):
        # A release that became due waits about a month for the other copy of the log: it might
        # hold a notice this one lacks. Counted in scheduled runs, not days, so that a run by hand or
        # a run delayed past midnight waits too (wait_until). Then it goes by its own.
        if released_everywhere(cfg, base, rel):
            say("    Released already: every target holds the record. Nothing left to do here.")
        else:
            problems.append("RELEASE DUE, WAITING: %s's copy of the log cannot be read, and it might hold a "
                            "notice this one lacks. This job waits until its scheduled run of %s; if it still "
                            "cannot read it then, it publishes on its own log alone."
                            % (other, wait_until(cfg, dt.date.fromordinal(day))))
    elif day <= T:
        say("  RELEASE DUE: opening the copy and publishing")
        release(cfg, base, rel, today, problems, a.offline_test)
    else:
        say("  health (%s):" % platform_name())
        beat, hb, missed = health(cfg, base, problems, a.offline_test, rel, today, sound)
        left = day - T                                    # the effective day: a postponement counts
        # Reminders and check-ins come from the platform that runs first on a run day, or from the
        # other once the first has missed its latest run: one e-mail each, not one per platform.
        speaker = speaks(cfg, hb, missed)
        runs = [dt.date.fromisoformat(x) for x in cfg.get("runs") or []]
        upcoming = run_words(runs) if runs else "its scheduled dates"
        due = dt.date.fromordinal(day)
        publish_on = (scheduled(cfg, due, due + dt.timedelta(days=400)) or [due])[0]
        # One reminder per run date: a second run for a date this platform has covered (GitHub's
        # extra run on 29 February in the far west) does not repeat it; a run by hand shows it.
        remind = 0 < left <= max(2 * hi, 62) and speaker and not cfg.get("rehearsal") \
            and (manual_run() or beat_due(cfg, hb, platform_name(), today))
        checkin = (not remind and beat and cfg.get("check_in", cfg.get("monthly_check_in")) and speaker
                   and not cfg.get("rehearsal") and checkin_due(cfg, hb, today))
        if (remind or checkin) and released_everywhere(cfg, base, rel):
            say("    The record is already public in every opening repository (you released it yourself): "
                "nothing is left to remind you of. Delete this repository and its deploy keys when you like.")
        elif remind:
            problems.append("REMINDER, not a fault: your record is due to be released on %s, in %d day(s), "
                            "unless sc2/log.txt shows a completed cancellation; the job publishes it at its first "
                            "run from that day, on %s. Push every notice your custodian has reported valid; if "
                            "you have nothing to add, ignore this." % (due, left, publish_on))
        elif checkin:
            also = (cfg.get("also_runs") or {}).get(my_copy(cfg)[0])
            problems.append("YEARLY CHECK-IN, not a fault: the automatic release is still armed, for %s. This red "
                            "run is how %s e-mails you, once a year; if a year passes with no such e-mail, look at "
                            "its runs: they may have stopped. It runs on %s, %s."
                            % (dt.date.fromordinal(day), my_copy(cfg)[0], upcoming,
                               "and also on %s" % also if also else "and on no other day"))
    return finish(problems)


def finish(problems):
    say("")
    for p in problems:
        say("PROBLEM: " + p)
        if ON_GITHUB:
            print("::error title=SC2::" + p.replace("%", "%25").replace("\r", "").replace("\n", " "), flush=True)
    say("STATUS: %s" % ("OK" if not problems else "ACTION NEEDED (%d)" % len(problems)))
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if ON_GITHUB and summary:
        try:
            with open(summary, "a", encoding="utf-8") as f:
                f.write("```\n%s\n```\n" % "\n".join(SAID))
        except OSError:
            pass
    return 1 if problems else 0


# ------------------------------------------------------------------- probe and decrypt
def cmd_notice(a):
    """Logs one notice from your working copy. It checks the date and that the code is the next
    valid one (or already in the log), that no copy has changes this working copy lacks, adds
    and commits the line, then pushes it to EVERY push address of origin, one by one, reads each
    one back, and checks that every private repository of the kit was among them. It uses your
    own git settings and sign-in. When it refuses, it changes nothing."""
    rel = sibling("sc2_release", "sc2-release.py")
    kit = os.path.abspath(a.kit)
    if not os.path.isfile(os.path.join(kit, "sc2", "config.json")):
        raise SystemExit("%s holds no sc2/config.json: run this from your working copy of the private "
                         "repository (autorelease-repo), or give --kit" % kit)
    cfg = json.load(open(os.path.join(kit, "sc2", "config.json"), encoding="utf-8"))
    try:
        day = dt.date.fromisoformat(a.date)
    except ValueError:
        raise SystemExit("%s is not a date (YYYY-MM-DD): give the date your custodian counted it under" % a.date)
    today = dt.date.fromisoformat(a.today) if a.today else local_today(cfg["timezone"], cfg.get("tz_offsets"))
    sealed = dt.date.fromisoformat(cfg["sealed"])
    if day > today:
        raise SystemExit("%s is after today (%s, %s): a notice cannot count under a future date"
                         % (day, today, cfg["timezone"]))
    if day < sealed:
        raise SystemExit("%s is before the record was even sealed (%s): no notice counts under it. A "
                         "mistyped year?" % (day, sealed))
    code = rel.norm(a.code)
    if code is None:
        raise SystemExit("not a code: 128 characters 0-9 a-f (spaces and line breaks are ignored)")
    run = lambda *c: subprocess.run(["git"] + list(c), cwd=kit, capture_output=True, text=True,
                                    encoding="utf-8", errors="replace")
    branch = run("symbolic-ref", "--short", "-q", "HEAD").stdout.strip()
    if branch != "main":
        raise SystemExit("this working copy is on %s, not main: run  git switch main  first"
                         % (branch or "no branch"))
    log = os.path.join(kit, "sc2", "log.txt")
    old = open(log, "rb").read()
    if b"\x00" in old and old[:2] not in (b"\xff\xfe", b"\xfe\xff"):
        raise SystemExit("REFUSING: sc2/log.txt mixes text encodings (NUL bytes without a UTF-16 mark, as when "
                         "Windows PowerShell's >> appends to it), and the jobs cannot read it either. Save it "
                         "again as plain text (UTF-8), one notice per line, check it with sc2-release.py check, "
                         "commit it, then run this again.")
    entries, problems = rel.parse_log(old)
    dates = [d for d, c, _ in entries if rel.norm(c) == code]
    if dates and day not in dates:
        raise SystemExit("REFUSING: this code is already in the log, dated %s. If that date is wrong, correct "
                         "that line by hand, commit, and run this again." % dates[0])
    urls = [u for u in run("remote", "get-url", "--push", "--all", "origin").stdout.split() if u]
    if not urls:
        raise SystemExit("this working copy has no push address for origin (RUNBOOK 10A-d)")
    for u in urls:                                     # pushing over a change made elsewhere would fail
        got = run("ls-remote", u, "refs/heads/main")
        sha = (got.stdout.split() or [""])[0]
        if got.returncode == 0 and sha and run("merge-base", "--is-ancestor", sha, "HEAD").returncode:
            raise SystemExit("REFUSING: %s has changes this working copy lacks. Bring them in with\n"
                             "    git pull --ff-only %s main\n"
                             "look at what changed (git log -p -3), then run this again. If git says it cannot "
                             "fast-forward, the copies have diverged: run  git pull %s main , check sc2/log.txt, "
                             "commit, then run this again. Nothing was changed." % (u, u, u))
    dirty = bool(run("status", "--porcelain", "--", "sc2/log.txt").stdout.strip())
    committed = subprocess.run(["git", "show", "HEAD:sc2/log.txt"], cwd=kit, capture_output=True)
    if dirty:          # only the very line being logged may be waiting to be committed
        before = {(d, rel.norm(c)) for d, c, _ in rel.parse_log(committed.stdout)[0]} if not committed.returncode else set()
        now = {(d, rel.norm(c)) for d, c, _ in entries}
        if not dates or now - before != {(day, code)} or not before <= now:
            raise SystemExit("REFUSING: sc2/log.txt has changes that are not committed (git diff sc2/log.txt "
                             "shows them): commit or undo them, then run this again. Nothing was changed.")
    view = lambda data: (lambda kept, _w, bl: (kept, bl + date_conflicts([kept], rel, ["the log"])))(
        *read_log_bytes(data, today, rel, sealed))
    if not dates:
        trial = sorted(entries + [(day, code, 10 ** 6)], key=lambda e: (e[0], e[2]))
        status, _ = rel.accept(rel.norm(cfg["start"]), cfg["certain"] and rel.norm(cfg["certain"]), trial)
        if status.get(10 ** 6) not in ("valid", "RELEASE MADE CERTAIN"):
            raise SystemExit("REFUSING: this code is not the next valid one in your log (%s). Check that it is "
                             "the code your custodian reported valid, and its date. Nothing was changed."
                             % status.get(10 ** 6))
        body = old                                     # a UTF-16 log (PowerShell) is rewritten as UTF-8
        if old[:2] in (b"\xff\xfe", b"\xfe\xff"):
            body = "\n".join(rel.log_lines(old)).encode("utf-8")
        new = (body + (b"" if not body or body.endswith((b"\n", b"\r")) else b"\n")
               + ("%s %s\n" % (day, code)).encode())
        e2, p2 = rel.parse_log(new)                    # read back exactly as the jobs will read it
        if (day, code) not in {(d, rel.norm(c)) for d, c, _ in e2} or len(p2) != len(problems):
            raise SystemExit("REFUSING: with the line added, sc2/log.txt would not read back as it should. "
                             "Nothing was changed.")
        kept, bl = view(new)
        if bl:
            raise SystemExit("REFUSING: the jobs would not act on the log, even with this line: %s. Fix that "
                             "first (RUNBOOK 10A-e), commit, then run this again. Nothing was changed."
                             % "; ".join(bl[:3]))
        with open(log, "wb") as f:
            f.write(new)
        r = run("commit", "-q", "-m", "SC2: notice %s" % day, "--", "sc2/log.txt")
        if r.returncode:
            with open(log, "wb") as f:
                f.write(old)
            raise SystemExit("git commit failed, and the log is back as it was: %s" % (r.stderr.strip() or r.stdout.strip()))
        say("logged: %s %s..." % (day, code[:16]))
    else:
        kept, bl = view(old)
        if bl:
            raise SystemExit("REFUSING: the jobs would not act on the log: %s. Fix that first (RUNBOOK 10A-e), "
                             "commit, then run this again. Nothing was changed." % "; ".join(bl[:3]))
        say("already in the log: %s %s... -- pushing it again and checking" % (day, code[:16]))
        if dirty:
            r = run("commit", "-q", "-m", "SC2: notice %s" % day, "--", "sc2/log.txt")
            if r.returncode:
                raise SystemExit("git commit failed: %s" % (r.stderr.strip() or r.stdout.strip()))
    two = len(cfg.get("platforms") or []) > 1
    try:                                               # where this notice leaves the series
        R, (lo, hi) = dt.date.fromisoformat(cfg["release"]), cfg["window"]
        now = kept
        rep, outcome, _ = rel.check(cfg["start"], cfg["certain"], R, lo, hi, now, today)
        _, events = rel.accept(rel.norm(cfg["start"]), cfg["certain"] and rel.norm(cfg["certain"]), now)
        notes = rel.evaluate([(d, kind) for d, kind, _ in events], R.toordinal(), lo, hi)[2]
        ks = {k for d, c, k in now if d == day and rel.norm(c) == code}
        for i, (d, kind, k) in enumerate(events):
            if k in ks and notes[i][0] == 1 and i:
                say("  NOTE: this notice STARTS A NEW SERIES: it came %d days after the previous valid one, "
                    "outside %d-%d, so the earlier ones no longer count towards a cancellation. Is its date "
                    "right?" % (d - events[i - 1][0], lo, hi))
            elif k in ks and notes[i][1]:
                say("  note: " + notes[i][1])
        if outcome == "cancel":
            say("  CANCELLED: the jobs will never open their copies. Once every copy has this line (below), "
                "delete %s and remove the jobs' deploy keys from the opening repositories (RUNBOOK 10A-f)."
                % ("BOTH private repositories, GitHub's and GitLab's (GitLab: Delete, then Delete permanently)"
                   if two else "the private repository"))
        else:
            for line in rep[rep.index("") + 1:]:
                say("  " + line)
    except SystemExit as e:
        say("  note: the log cannot be checked as a whole: %s" % e)
    head = run("rev-parse", "HEAD").stdout.strip()
    failed = []
    for u in urls:
        r = run("push", "-q", u, "HEAD:refs/heads/main")
        got = run("ls-remote", u, "refs/heads/main").stdout.split()
        if got and got[0] == head:
            say("  ok      %s has it" % u)
        else:
            failed.append(u)
            say("  FAILED  %s does not have it: %s" % (u, " ".join((r.stderr or "").split())[:300]))
    privs = cfg.get("private_repos") or {}
    keys = {u: repo_key(u) for u in urls}
    ok_keys = {keys[u] for u in urls if u not in failed}
    missing = [(plat, u) for plat, u in sorted(privs.items()) if repo_key(u) not in keys.values()]
    unmatched = [u for u in urls if keys[u] not in {repo_key(x) for x in privs.values()}]
    got = [plat for plat, u in privs.items() if repo_key(u) in ok_keys] if privs else [u for u in urls if u not in failed]
    for plat, u in missing:
        say("  MISSING %s's copy (%s) is not among this working copy's push addresses%s" % (
            plat, u, " -- unless it is %s under another name" % " or ".join(unmatched) if unmatched else
            ": it did not get the line"))
    if not got and not (missing and unmatched and not failed):
        raise SystemExit("NO copy has this notice yet: the jobs will act as if it had never been sent. Fix the "
                         "cause (your sign-in, the network) and run this again today, with the same date and "
                         "code: it adds nothing twice.")
    if failed or (missing and not unmatched):
        fix = ["%s is reachable" % u for u in failed]
        if missing and not unmatched:
            pushurls = run("config", "--get-all", "remote.origin.pushurl").stdout.split()
            cmds = ([] if pushurls else ["git remote set-url --add --push origin %s"
                                         % run("remote", "get-url", "origin").stdout.strip()])
            cmds += ["git remote set-url --add --push origin %s" % u for _, u in missing]
            fix.append("you have added the missing address (SETUP.txt G2):  " + "  then  ".join(cmds))
        raise SystemExit("Not every copy has it. Run this again today, with the same date and code, once %s. "
                         "Until then the jobs report the difference at each run, and count the line only while "
                         "they can read a copy that has it." % " and ".join(fix))
    if missing:
        say("every push address has it (%d), but check with  git remote -v  that %s among them" % (
            len(urls), " and ".join("%s's copy (%s) is" % (plat, u) for plat, u in missing)))
        return 0
    say("every copy has it (%d)" % len(urls))
    return 0


def cmd_probe(a):
    ways, notes = tle_ways(HERE)
    for n in notes:
        say("note: " + n)
    if not ways:
        raise SystemExit("no tle to run")
    relays = a.relay or RELAYS
    value = secrets.token_hex(32).encode()
    r = current_round() + 10
    locked, label, relay = timelock_encrypt(ways, relays, CHAIN, r, value)
    say("time-locked a random value to round %d (%s UTC) with %s via %s" % (r, iso(round_time(r)), label, relay))
    out, tried = timelock_decrypt(ways, relays, CHAIN, locked)
    if out is not None:
        raise SystemExit("PROBE FAILED: it opened before its round")
    if not any("too early" in t for t in tried):
        raise SystemExit("PROBE FAILED: no relay could be asked:\n  " + "\n  ".join(tried))
    say("  ok   refused before its round: " + tried[-1])
    time.sleep(max(0, round_time(r) + 2 - time.time()))
    out, tried = timelock_decrypt(ways, relays, CHAIN, locked)
    if out != value:
        raise SystemExit("PROBE FAILED: it did not open after its round:\n  " + "\n  ".join(tried))
    say("  ok   opened after round %d, and matches" % r)
    say("PROBE PASSED")
    return 0


def cmd_decrypt(a):
    rel = sibling("sc2_release", "sc2-release.py")
    base = os.path.join(os.path.abspath(a.kit), "sc2")
    cfg = json.load(open(os.path.join(base, "config.json"), encoding="utf-8"))
    copies = cfg.get("copies") or {"GitHub": dict(sealed="sealed.bin", timelock="key-timelock.age", key_check=cfg["key_check"])}
    if a.platform not in copies:
        raise SystemExit("this kit has no copy for %s (it has: %s)" % (a.platform, ", ".join(copies)))
    copy = copies[a.platform]
    v = "".join(open(a.key_file).read().split()).lower()
    if not re.fullmatch(r"[0-9a-f]{128}", v) or key_check(bytes.fromhex(v)) != copy["key_check"]:
        raise SystemExit("%s is not this kit's key for %s's copy" % (a.key_file, a.platform))
    if os.path.exists(a.output):
        raise SystemExit("REFUSING: %s already exists" % a.output)
    ways, _ = tle_ways(os.path.join(base, "tools"))
    if not ways:
        ways, _ = tle_ways(HERE)
    out, tried = timelock_decrypt(ways, cfg["drand"]["relays"], cfg["drand"]["chain"],
                                  open(os.path.join(base, copy["timelock"]), "rb").read())
    kth = out.decode("ascii", "replace").strip() if out is not None else None
    if kth is None and a.half_file and cfg.get("peer") and cfg["peer"]["copy"] == a.platform:
        h = "".join(open(a.half_file).read().split()).lower()[:128]
        kth = h if half_ok(h, cfg["peer"]) else None
    if not kth or not re.fullmatch(r"[0-9a-f]{128}", kth):
        raise SystemExit("the time-lock did not open:\n  " + "\n  ".join(tried))
    record = unseal(open(os.path.join(base, copy["sealed"]), "rb").read(), bytes.fromhex(v), bytes.fromhex(kth))
    if record is None:
        raise SystemExit("the copy does not decrypt with these keys")
    tmp = tempfile.mkdtemp(prefix="sc2-")
    try:
        t = os.path.join(tmp, "commitment.txt")
        write(t, record, 0o600)
        if not matches(t, os.path.join(base, "commitment-reference.txt"), os.path.join(base, "commitment-title.txt"), rel):
            raise SystemExit("REFUSING: the opened copy does NOT match the reference; nothing written")
        write(a.output, record, 0o600)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    say("wrote %s: it matches all four digests and the short form" % a.output)
    return 0


def main(argv):
    if sys.version_info < (3, 9):
        raise SystemExit("Python 3.9 or later is needed (time zones)")
    ap = argparse.ArgumentParser(description="SC2 automatic release on GitHub (RUNBOOK step 10A)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("make", "rehearse"):
        m = sub.add_parser(name)
        m.add_argument("--opening-repo", action="append", required=True,
                       help="SSH address of the repository the job publishes to: a dedicated public one "
                            "(repeat for mirrors, up to 3); for a rehearsal, a private stand-in")
        m.add_argument("--timezone", default="Europe/Paris", help="your custodian's time zone (IANA name)")
        m.add_argument("--branch", default="main")
        m.add_argument("--out", default="autorelease-repo" if name == "make" else "rehearsal-repo")
        m.add_argument("--secrets", default="autorelease-secrets" if name == "make" else "rehearsal-secrets")
        m.add_argument("--canary-rounds", type=int, default=10, help=argparse.SUPPRESS)
        m.add_argument("--opening", default="autorelease-opening", help="folder for the opening repository's first files")
        m.add_argument("--gitlab", action="store_true",
                       help="also run the job on GitLab: a second, independent scheduler (RUNBOOK 10A-h)")
        m.add_argument("--no-peer-key", action="store_true",
                       help="with --gitlab: GitLab does NOT hold GitHub's time-locked key half (RUNBOOK 10A-h)")
        m.add_argument("--no-check-in", action="store_true",
                       help="no deliberate red run once a year (see RUNBOOK 10A-g)")
        m.add_argument("--private-repo", help="with --gitlab: the SSH address of the private GitHub repository "
                                              "that will hold this kit")
        m.add_argument("--gitlab-repo", help="with --gitlab: the SSH address of the private GitLab project "
                                             "that will hold this kit")
        if name == "make":
            m.add_argument("--entropy", required=True, help="350 FRESH dice rolls (512 bits assessed)")
            m.add_argument("--letter", default="release-kit/CUSTODIAN-LETTER-EN.txt")
            m.add_argument("--preimage", default="commitment.txt")
            m.add_argument("--reference", default="commitment-reference.txt")
            m.add_argument("--short", default="commitment-title.txt")
            m.add_argument("--today", help=argparse.SUPPRESS)
        else:
            m.add_argument("--days", type=int, default=1, help="the rehearsal is due this many days from today")
    r = sub.add_parser("run")
    r.add_argument("--kit", required=True)
    r.add_argument("--today", help=argparse.SUPPRESS)
    r.add_argument("--offline-test", action="store_true", help=argparse.SUPPRESS)
    n = sub.add_parser("notice")
    n.add_argument("--kit", default=".", help="your working copy of the private repository (default: here)")
    n.add_argument("date", help="the date your custodian counted the notice under, YYYY-MM-DD")
    n.add_argument("code", help="the code you sent (128 hexadecimal characters)")
    n.add_argument("--today", help=argparse.SUPPRESS)
    p = sub.add_parser("probe")
    p.add_argument("--relay", action="append")
    d = sub.add_parser("decrypt")
    d.add_argument("--kit", required=True)
    d.add_argument("--key-file", required=True)
    d.add_argument("-o", "--output", required=True)
    d.add_argument("--platform", default="GitHub", help="whose copy to open (GitHub or GitLab)")
    d.add_argument("--half-file", help="the key half another platform released, if drand does not open the lock")
    a = ap.parse_args(argv)
    if a.cmd == "make":
        cmd_make(a)
        return 0
    if a.cmd == "rehearse":
        cmd_rehearse(a)
        return 0
    return {"run": cmd_run, "probe": cmd_probe, "decrypt": cmd_decrypt, "notice": cmd_notice}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
