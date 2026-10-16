#!/usr/bin/env python3
"""sc2-disclose.py -- your own release of the sealed record, whenever you choose, with a
cooling-off delay (RUNBOOK Step 12).

The record is yours: you can publish commitment.txt at any time, and nothing in this toolkit
stops you. The custodian's date and the automated jobs only govern a release made without you.
This command adds impulse control: a release in two steps, at least an hour apart, the second
one made by typing a sentence.

  start    checks commitment.txt against your reference and short form, and records the time.
           Nothing is published. --hours N makes the wait N hours (1 at least).
  status   says where the request stands.
  confirm  from the end of the wait, and for 24 hours after it: shows what it will do, and once
           you type the sentence it asks for, publishes opening/commitment.txt and a short note
           in each repository you name (your local clone of a public repository you can push to):
           it builds the commit beside your clone, pushes it, reads the record back, checks that
           an anonymous reader gets it, and asks Software Heritage and the Wayback Machine to
           archive it. Your clone's branch moves only after that. Typing anything else publishes
           nothing; the request stays open. If confirm is interrupted, the request says where
           the record was pushed, and where a push was cut short. While confirm publishes, the
           other commands refuse to act in that folder (status only reports).
  cancel   drops the request. A request closed by a release, or dropped after one, stays in
           the file as the list of repositories the record went to.

  python3 sc2-disclose.py start [--hours 1]
  python3 sc2-disclose.py confirm --repo ~/sc2-public [--repo ~/commitment/autorelease-opening ...]

Run it in the folder that holds commitment.txt, commitment-reference.txt and
commitment-title.txt. The request is the file sc2-release-request.json there; confirm builds the
commit in a folder sc2-disclose-tmp-... beside it, removed when it ends, or by the next run of
this command if the computer stopped. A lock on the folder itself (nothing is written for it)
keeps two of its commands from acting there at once.

It keeps a discipline; it does not lock you out. The file is yours, and you could publish it by hand.
For the delay to hold, release only through this command, and keep commitment.txt out of
easy reach (RUNBOOK Step 12).
"""
import argparse, datetime as dt, glob, hashlib, importlib.util, json, math, os, re, shutil, signal, stat, subprocess, sys, tempfile, time
try:
    import fcntl
except ImportError:                     # Windows: no lock; a leftover working folder is removed after a day
    fcntl = None

HERE = os.path.dirname(os.path.abspath(__file__))
FORMAT = "SC2-RELEASE-REQUEST-1"
WINDOW = dt.timedelta(hours=24)        # how long a request may be confirmed once the wait is over
TMP = "sc2-disclose-tmp-"              # confirm's working folder, beside the request
MADE = "made-by-sc2-disclose"          # in it: what sweep() may remove
STOP = {"now": False}                  # set by the first signal: later ones are ignored while the command stops
RUN = {}                               # confirm's request once it may publish, for main() if a signal ends it
SSH_443 = {"ssh.github.com": "github.com", "altssh.gitlab.com": "gitlab.com"}   # SSH over port 443: their web hosts

NOTE = """\
RELEASE OF SEALED RECORD SC2/{{CASE}} BY ITS AUTHOR
================================================================================

The author of this sealed record released it on {{DAY}}. Its public reference --
two lines, commitment-reference.txt, published long before -- has this short
form (one line; the breaks here are not part of it):
{{SHORT}}

The record is opening/commitment.txt. Anyone can check that it is exactly the
record the reference referred to; nobody needs to trust this repository or its
owner, because a single changed byte would fail the check. From the folder that
holds commitment-reference.txt and opening/:

  { printf 'SC2-A\\n'; cat opening/commitment.txt; } | openssl dgst -sha3-512
  { printf 'SC2-B\\n'; cat opening/commitment.txt; } | openssl dgst -sha3-512
  openssl dgst -blake2b512 opening/commitment.txt
  sha512sum opening/commitment.txt                 (macOS: shasum -a 512)
  tr -s '[:space:]' ' ' < commitment-reference.txt | sed 's/^ *//; s/ *$//' | tr -d '\\n' | openssl dgst -sha3-512

The first four must equal S3A, S3B, B2 and S5 on line 2 of commitment-reference.txt;
the fifth must equal the short form above.

--------------------------------------------------------------------------------
PUBLICATION PAR SON AUTEUR DE L'ENREGISTREMENT SCELLÉ SC2/{{CASE}}

L'auteur de cet enregistrement scellé l'a rendu public le {{DAY}}. Sa référence
publique -- deux lignes, commitment-reference.txt, publiées bien avant -- a la
forme courte ci-dessus.

L'enregistrement est opening/commitment.txt. Chacun peut vérifier que c'est
exactement l'enregistrement auquel renvoyait la référence, avec les cinq
commandes ci-dessus ; personne n'a besoin de faire confiance à ce dépôt ni à
son propriétaire : un seul octet modifié ferait échouer la vérification.
"""


def sibling(modname, filename):
    spec = importlib.util.spec_from_file_location(modname, os.path.join(HERE, filename))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def now():
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0)


def when(t):
    """A time in this computer's local time, and in UTC."""
    return "%s (%s UTC)" % (t.astimezone().strftime("%Y-%m-%d %H:%M %Z").strip(), t.strftime("%Y-%m-%d %H:%M"))


def shown(text):
    """An address, or git's message, as printed: without any user name or token written into an address."""
    return re.sub(r"(?<=//)[^@/\s]+@", "", text)


def record(a):
    """(case, short form, the record's bytes), once the four digests and the short form match."""
    for p in (a.file, a.reference, a.short):
        if not os.path.isfile(p):
            raise SystemExit("%s: no such file. Run this in the folder that holds your record and its reference "
                             "(Step 3), or give --file, --reference and --short." % p)
    case, short = sibling("sc2_release", "sc2-release.py").verify_kit_inputs(a.file, a.reference, a.short)
    return case, short, open(a.file, "rb").read()


def load(path):
    """(request, end of the wait, end of the day to confirm), or (None, None, None)."""
    try:
        with open(path, encoding="utf-8") as f:
            r = json.load(f)
        if not isinstance(r, dict) or r.get("format") != FORMAT:
            raise ValueError("not a release request")
        nb, na = dt.datetime.fromisoformat(r["not_before"]), dt.datetime.fromisoformat(r["not_after"])
        if nb.tzinfo is None or na.tzinfo is None or not isinstance(r.get("case"), str) or not isinstance(r.get("sha512"), str):
            raise ValueError("a time without its offset, or a missing value")
        for k in ("published", "unsure"):           # where the record was pushed; where a push was cut short
            r.setdefault(k, [])
            if not isinstance(r[k], list) or not all(isinstance(x, str) for x in r[k]):
                raise ValueError("its list of repositories is not one")
        dt.datetime.fromisoformat(r["requested"])
        if r.get("closed") is not None:         # released, or dropped after a release: kept as the list of pushes
            if dt.datetime.fromisoformat(r["closed"]).tzinfo is None:
                raise ValueError("a time without its offset")
            if not isinstance(r.get("how"), str):
                raise ValueError("a closed request without how it closed")
        return r, nb, na
    except FileNotFoundError:
        return None, None, None
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as e:
        raise SystemExit("%s cannot be read (%s). This command published nothing. Rename the file, do not delete it: it "
                         "may list where the record went. Look at the repositories you named, then start again." % (path, e))


def save(path, r):
    """Writes the request in one step: an interruption, even a power cut, leaves the old one or the
    new one, whole."""
    part = "%s.%d.part" % (path, os.getpid())
    with os.fdopen(os.open(part, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w", encoding="utf-8") as f:
        json.dump(r, f, indent=1)
        f.flush()
        os.fsync(f.fileno())
    os.replace(part, path)
    try:                                        # and the renaming itself, on disk
        fd = os.open(os.path.dirname(os.path.abspath(path)), os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError:
        pass


def cmd_start(a):
    case, short, data = record(a)
    if not 1 <= a.hours <= 24 * 366:
        raise SystemExit("--hours must be from 1 (the wait is the point) to %d (a year)" % (24 * 366))
    t = now()
    r, nb, na = load(a.request)
    if r and not r.get("closed") and t <= na:
        raise SystemExit("A release request is already open, made at %s. Confirm it from %s, or drop it with:\n"
                         "    python3 sc2-disclose.py cancel" % (when(dt.datetime.fromisoformat(r["requested"])), when(nb)))
    if r and (r["case"], r["sha512"]) != (case, hashlib.sha512(data).hexdigest()):
        raise SystemExit("%s is the request of another record, SC2/%s. Move it elsewhere (it lists where that record "
                         "went), then start again. Nothing was published." % (a.request, r["case"]))
    nb = t + dt.timedelta(hours=a.hours)
    r = dict(format=FORMAT, case=case, sha512=hashlib.sha512(data).hexdigest(), requested=t.isoformat(),
             not_before=nb.isoformat(), not_after=(nb + WINDOW).isoformat(),   # an earlier request's lists are kept
             published=list(r["published"]) if r else [], unsure=list(r["unsure"]) if r else [])
    save(a.request, r)
    print("SC2/%s: release requested at %s. %s" % (case, when(t), nothing(r)))
    print("To release it, run this between %s\nand %s:" % (when(nb), when(nb + WINDOW)))
    print("    python3 sc2-disclose.py confirm --repo <your public repository's folder> [--repo ...]")
    print("If you change your mind, do nothing: the request lapses. Or drop it now:  python3 sc2-disclose.py cancel")
    return 0


def already(r, running=False):
    """What earlier runs put out, or may have: "" if nothing. running: a confirm is at work now."""
    if not r:
        return ""
    said, unsure = [], [u for u in r.get("unsure", []) if u not in r.get("published", [])]
    if r.get("published"):
        said.append("The record was ALREADY PUSHED to: %s." % ", ".join(r["published"]))
    if unsure:
        said.append(("A push to %s is under way, or was cut short: the record MAY be there." if running else
                     "A push to %s was cut short: the record MAY be there; look.") % " and ".join(unsure))
    return " ".join(said)


def nothing(r):
    """What a command that stops before publishing says of what is out there. With no request file,
    nothing is known of earlier runs: only of this one."""
    if not r:
        return "This command published nothing."
    return "Nothing more was published. " + already(r) if already(r) else "Nothing was published."


def closed_words(r):
    """How an earlier request ended, if it did."""
    return "the last one, made at %s, was %s at %s" % (when(dt.datetime.fromisoformat(r["requested"])), r["how"],
                                                      when(dt.datetime.fromisoformat(r["closed"])))


def cmd_status(a):
    if RUN.get("busy"):
        print("A confirm is publishing in this folder now, or another command of sc2-disclose.py is at work: what follows may change.")
    r, nb, na = load(a.request)
    if not r or r.get("closed"):
        print("No release request is open here%s." % (": " + closed_words(r) if r else ""))
        if already(r, RUN.get("busy")):
            print(already(r, RUN.get("busy")))
        return 0
    t = now()
    print("SC2/%s: release requested at %s." % (r["case"], when(dt.datetime.fromisoformat(r["requested"]))))
    if t < nb:
        print("Too early to confirm: the wait ends at %s, in %d minute(s)." % (when(nb), math.ceil((nb - t).total_seconds() / 60)))
    elif t <= na:
        print("It can be confirmed now, until %s." % when(na))
    else:
        print("It lapsed at %s: start again if you still want to release." % when(na))
    if already(r, RUN.get("busy")):
        print(already(r, RUN.get("busy")))
    return 0


def cmd_cancel(a):
    r, _, _ = load(a.request)
    if not r or r.get("closed"):
        print(("No release request is open here%s. %s" % (": " + closed_words(r) if r else "", already(r))).rstrip())
        return 0
    if not already(r):
        os.remove(a.request)
        print("Release request dropped. Nothing was published.")
        return 0
    r.update(closed=now().isoformat(), how="dropped")       # kept: where the record went
    save(a.request, r)
    print("Release request dropped. %s What was pushed stays: a release cannot be undone." % already(r))
    return 0


def git(d, *args, binary=False, env=None, data=None, apart=False):
    """git in folder d. apart: in a session of its own, which the terminal's Ctrl-C does not reach."""
    r = subprocess.run(["git"] + list(args), cwd=d, capture_output=True, input=data,
                       env=dict(os.environ, **env) if env else None, start_new_session=apart)
    if binary:
        return r
    return subprocess.CompletedProcess(r.args, r.returncode, r.stdout.decode("utf-8", "replace").strip(),
                                       " ".join(r.stderr.decode("utf-8", "replace").split()))


def gpath(d, *args):
    """A path that git prints, exactly as it is (one that ends in a space too): only its line end removed."""
    out = os.fsdecode(git(d, *args, binary=True).stdout)
    return out[:-1] if out.endswith("\n") else out


def gerr(r):
    """git's error message, as printed."""
    return shown(r.stderr)[:300]


def web_url(url, top=None):
    """The repository's https address, for the anonymous check and the archives, or None: a local
    path, or a host whose web address is not known here. An SSH host is the one ssh connects to:
    ssh -G, which connects to nothing, reads your SSH configuration (running any "Match exec"
    command in it, as ssh itself would) and turns a host alias (github-sc2) into its real host;
    GitHub's and GitLab's SSH hosts on port 443 stand for their web hosts. Not when git uses an ssh
    command of its own (GIT_SSH_COMMAND, GIT_SSH, core.sshCommand), which may read another
    configuration: the host is then taken as written."""
    m = re.fullmatch(r"https://(?:[^@/\s]+@)?([^/\s]+)/([^\s]+?)(?:\.git)?/?", url)
    if m:
        return "https://%s/%s" % (m.group(1), m.group(2)) if "." in m.group(1) else None
    m = (re.fullmatch(r"(?:ssh|git\+ssh|ssh\+git)://(?:[^@/\s]+@)?([A-Za-z0-9][A-Za-z0-9._-]*)(?::\d+)?/([^\s]+?)(?:\.git)?/?", url)
         or re.fullmatch(r"(?:[^@/\s:]+@)?([A-Za-z0-9][A-Za-z0-9._-]*):(?!/)([^\s]+?)(?:\.git)?/?", url))
    if not m:
        return None
    host = m.group(1)
    own = os.environ.get("GIT_SSH_COMMAND") or os.environ.get("GIT_SSH") or (top and git(top, "config", "core.sshCommand").stdout)
    if not own:
        try:
            g = subprocess.run(["ssh", "-G", "--", host], capture_output=True, timeout=30)
            found = re.findall(r"(?m)^hostname (\S+)$", g.stdout.decode("utf-8", "replace"))
            host = found[0] if g.returncode == 0 and found else host
        except (OSError, subprocess.SubprocessError):
            pass
    host = SSH_443.get(host.lower(), host.lower())
    return "https://%s/%s" % (host, m.group(2)) if "." in host else None


def ident(top):
    """The name and e-mail git will sign with in this clone, or None."""
    i = git(top, "var", "GIT_AUTHOR_IDENT")
    if i.returncode or git(top, "var", "GIT_COMMITTER_IDENT").returncode:
        return None
    return re.sub(r"\s+\d+\s+[+-]\d{4}$", "", i.stdout)


def plan(folder, data, case, tail):
    """What publishing through this clone involves, checked first; refuses rather than guess."""
    d = os.path.abspath(os.path.expanduser(folder))
    if not os.path.isdir(d) or git(d, "rev-parse", "--is-inside-work-tree").stdout != "true":
        raise SystemExit("%s is not a git working copy: give the folder of your local clone of the public "
                         "repository. %s" % (folder, tail))
    top = gpath(d, "rev-parse", "--show-toplevel")
    if os.path.exists(os.path.join(top, "sc2", "config.json")):
        raise SystemExit("REFUSING: %s is the working copy of your PRIVATE automated-release repository, not a "
                         "public one. %s" % (top, tail))
    branch = git(top, "symbolic-ref", "--short", "-q", "HEAD").stdout
    up = git(top, "rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}").stdout
    if not branch or "/" not in up:
        raise SystemExit("%s: its branch %s has no upstream to push to. Set it, e.g.  git -C %s branch -u origin/main\n"
                         "%s" % (top, branch or "(none)", top, tail))
    remote, rbranch = up.split("/", 1)
    url = git(top, "remote", "get-url", remote).stdout
    pushes = [u for u in git(top, "remote", "get-url", "--push", "--all", remote).stdout.splitlines() if u]
    if pushes != [url]:
        raise SystemExit("REFUSING: %s pushes to %s, not only to %s, where it reads from. If that is the same "
                         "repository reached another way (a rule that pushes over SSH what is read over HTTPS), give "
                         "the clone the address it pushes to:  git -C %s remote set-url %s %s\n%s"
                         % (top, ", ".join(map(shown, pushes)), shown(url), top, remote, shown(pushes[0]) if pushes else "<address>",
                            tail))
    who = ident(top)
    if not who:
        raise SystemExit("REFUSING: git does not know your name and e-mail in %s, so it could not commit. Set them as "
                         "in Step 6a:\n    git -C %s config user.name \"<name or pseudonym>\"\n    git -C %s config "
                         "user.email \"<public e-mail or no-reply address>\"\n%s" % (top, top, top, tail))
    f = git(top, "fetch", "-q", remote)
    if f.returncode:
        raise SystemExit("%s: cannot reach %s (%s). %s" % (top, shown(url), gerr(f), tail))
    there = git(top, "show", "%s:opening/commitment.txt" % up, binary=True)
    if there.returncode == 0 and there.stdout != data:
        raise SystemExit("REFUSING: %s already holds an opening/commitment.txt that is not this record. %s"
                         % (shown(url), tail))
    return dict(dir=top, up=up, remote=remote, branch=rbranch, url=url, web=web_url(url, top), who=who,
                done=there.returncode == 0, track=git(top, "rev-parse", "--symbolic-full-name", "@{u}").stdout,
                objects=os.path.join(top, gpath(top, "rev-parse", "--git-common-dir"), "objects"))


OID = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")


def objects(p, tmp):
    """The environment in which the release commit is made: its objects go to a store of their own
    in tmp, which also reads the clone's, named in its alternates file (where a path may hold a
    colon; one with a line break is quoted, as git reads it). If the release does not happen,
    deleting tmp leaves no copy of the record in the clone's .git."""
    store, path = os.path.join(tmp, "objects"), p["objects"]
    os.makedirs(os.path.join(store, "info"))
    if "\n" in path or path.startswith(('"', "#")):
        path = '"%s"' % "".join("\\%03o" % ord(c) if c < " " else "\\" + c if c in '"\\' else c for c in path)
    with open(os.path.join(store, "info", "alternates"), "w", encoding="utf-8") as f:
        f.write(path + "\n")
    return dict(GIT_OBJECT_DIRECTORY=store)


def adopt(p, c, tmp):
    """After a push of commit c, finished or cut short. If the remote took it, git has moved the
    clone's record of the remote's branch to it: c's objects are then copied into the clone, so that
    this record names nothing missing once tmp is gone. If not, the clone gets nothing. Each object
    is written under a temporary name, as git writes its own, then renamed into place. False if
    that could not be done, or if it is not known whether the remote took the push."""
    try:
        v = git(p["dir"], "rev-parse", "-q", "--verify", p["track"], apart=True)
        if v.returncode == 1 or (v.returncode == 0 and v.stdout != c):
            return True
        if v.returncode != 0:
            return False
        src = os.path.join(tmp, "objects")
        for sub in (s for s in os.listdir(src) if re.fullmatch(r"[0-9a-f]{2}", s)):
            into = os.path.join(p["objects"], sub)
            os.makedirs(into, exist_ok=True)
            for name in os.listdir(os.path.join(src, sub)):
                if not os.path.exists(os.path.join(into, name)):
                    fd, part = tempfile.mkstemp(prefix="tmp_obj_", dir=into)
                    os.close(fd)
                    shutil.copyfile(os.path.join(src, sub, name), part)
                    os.replace(part, os.path.join(into, name))
                    os.chmod(os.path.join(into, name), 0o444)
        return True
    except (OSError, subprocess.SubprocessError):
        return False


def pushes(work):
    """The pushes made from this working folder: (what was noted before each, its folder)."""
    for j in glob.glob(os.path.join(glob.escape(work), "*", "pushing.json")):
        try:
            with open(j, encoding="utf-8") as g:
                q = json.load(g)
            if isinstance(q, dict):
                yield q, os.path.dirname(j)
        except (OSError, ValueError):
            pass


def adopt_all(work):
    """adopt() for each push made from this working folder. True if each was done."""
    done = True
    for q, tmp in pushes(work):
        try:
            done = adopt(q, q["commit"], tmp) and done
        except (KeyError, TypeError, AttributeError):
            pass
    return done


def started(pid):
    """When process pid started, in the system's clock ticks since boot (Linux), or None. It stays
    the same through exec, and a number the system gives again to another program does not share it."""
    try:
        with open("/proc/%d/stat" % pid, "rb") as f:
            return f.read().rsplit(b")", 1)[1].split()[19].decode()
    except (OSError, IndexError, UnicodeDecodeError):
        return None


def alive(q):
    """Whether the push noted in q may still run. Where its start time was noted (Linux): the process
    with its number started at that time. Elsewhere: that number is in use, for less than 6 hours
    since the push was noted."""
    pid = q.get("pid")
    if os.name != "posix" or not isinstance(pid, int):
        return False
    if q.get("started"):
        return started(pid) == q["started"]
    try:
        if now() - dt.datetime.fromisoformat(q["at"]) > dt.timedelta(hours=6):
            return False
    except (KeyError, TypeError, ValueError):
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except OSError:
        pass
    return True


def remove(d):
    """Removes a working folder, its read-only files too (git's objects are: Windows will not delete
    them as they are), its mark last: a folder half removed is still found by the next sweep. True
    once it is gone."""
    def again(func, path, _):
        try:
            os.chmod(path, stat.S_IWRITE)
            func(path)
        except OSError:
            pass
    try:
        for name in os.listdir(d):
            if name != MADE:
                path = os.path.join(d, name)
                if os.path.isdir(path) and not os.path.islink(path):
                    shutil.rmtree(path, **{"onexc" if sys.version_info >= (3, 12) else "onerror": again})
                else:
                    os.remove(path)
        shutil.rmtree(d, **{"onexc" if sys.version_info >= (3, 12) else "onerror": again})
    except OSError:
        pass
    return not os.path.exists(d)


def build(p, data, note, msg, env, tmp):
    """The release commit, on the upstream's tip as just fetched, made beside the clone: the
    clone's branch, index, files and object store are not touched, and no filter or hook runs.
    Returns its id once its two files have been read back from it, byte for byte, or None."""
    blobs = []
    for content in (data, note.encode("utf-8")):
        r = git(p["dir"], "hash-object", "-w", "--no-filters", "--stdin", data=content, env=env)
        if r.returncode or not OID.fullmatch(r.stdout):
            return None
        blobs.append(r.stdout)
    ienv = dict(env, GIT_INDEX_FILE=os.path.join(tmp, "index"))
    base = git(p["dir"], "rev-parse", "--verify", "-q", "%s^{commit}" % p["up"]).stdout
    if not OID.fullmatch(base):
        return None
    steps = [["read-tree", base]] + [["update-index", "--add", "--cacheinfo", "100644,%s,%s" % (b, n)] for b, n in
                                     zip(blobs, ("opening/commitment.txt", "opening/RELEASE-NOTE-AUTHOR.txt"))]
    for step in steps:
        if git(p["dir"], *step, env=ienv).returncode:
            return None
    tree = git(p["dir"], "write-tree", env=ienv)
    if tree.returncode or not OID.fullmatch(tree.stdout):
        return None
    stamp = "@%d +0000" % int(now().timestamp())             # in UTC: the commit tells no time zone
    c = git(p["dir"], "commit-tree", tree.stdout, "-p", base, "-m", msg,
            env=dict(env, GIT_AUTHOR_DATE=stamp, GIT_COMMITTER_DATE=stamp))
    if c.returncode or not OID.fullmatch(c.stdout):
        return None
    for want, n in ((data, "opening/commitment.txt"), (note.encode("utf-8"), "opening/RELEASE-NOTE-AUTHOR.txt")):
        if git(p["dir"], "cat-file", "blob", "%s:%s" % (c.stdout, n), binary=True, env=env).stdout != want:
            return None
    return c.stdout


def anon_env(home):
    """An environment in which git has none of this computer's credentials: no configuration,
    no credential helper, no password program (an empty GIT_ASKPASS turns it off), and a home
    folder with no .netrc in it, which git's HTTPS library would otherwise read."""
    keep = ("PATH", "SYSTEMROOT", "http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY", "all_proxy", "ALL_PROXY",
            "no_proxy", "NO_PROXY", "SSL_CERT_FILE", "SSL_CERT_DIR", "GIT_SSL_CAINFO", "GIT_SSL_CAPATH")
    env = {k: os.environ[k] for k in keep if k in os.environ}
    env.update(HOME=home, XDG_CONFIG_HOME=home, GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1",
               GIT_TERMINAL_PROMPT="0", GIT_ASKPASS="", LC_ALL="C")
    return env


def anonymous(p, data, work):
    """True if an anonymous reader gets the record from the repository's https address, without
    any of this computer's credentials; False if that could not be confirmed; None if there is
    no address to try."""
    if not p["web"]:
        return None
    tmp = tempfile.mkdtemp(prefix="anon-", dir=work)
    try:
        env, d = anon_env(tmp), os.path.join(tmp, "r")
        for args in (["init", "-q", d], ["-C", d, "-c", "credential.helper=", "fetch", "-q", "--depth", "1",
                                         p["web"] + ".git", "refs/heads/" + p["branch"]]):
            if subprocess.run(["git"] + args, env=env, capture_output=True, timeout=180).returncode:
                return False
        r = subprocess.run(["git", "-C", d, "cat-file", "blob", "FETCH_HEAD:opening/commitment.txt"], env=env,
                           capture_output=True, timeout=60)
        return r.returncode == 0 and r.stdout == data
    except (OSError, subprocess.SubprocessError):
        return False
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def push(p, c, env, at, noted):
    """git push of commit c alone, its process id noted at `at` while it runs, so that a sweep after
    this program was killed leaves its working folder until that push ends. The push waits, behind
    a shell's read, until that note is saved (the shell becomes git, under the same process id): if
    this program dies first, the read ends and nothing is pushed. A signal stops it."""
    args = ["git", "push", "-q", "--no-follow-tags", "--recurse-submodules=no", p["remote"], "%s:refs/heads/%s" % (c, p["branch"])]
    gate = os.name == "posix"
    try:
        proc = subprocess.Popen((["/bin/sh" if os.path.exists("/bin/sh") else "sh", "-c", 'read go || exit 1; exec "$0" "$@"']
                                 if gate else []) + args, cwd=p["dir"], env=dict(os.environ, **env),
                                stdin=subprocess.PIPE if gate else subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError:                             # no shell to wait in: the push, without its gate
        gate = False
        proc = subprocess.Popen(args, cwd=p["dir"], env=dict(os.environ, **env), stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        save(at, dict(noted, pid=proc.pid, at=now().isoformat(), started=started(proc.pid)))
        out, err = proc.communicate(b"go\n" if gate else None)
    except BaseException:
        proc.kill()
        proc.wait()
        raise
    return subprocess.CompletedProcess(args, proc.returncode, out.decode("utf-8", "replace").strip(),
                                       " ".join(err.decode("utf-8", "replace").split()))


def look(p, data):
    """What the repository's branch holds, as fetched now: ("record" | "nothing" | "other"), or
    ("unreachable", git's message)."""
    f = git(p["dir"], "fetch", "-q", p["remote"])
    if f.returncode:
        return "unreachable", gerr(f)
    there = git(p["dir"], "show", "%s:opening/commitment.txt" % p["up"], binary=True)
    return ("nothing" if there.returncode else "record" if there.stdout == data else "other"), ""


def publish(p, data, note, case, day, tmp, mark):
    """Publishes the record through this clone: builds the release commit on the upstream as it is
    now, pushes that commit alone (no tags) to the remote, reads the record back, and checks that
    an anonymous reader gets it. Only then does it bring the clone's branch forward, if it can do
    so without touching anything of yours. A failure before the push leaves the clone as it was.
    mark() is told at once what is known: "pushing" before a push, "record" once the repository
    holds the record, "nothing" once it is known not to. Returns (ok, public: True / False / None
    when there is no address to check, message)."""
    msg = "SC2/%s: released by its author, %s" % (case, day)
    os.makedirs(tmp, exist_ok=True)
    if p["done"]:
        mark("record")
        said = "already holds the record"
    else:
        env, refused, lost = objects(p, tmp), None, False
        for attempt in range(4):            # a heartbeat pushed meanwhile: build again on top of it, push again
            state, err = look(p, data)
            if state == "unreachable":
                return False, None, ("cannot reach the repository (%s); this run published nothing there" % err if not refused
                                     else "git push failed (%s), and the repository cannot be read now (%s): the record "
                                     "MAY be there. Run confirm again to find out (it adds nothing twice)" % (refused, err))
            if state == "other":
                mark("nothing")
                return False, None, "it now holds an opening/commitment.txt that is not this record: left alone"
            if state == "record":
                mark("record")
                said = ("published (git push reported an error, yet the record is there: %s)" % refused if refused
                        else "already holds the record")
                break
            mark("nothing")
            if attempt == 3:
                return False, None, "git push failed (%s); nothing was published there, and your clone is as it was" % refused
            c = build(p, data, note, msg, env, tmp)
            if not c:
                return False, None, "the release commit could not be built and checked; this run published nothing there"
            noted = dict(dir=p["dir"], track=p["track"], objects=p["objects"], commit=c)   # for sweep(), after a kill
            save(os.path.join(tmp, "pushing.json"), noted)
            mark("pushing")
            try:
                r = push(p, c, env, os.path.join(tmp, "pushing.json"), noted)
            finally:
                lost = not adopt(p, c, tmp)
            if r.returncode == 0:
                mark("record")
                state, err = look(p, data)
                if state == "unreachable":
                    return False, None, ("published, but it could not be read back (%s): run confirm again to check it (it "
                                         "adds nothing twice)%s" % (err, "; first,  git -C %s fetch" % p["dir"] if lost else ""))
                if state != "record":
                    return False, None, "pushed, but what the repository holds now is not the record: look at it"
                said = "published"
                break
            refused = gerr(r)
    public = anonymous(p, data, tmp)
    if public is False:
        return False, False, ("%s, but it could not be confirmed that an anonymous reader gets it from %s. Check that this "
                              "is the public repository you meant, and that it is public, then run confirm again (it adds "
                              "nothing twice)" % (said, p["web"]))
    dirty = git(p["dir"], "status", "--porcelain", "--untracked-files=no").stdout
    ff = "" if dirty or p["done"] else git(p["dir"], "-c", "merge.autoStash=false", "merge", "-q", "--ff-only", p["up"]).stderr
    return True, public, "%s and read back%s%s" % (
        said, ", anonymously too" if public else " (NOT checked as public: no public web address known for it)",
        "; bring your clone up to date with  git -C %s pull" % p["dir"] if (dirty or ff) and not p["done"] else "")


def cmd_confirm(a):
    r, nb, na = load(a.request)
    if not r or r.get("closed"):
        raise SystemExit("No release request is open here (%s%s). Run  python3 sc2-disclose.py start  first, then "
                         "wait. %s" % (a.request, ": " + closed_words(r) if r else "", nothing(r)))
    t = now()
    if t < nb:
        raise SystemExit("Too early: the wait ends at %s, in %d minute(s). %s"
                         % (when(nb), math.ceil((nb - t).total_seconds() / 60), nothing(r)))
    if t > na:
        raise SystemExit("This request lapsed at %s. %s Start again if you still want to release." % (when(na), nothing(r)))
    case, short, data = record(a)
    if (case, hashlib.sha512(data).hexdigest()) != (r["case"], r["sha512"]):
        raise SystemExit("REFUSING: %s is not the record this request was made for. %s" % (a.file, nothing(r)))
    if not a.repo:
        raise SystemExit("Name at least one --repo: your local clone of a public repository you can push to. %s"
                         % nothing(r))
    ar = sibling("sc2_autorelease", "sc2-autorelease.py")
    plans, seen = [], set()
    for f in a.repo:
        p = plan(f, data, case, nothing(r))
        if os.path.realpath(p["dir"]) not in seen:     # one clone named twice: once. A second clone of the same
            seen.add(os.path.realpath(p["dir"]))       # repository finds the record there, and adds nothing.
            plans.append(p)
    print("SC2/%s: ready to publish the record. This cannot be undone: the archives keep it." % case)
    for p in plans:
        print("  %s, branch %s (from %s): %s;\n    %s" % (
            shown(p["url"]), p["branch"], p["dir"], "already holds the record" if p["done"] else
            "adds opening/commitment.txt and a note, signed %s" % p["who"], "then checked as an anonymous reader, at %s"
            % p["web"] if p["web"] else "no public web address known for it: you will check by hand that it is public"))
    sentence = "release SC2/%s now" % case
    print("To publish it, type exactly:  %s" % sentence)
    try:
        typed = input("> ")
    except (EOFError, KeyboardInterrupt, RuntimeError):     # RuntimeError: no input at all (closed)
        typed = None
    if typed is None or typed.strip() != sentence:
        try:                                    # read afresh: another confirm may have released meanwhile
            now_r = load(a.request)[0]
        except SystemExit:
            now_r = None
        same = now_r and not now_r.get("closed") and now_r["requested"] == r["requested"]
        say("%sNot published by this command: that is not the sentence. %s%s"
            % ("\n" if typed is None else "", already(now_r) + " " if already(now_r) else "",
               "The request stays open until %s." % when(na) if same else
               "The request is no longer open: run  python3 sc2-disclose.py status  to see where things stand."))
        return 1
    folder = os.path.dirname(a.request)         # only now the lock: a confirm left at its prompt keeps no one out
    for i in range(20):                         # a status at that moment holds it an instant: wait up to 10 s
        free, RUN["lock"] = take(folder)
        if free:
            break
        time.sleep(0.5)
    if not free:
        raise SystemExit("Another command of sc2-disclose.py is at work in this folder, perhaps another confirm publishing "
                         "right now: this one published nothing. Run it again once that one has ended.")
    if RUN["lock"] is None:
        unlocked()
    sweep(folder, RUN["lock"] is not None)
    was = r                                     # the request may have been dropped, or released, meanwhile
    r, nb, na = load(a.request)
    if not r or r.get("closed") or (r["requested"], r["case"], r["sha512"]) != (was["requested"], was["case"], was["sha512"]):
        raise SystemExit("The request changed while the sentence was being typed (dropped, or released by another confirm): "
                         "this command published nothing. Run  python3 sc2-disclose.py status  to see where things stand.")
    t = now()                                   # the day may have ended while the sentence waited
    if t > na:
        raise SystemExit("This request lapsed at %s, while the sentence was being typed. %s Start again if you "
                         "still want to release." % (when(na), nothing(r)))
    day = t.astimezone().date().isoformat()
    note = NOTE.replace("{{CASE}}", case).replace("{{DAY}}", day).replace("{{SHORT}}", "  SC2 REF-SHA3-512=\n" + "\n".join(
        "  " + short[17:][i:i + 64] for i in range(0, 128, 64)))

    def mark(u, state):
        """What is known of repository u, saved at once: an interruption may come next. A repository
        is listed as pushed before it leaves the list of pushes cut short."""
        if state == "record" and u not in r["published"]:
            r["published"].append(u)
        if state == "pushing":
            if u not in r["published"] and u not in r["unsure"]:
                r["unsure"].append(u)
        elif u in r["unsure"]:
            r["unsure"].remove(u)
        save(a.request, r)

    work = tempfile.mkdtemp(prefix=TMP, dir=folder)
    open(os.path.join(work, MADE), "w").close()
    RUN.update(r=r, request=a.request)          # from here on, a signal is answered with what is out there
    results, keep = [], False
    try:
        for i, p in enumerate(plans):
            good, public, msg = publish(p, data, note, case, day, os.path.join(work, str(i)),
                                        lambda state, u=shown(p["url"]): mark(u, state))
            print("  %s %s: %s" % ("ok    " if good else "FAILED", shown(p["url"]), msg))
            results.append((p, good, public))
        if not a.no_archive:
            for p, good, public in results:
                if good and p["web"]:
                    for line in ar.archive(dict(repo=shown(p["url"]), web=p["web"], branch=p["branch"])):
                        print("         " + line)
                elif good:
                    print("         %s: no public web address known for it; archive it by hand" % shown(p["url"]))
        STOP["now"] = True                      # nothing left to stop: what remains is said, saved and cleaned up
        if not all(good for p, good, public in results):
            print("Not every repository got it, or could be confirmed public (above). Fix the cause and run confirm again "
                  "before %s: it adds nothing twice." % when(na))
            return 1
        r.update(closed=now().isoformat(), how="released")    # kept: where the record went
        save(a.request, r)
        RUN["closed"] = True
        checked = [p["web"] for p, good, public in results if public]
        unchecked = [shown(p["url"]) for p, good, public in results if public is None]
        if not checked:
            print("Pushed to %s, but NOT checked as public: no public web address is known here to check. Check by "
                  "hand, signed out (in a private browser window, say), that opening/commitment.txt is there. Until you "
                  "have, count on nothing: tell no one it is public, and delete nothing." % " and ".join(unchecked))
            return 0
        print("Released: SC2/%s is public: an anonymous reader gets it from %s." % (case, " and ".join(checked)))
        if unchecked:
            print("Not checked for %s: no public web address known here for it. Check that by hand, signed out."
                  % " and ".join(unchecked))
        print("Next: tell your custodian it is public; their release on the date publishes the same file again, which "
              "does no harm. With Step 10A, the jobs find it in any opening repository named here and publish nothing "
              "more there; you may delete the private repository (both, with GitLab) and the jobs' deploy keys. Point "
              "people to VERIFY-PUBLIC.txt.")
        return 0
    except KeyboardInterrupt:                   # Ctrl-C, a closed terminal, a shutdown; any later signal is ignored
        STOP["now"] = True
        keep = not adopt_all(work)              # a push the remote took: the clone gets its commit
        save(a.request, r)
        say("\nINTERRUPTED. %s Run confirm again before %s to finish: it adds nothing twice.%s"
            % (already(r) or "Nothing was published.", when(na), " (Its working folder, with a copy of the record, stays "
               "until then: confirm's first step gives your clone what it needs, then removes it.)" if keep else ""))
        return 130
    finally:
        if not keep:
            remove(work)


def say(text):
    """Prints, if the terminal is still there (a closed one makes any later output fail, up to the
    exit itself, so it then goes nowhere): what matters is saved already."""
    try:
        print(text, flush=True)
    except OSError:
        try:
            sys.stdout = open(os.devnull, "w")
        except OSError:
            pass


def interrupted(signum, frame):
    """Ctrl-C, a closed terminal, a shutdown. The first stops the command; any later one is ignored,
    so that it can save what it knows and clean up."""
    if not STOP["now"]:
        STOP["now"] = True
        raise KeyboardInterrupt


def take(folder):
    """(True, the lock) once this process holds a lock on the folder itself (nothing is written for
    it, and it cannot be deleted), which the system drops when the process ends, however it ends;
    (False, None) while another command of sc2-disclose.py holds it. (True, None) where the system
    offers no such lock (Windows, some network file systems)."""
    if not fcntl:
        return True, None
    try:
        fd = os.open(folder, os.O_RDONLY)
    except OSError:
        return True, None
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return True, fd
    except BlockingIOError:
        os.close(fd)
        return False, None
    except OSError:
        os.close(fd)
        return True, None


def unlocked():
    """Says that, here, nothing keeps two commands from acting at once."""
    print("Note: this folder cannot be locked here, so two commands of sc2-disclose.py run at once in it would not be "
          "kept apart: run one at a time.", file=sys.stderr)


def sweep(folder, locked):
    """Removes what a confirm stopped by force (the computer turned off, kill -9) left beside the
    request: its working folder, which holds a copy of the record. Only while this process holds
    the folder's lock (locked), when no confirm can be publishing; without a lock, only folders a
    day old. Only folders a confirm made (holding its mark), and an empty one it made just before
    being stopped. Never while a push started from it still runs. If the remote took a push made
    from one, the clone first gets that commit (adopt_all); if that fails, the folder stays."""
    try:
        names = os.listdir(folder)
    except OSError:
        return
    for name in names:
        d = os.path.join(folder, name)
        if not name.startswith(TMP) or os.path.islink(d) or not os.path.isdir(d):
            continue
        try:
            if not os.path.isfile(os.path.join(d, MADE)):
                if locked and re.fullmatch(re.escape(TMP) + r"[a-z0-9_]{8}", name) and not os.listdir(d):
                    os.rmdir(d)
                continue
            if not locked and time.time() - os.path.getmtime(d) < 86400:
                continue
        except OSError:
            continue
        running = [q["pid"] for q, _ in pushes(d) if alive(q)]
        if running:
            print("Kept %s, which holds a copy of the record: a push started from it still runs (process %d). The next "
                  "run of sc2-disclose.py here, once it has ended, removes it." % (d, running[0]))
        elif not adopt_all(d):
            print("Kept %s, which holds a copy of the record: a clone could not yet be given the commit a push from it "
                  "left there. Run  git -C <that clone> fetch  (%s), then any command of sc2-disclose.py here removes it."
                  % (d, ", ".join(sorted({str(q.get("dir")) for q, _ in pushes(d)}))))
        elif remove(d):
            print("Removed %s, left by a confirm that was stopped: it held a copy of the record." % d)


def main(argv):
    ap = argparse.ArgumentParser(prog="sc2-disclose.py", description="Your own release of the sealed record, "
                                 "whenever you choose, in two steps at least an hour apart (RUNBOOK Step 12).")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("start", "status", "confirm", "cancel"):
        p = sub.add_parser(name)
        p.add_argument("--request", default="sc2-release-request.json")
        if name in ("start", "confirm"):
            p.add_argument("--file", default="commitment.txt")
            p.add_argument("--reference", default="commitment-reference.txt")
            p.add_argument("--short", default="commitment-title.txt")
        if name == "start":
            p.add_argument("--hours", type=int, default=1, help="the wait before you can confirm (1 at least)")
        if name == "confirm":
            p.add_argument("--repo", action="append", default=[],
                           help="your local clone of a public repository you can push to (one or more)")
            p.add_argument("--no-archive", action="store_true", help="do not ask the archives (do it by hand)")
    a = ap.parse_args(argv)
    a.request = os.path.realpath(a.request)    # through a link: the folder, and the file, it leads to
    RUN.clear()
    STOP["now"] = False
    try:
        for name in ("SIGINT", "SIGHUP", "SIGTERM"):    # Ctrl-C, a closed terminal, a shutdown; not one ignored (nohup)
            sig = getattr(signal, name, None)
            if sig is not None and signal.getsignal(sig) != signal.SIG_IGN:
                signal.signal(sig, interrupted)
        if a.cmd != "confirm":                  # confirm takes the lock once the sentence is typed
            free, RUN["lock"] = take(os.path.dirname(a.request))
            if not free and a.cmd != "status":
                raise SystemExit("Another command of sc2-disclose.py is at work in this folder, perhaps a confirm "
                                 "publishing right now: %s does nothing meanwhile. Let it end, or stop it with Ctrl-C in "
                                 "its window (if it was stopped with Ctrl-Z, bring it back first with fg); then run %s "
                                 "again." % (a.cmd, a.cmd))
            RUN["busy"] = not free
            if free:
                if RUN["lock"] is None and a.cmd != "status":
                    unlocked()
                sweep(os.path.dirname(a.request), RUN["lock"] is not None)
        return {"start": cmd_start, "status": cmd_status, "confirm": cmd_confirm, "cancel": cmd_cancel}[a.cmd](a)
    except KeyboardInterrupt:
        STOP["now"] = True
        if "r" not in RUN:
            say("\nInterrupted. This command published nothing.")
        else:                                   # confirm, stopped while publishing: say what is out there
            if not RUN.get("closed"):
                save(RUN["request"], RUN["r"])
            say("\nINTERRUPTED. %s" % (already(RUN["r"]) or "Nothing was published."))
        return 130
    finally:
        STOP["now"] = True                      # what remains is only giving the lock back
        if RUN.get("lock") is not None:
            os.close(RUN["lock"])


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
