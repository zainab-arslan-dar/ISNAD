"""ISNAD analysis engine (pure Python, no web code).
Parsers (text/JSON logs, Zeek conn.log, EVTX), 18 ATT&CK-mapped indicators,
Isolation Forest anomaly scoring, plain-language explanations, ranked leads."""
import hashlib, json, math, os, re, tempfile
from collections import Counter, defaultdict
from datetime import datetime, timezone

SV = ["Info", "Low", "Medium", "High", "Critical"]
I = re.I
E = r"Event ?ID\W{0,4}"
# (regex, severity, title, why it matters, ATT&CK id)
RULES = [
 (re.compile(r"log(s)? (was )?cleared|" + E + r"(1102|104)\b|wevtutil\s+cl", I), 4, "Anti-forensics: log cleared", "Clearing audit logs is a recognised attempt to remove evidence of prior activity.", "T1070.001"),
 (re.compile(r"vssadmin.*delete\s+shadows|wmic.*shadowcopy.*delete|bcdedit.*recoveryenabled", I), 4, "Shadow-copy deletion", "Deleting volume shadow copies removes recovery points and typically precedes ransomware.", "T1490"),
 (re.compile(r"lsass.*(procdump|comsvcs|minidump|\.dmp)|procdump.*lsass|sekurlsa|mimikatz", I), 4, "Credential dumping (LSASS)", "Dumping LSASS memory exposes credentials for lateral movement.", "T1003.001"),
 (re.compile(r"ransom|\.locked\b|\.encrypted\b|README_DECRYPT", I), 4, "Encryption for impact", "Mass file renaming or ransom-note artefacts indicate data encryption.", "T1486"),
 (re.compile(r"powershell.*(-enc|-nop|bypass|downloadstring)|FromBase64String", I), 4, "Suspicious PowerShell command", "Encoded or policy-bypassing PowerShell is widely used for payload staging and obfuscation.", "T1059.001"),
 (re.compile(r"certutil.*-urlcache|bitsadmin.*/transfer|(wget|curl)\s[^|]*\|\s*(ba)?sh|\bnc(\.exe)?\s+-e", I), 4, "Suspicious download / reverse shell", "Command pattern used to fetch tooling or open a remote shell.", "T1105"),
 (re.compile(r"Set-MpPreference.*Disable|DisableRealtimeMonitoring|sc\s+stop\s+WinDefend", I), 4, "Security tooling disabled", "Disabling endpoint protection is a defence-evasion step.", "T1562.001"),
 (re.compile(r"psexec|PSEXESVC|wmic\s+/node|winrs\b", I), 3, "Remote execution", "Remote command execution tools support lateral movement.", "T1021.002"),
 (re.compile(E + r"4720|net\s+user\s+\S+\s+.*/add|useradd", I), 3, "Account creation", "New accounts can indicate persistence if not tied to an approved change.", "T1136.001"),
 (re.compile(E + r"(4728|4732|4756)|net\s+localgroup\s+administrators", I), 3, "Privileged group change", "Adding accounts to privileged groups expands attacker access.", "T1098"),
 (re.compile(r"wuauserv|Windows Update|scheduled patching", I), 0, "Allow-listed patching activity", "Known scheduled patching; allow-listed to reduce false positives.", ""),
 (re.compile(E + r"7045|service installed|sc\s+create", I), 3, "New service installed", "Service creation is a typical persistence technique (also used by legitimate patching).", "T1543.003"),
 (re.compile(E + r"4698|schtasks\s+/create|crontab\s+-", I), 3, "Scheduled task / persistence", "Scheduled tasks are a common persistence mechanism.", "T1053.005"),
 (re.compile(r"\b(7z|rar|zip)\b.*\s-p\S*|\bgpg\s+-c", I), 3, "Password-protected archive", "Encrypted archives are commonly used to stage data for exfiltration.", "T1560.001"),
 (re.compile(r"LogonType\W{0,3}10\b|logon type:?\s*10\b", I), 2, "Remote desktop logon", "Interactive remote logon; significant when it follows failed attempts from an external address.", "T1021.001"),
 (re.compile(r"sudo|su: |" + E + r"4672", I), 2, "Privilege use", "Elevated privileges were used; correlate with the account and time.", "T1548"),
 (re.compile(E + r"5145", I), 1, "Network share access", "Single accesses are normal; bulk access is evaluated separately.", "T1039"),
 (re.compile(r"Failed password|authentication failure|" + E + r"4625", I), 1, "Failed logon", "Low risk alone; evaluated for bursts per source address.", "T1110"),
 (re.compile(r"Accepted (password|publickey)|" + E + r"4624", I), 0, "Successful logon", "Baseline authentication used for correlation with failures.", "T1078"),
]
EXTRA = {"Brute-force pattern": "T1110", "Successful logon after brute force": "T1078", "Bulk share access": "T1039", "Port-scan behaviour": "T1046",
         "Large outbound transfer": "T1048", "Lateral movement (SMB fan-out)": "T1021.002", "Activity outside business hours": "", "Extension / signature mismatch": "T1036", "High-entropy content": "T1027"}
T2A = {r[2]: r[4] for r in RULES}; T2A.update(EXTRA)
mitre = lambda title: T2A.get(title) or "-"
IPR, URLR, MAILR = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), re.compile(r"https?://[^\s\"'<>]+"), re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")

def pts(l):
    m = re.search(r"(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})", l)
    if m: return int(datetime.fromisoformat(m[1] + "T" + m[2]).replace(tzinfo=timezone.utc).timestamp() * 1000)
    m = re.match(r"([A-Z][a-z]{2})\s+(\d+)\s(\d\d:\d\d:\d\d)", l)
    try: return int(datetime.strptime("%s %s 2026 %s" % m.groups(), "%b %d %Y %H:%M:%S").replace(tzinfo=timezone.utc).timestamp() * 1000) if m else None
    except ValueError: return None

def extract(ln):
    m = lambda p: (re.search(p, ln, I) or [None, None])[1]
    parts = ln.split(); host = m(r"host=(\S+)") or (parts[1] if len(parts) > 1 and re.match(r"^[A-Za-z][\w-]*$", parts[1]) else None)
    return dict(host=host, usr=m(r"user=(\S+)") or m(r"for (?:invalid user )?(\w+) from"), eid=int(m(r"Event ?ID\W{0,4}(\d+)") or 0),
                proc=m(r"proc=(\S+)") or m(r"\b(powershell|wget|useradd|sudo|certutil|mimikatz|schtasks|cmd|nc|vssadmin|psexec|7z|procdump)(?:\.exe)?\b") or m(r"(\w+)\[\d+\]"),
                ip=(IPR.search(ln) or [None])[0])

def _ioc(s, ioc):
    for t, r in (("IPv4", IPR), ("URL", URLR), ("Email", MAILR)):
        for x in r.findall(s): ioc[t + "|" + x] += 1

def parse_text(name, data):
    tl, fd, ioc = [], [], defaultdict(int); hits = defaultdict(list); fails = defaultdict(list); fidx = defaultdict(list); ok = {}; shares = defaultdict(list)
    for i, ln in enumerate(data.decode("utf-8", "replace").splitlines(), 1):
        if not ln.strip(): continue
        _ioc(ln, ioc); ts = pts(ln); r = next((x for x in RULES if x[0].search(ln)), None); ex = extract(ln)
        if not r:
            if ts is not None: tl.append(dict(ts=ts, type="Event", detail=ln[:220], sev=0, line=i, attck="", **ex))
            continue
        tl.append(dict(ts=ts, type=r[2], detail=ln[:220], sev=r[1], line=i, attck=r[4], **ex))
        if r[1] >= 2: hits[r[2]].append((i, ts, r))
        if r[2] == "Failed logon": fails[ex["ip"]].append(ts); fidx[ex["ip"]].append(len(tl) - 1)
        if r[2] == "Successful logon": ok[ex["ip"]] = ts
        if r[2] == "Network share access" and ts is not None: shares[ex["usr"]].append((ts, len(tl) - 1))
    for title, h in hits.items():
        r = h[0][2]; fd.append(dict(sev=r[1], t=title, w="%s (%d event(s); first at line %d)" % (r[3], len(h), h[0][0]), ts=h[0][1]))
    for ip, ts in fails.items():
        if ip and len(ts) >= 5:
            for k in fidx[ip]: tl[k].update(sev=3, type="Brute-force pattern", attck="T1110")
            fd.append(dict(sev=3, t="Brute-force pattern", w="%d failed logons from %s exceed the burst threshold of 5." % (len(ts), ip), ts=ts[0]))
            if ip in ok: fd.append(dict(sev=4, t="Successful logon after brute force", w="%s authenticated successfully after repeated failures, consistent with credential compromise." % ip, ts=ok[ip]))
    for u, ts in shares.items():
        ts.sort()
        for a in range(len(ts)):
            b = a
            while b < len(ts) and ts[b][0] - ts[a][0] <= 600000: b += 1
            if b - a >= 30:
                for _, k in ts[a:b]: tl[k].update(sev=3, type="Bulk share access", attck="T1039")
                fd.append(dict(sev=3, t="Bulk share access", w="%d share accesses by %s within 10 minutes, a possible data-collection pattern." % (b - a, u), ts=ts[a][0])); break
    off = sum(1 for t in tl if t["sev"] >= 2 and t["ts"] is not None and datetime.fromtimestamp(t["ts"] / 1000, timezone.utc).hour < 5)
    if off: fd.append(dict(sev=2, t="Activity outside business hours", w="%d elevated-risk event(s) between 00:00 and 05:00 UTC." % off, ts=None))
    return dict(tl=tl, fd=fd, ioc=dict(ioc))

def parse_zeek(name, data):
    cols, conns, ioc = [], [], defaultdict(int)
    for i, ln in enumerate(data.decode("utf-8", "replace").splitlines(), 1):
        if ln.startswith("#fields"): cols = ln.split("\t")[1:]
        elif ln and not ln.startswith("#") and cols:
            d = dict(zip(cols, ln.split("\t")))
            try: conns.append((i, int(float(d["ts"]) * 1000), d["id.orig_h"], d["id.resp_h"], int(d["id.resp_p"]), d.get("proto", ""), d.get("service", "-"), int(d["orig_bytes"]) if d.get("orig_bytes", "-") != "-" else 0, int(d["resp_bytes"]) if d.get("resp_bytes", "-") != "-" else 0, d.get("conn_state", "")))
            except (KeyError, ValueError): pass
    priv = lambda a: a.startswith(("10.", "192.168.")) or (a.startswith("172.") and 16 <= int(a.split(".")[1]) <= 31)
    ports = defaultdict(set); vol = defaultdict(int); rdp = Counter(); smb = defaultdict(set)
    for _, ts, s, d, p, *_r in conns:
        ports[s].add((d, p)); vol[(s, d)] += _r[2]
        if p in (3389, 22): rdp[(s, d, p)] += 1
        if p == 445 and priv(s) and priv(d): smb[s].add(d)
    mark = {}; fd = []
    for (s, d, p), n in rdp.items():
        if n >= 10 and not priv(s): mark[("rdp", s, d, p)] = (3, "Brute-force pattern", "T1110"); fd.append(dict(sev=3, t="Brute-force pattern", w="%d connections from external %s to %s:%d, consistent with remote-service password guessing." % (n, s, d, p), ts=min(c[1] for c in conns if c[2] == s and c[3] == d)))
    for s, pp in ports.items():
        if len(pp) >= 15: fd.append(dict(sev=3, t="Port-scan behaviour", w="%s contacted %d distinct host:port pairs, consistent with reconnaissance." % (s, len(pp)), ts=None)); mark[("scan", s)] = (3, "Port-scan behaviour", "T1046")
    for (s, d), b in vol.items():
        if b > 1e6 and priv(s) and not priv(d): fd.append(dict(sev=3, t="Large outbound transfer", w="%s sent %.1f MB to external %s, which may indicate exfiltration and needs content review." % (s, b / 1e6, d), ts=None)); mark[("vol", s, d)] = (3, "Large outbound transfer", "T1048")
    for s, ds in smb.items():
        if len(ds) >= 3: fd.append(dict(sev=3, t="Lateral movement (SMB fan-out)", w="%s connected over SMB to %d internal hosts." % (s, len(ds)), ts=None)); mark[("smb", s)] = (3, "Lateral movement (SMB fan-out)", "T1021.002")
    tl = []
    for i, ts, s, d, p, pr, sv, ob, rb, st in conns:
        m = mark.get(("rdp", s, d, p)) or mark.get(("scan", s)) or mark.get(("vol", s, d)) or (mark.get(("smb", s)) if p == 445 else None)
        _ioc(s + " " + d, ioc)
        tl.append(dict(ts=ts, type=m[1] if m else "Network connection", detail="%s -> %s:%d/%s %s orig_bytes=%d resp_bytes=%d state=%s" % (s, d, p, pr, sv, ob, rb, st), sev=m[0] if m else 0, line=i, attck=m[2] if m else "", host=s, usr=None, eid=0, proc="zeek", ip=s, nbytes=ob))
    return dict(tl=tl, fd=fd, ioc=dict(ioc))

def parse_evtx(name, data):
    try:
        from Evtx.Evtx import Evtx
    except ImportError: return None
    f = tempfile.NamedTemporaryFile(delete=False, suffix=".evtx"); f.write(data); f.close(); lines = []
    try:
        with Evtx(f.name) as log:
            for rec in log.records():
                x = rec.xml(); g = lambda p: (re.search(p, x) or [None, ""])[1]; kv = dict(re.findall(r'<Data Name="(\w+)">([^<]*)', x))
                lines.append('%s %s EventID %s user=%s proc=%s cmd="%s" LogonType=%s %s' % (g(r'SystemTime="([^"]+)"').replace(" ", "T")[:19], g(r"<Computer>([^<]+)"), g(r"<EventID[^>]*>(\d+)"), kv.get("SubjectUserName") or kv.get("TargetUserName") or "-", os.path.basename((kv.get("NewProcessName") or kv.get("Image") or "-").replace("\\", "/")), kv.get("CommandLine", ""), kv.get("LogonType", ""), kv.get("ServiceName", "")))
    except Exception: return None
    finally: os.unlink(f.name)
    return parse_text(name, "\n".join(lines).encode())

def analyze_bytes(name, data):
    data = data[:50 << 20]
    if data[:7] == b"ElfFile": return parse_evtx(name, data)
    if b"\x00" in data[:4096] or not data: return None
    return parse_zeek(name, data) if b"#fields" in data[:3000] else parse_text(name, data)

def shan(s):
    c = Counter(s); n = len(s) or 1
    return -sum(v / n * math.log2(v / n) for v in c.values())

def enrich(st):
    sha, rows = {e["name"]: e["sha"] for e in st["ev"]}, []
    for t in sorted(st["tl"], key=lambda t: (t["ts"] is None, t["ts"] or 0, t["file"], str(t["line"]), t["type"])):
        d = t["detail"]; x = extract(d)
        rows.append(dict(t=t, eid=t.get("eid") or x["eid"], proc=t.get("proc") or x["proc"] or "n/a", host=t.get("host") or x["host"], usr=t.get("usr") or x["usr"], ip=t.get("ip") or x["ip"], size=len(d.encode()), nb=t.get("nbytes") or 0, sha=sha.get(t["file"], ""), lead=None, burst=1))
    N = len(rows) or 1; pc = Counter(r["proc"] for r in rows); cnt = Counter((r["t"]["file"], r["proc"], r["t"]["type"]) for r in rows); by = defaultdict(list)
    for i, r in enumerate(rows):
        r["count"] = cnt[(r["t"]["file"], r["proc"], r["t"]["type"])]
        if r["t"]["ts"] is not None: by[r["host"] or r["ip"] or r["t"]["file"]].append(i)
    for idx in by.values():
        j = 0
        for k, i in enumerate(idx):
            while rows[i]["t"]["ts"] - rows[idx[j]]["t"]["ts"] > 60000: j += 1
            rows[i]["burst"] = k - j + 1
    for r in rows:
        d = r["t"]["detail"]; ts = r["t"]["ts"]; r["ent"] = shan(d); r["off"] = int(ts is not None and not 5 <= datetime.fromtimestamp(ts / 1000, timezone.utc).hour < 20); r["rare"] = 1 - pc[r["proc"]] / N
    X = [[r["eid"], r["count"], r["size"], r["t"]["sev"], r["off"], r["ent"], len(r["t"]["detail"]), r["rare"], r["burst"], math.log1p(r["nb"])] for r in rows]
    model = "Rule-based fallback (fewer than 8 events)"; pred = [-1 if r["t"]["sev"] >= 3 else 1 for r in rows]; raw = [r["t"]["sev"] for r in rows]
    if len(rows) >= 8:
        try:
            from sklearn.ensemble import IsolationForest
            c = IsolationForest(contamination=0.1, random_state=42).fit(X); pred = list(c.predict(X)); raw = list(-c.decision_function(X))
            model = "Isolation Forest (scikit-learn, contamination=0.1, random_state=42; 10 features: EventID, execution count, payload size, rule severity, off-hours, command entropy, command length, process rarity, 60 s burst, outbound volume)"
        except ImportError: model = "Rule-based fallback (scikit-learn not installed)"
    lo, hi = min(raw or [0]), max(raw or [1]); me = sum(r["ent"] for r in rows) / N; sd = (sum((r["ent"] - me) ** 2 for r in rows) / N) ** .5 or 1
    for r, p, s in zip(rows, pred, raw):
        v = r["t"]["sev"]; r["score"] = int(p); r["risk"] = round(.5 * (s - lo) / ((hi - lo) or 1) + .5 * v / 4, 4)
        r["pri"] = "CRITICAL / ANOMALY" if p == -1 and v >= 3 else "ANOMALY" if p == -1 else "HIGH (RULE)" if v >= 3 else "NORMAL"
        w = []
        if v >= 2: w.append("%s (%s)" % (r["t"]["type"], r["t"].get("attck") or mitre(r["t"]["type"])))
        if pc[r["proc"]] <= max(2, .02 * N) and r["proc"] != "n/a": w.append("'%s' is rarely seen (%d of %d events)" % (r["proc"], pc[r["proc"]], N))
        if r["ent"] > me + 2 * sd: w.append("unusually high-entropy command line")
        if r["off"]: w.append("outside business hours (05:00-20:00 UTC)")
        if r["burst"] >= 10: w.append("burst of %d events within 60 s" % r["burst"])
        if r["nb"] > 1e6: w.append("large outbound volume (%.1f MB)" % (r["nb"] / 1e6))
        r["why"] = w
    return rows, model

def leads(rows):
    L = []
    for r in rows:
        ts = r["t"]["ts"]
        if ts is None or not (r["t"]["sev"] >= 2 or (r["score"] == -1 and r["risk"] >= .55)): continue
        ents = {v for v in (r["host"], r["ip"], r["usr"]) if v and v not in ("SYSTEM", "n/a", "-")}
        hit = [l for l in L if l["ents"] & ents and ts - l["end"] <= 1800000]
        if hit:
            l = hit[0]
            for o in hit[1:]: l["rows"] += o["rows"]; l["ents"] |= o["ents"]; l["end"] = max(l["end"], o["end"]); L.remove(o)
        else: l = dict(rows=[], ents=set(), start=ts, end=ts); L.append(l)
        l["rows"].append(r); l["ents"] |= ents; l["end"] = max(l["end"], ts)
    out = []
    for l in L:
        R = l["rows"]; sm = max(r["t"]["sev"] for r in R); tech = sorted({r["t"].get("attck") or mitre(r["t"]["type"]) for r in R} - {"-", ""})
        pri = "P1" if (sm == 4 and (len(tech) >= 2 or len(R) >= 5)) or len(tech) >= 3 else "P2" if sm >= 3 else "P3" if sm == 2 else "P4"
        why = list(dict.fromkeys(w for r in R for w in r["why"]))[:6]
        out.append(dict(pri=pri, score=round(sum(r["risk"] for r in R), 2), start=l["start"], end=l["end"], n=len(R), techniques=tech, entities=sorted(l["ents"]), reasons=why,
                        refs=["%s:L%s" % (r["t"]["file"], r["t"]["line"]) for r in R[:5]], sevmax=sm, rows=R))
    out.sort(key=lambda l: (l["pri"], -l["score"]))
    for k, l in enumerate(out, 1):
        l["id"] = "L-%02d" % k
        for r in l.pop("rows"): r["lead"] = l["id"]
    return out

def digest(st, rows):
    core = {"ev": sorted((e["name"], e["sha"]) for e in st["ev"]), "fd": sorted((f["file"], f["sev"], f["t"], f["w"], f.get("ts")) for f in st["fd"]),
            "rows": [(r["t"]["ts"], r["t"]["file"], r["t"]["type"], r["eid"], r["proc"], r["count"], r["size"], r["score"], r["pri"]) for r in rows]}
    return hashlib.sha256(json.dumps(core, sort_keys=True, default=str).encode()).hexdigest()