"""ISNAD backend (Python 3) - Vercel Serverless Function Wrapper"""
import sys, os, csv, hashlib, io, json, queue, re, sqlite3, threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from xml.sax.saxutils import escape as xe

# Ensure root directory is in path so 'engine' can be imported
D = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(D)
sys.path.insert(0, ROOT_DIR)

from engine import mitre, enrich, digest, leads, analyze_bytes

# On Vercel, use /tmp for SQLite database since the root filesystem is read-only
IS_VERCEL = os.environ.get("VERCEL") == "1"
DB_DIR = os.path.join("/tmp", "data") if IS_VERCEL else os.path.join(ROOT_DIR, "data")
W, DB = os.path.join(ROOT_DIR, "web"), os.path.join(DB_DIR, "isnad.db")
ENGINE, SV = "ISNAD-PoC 0.3", ["Info", "Low", "Medium", "High", "Critical"]
lock, subs = threading.Lock(), []
SCHEMA = """CREATE TABLE IF NOT EXISTS evidence(name TEXT,size INT,mod INT,sha TEXT,scope TEXT,ent REAL,kind TEXT,sc INT,pr TEXT);
CREATE TABLE IF NOT EXISTS events(ts INT,file TEXT,type TEXT,detail TEXT,sev INT,line TEXT,eid INT,proc TEXT,host TEXT,usr TEXT,ip TEXT,attck TEXT,nbytes INT);
CREATE TABLE IF NOT EXISTS vault(sha TEXT PRIMARY KEY,name TEXT,path TEXT,size INT);
CREATE TABLE IF NOT EXISTS findings(id TEXT,file TEXT,sev INT,t TEXT,w TEXT,ts INT);
CREATE TABLE IF NOT EXISTS iocs(k TEXT,v INT);
CREATE TABLE IF NOT EXISTS decisions(fid TEXT,file TEXT,decision TEXT,examiner TEXT,ts TEXT,PRIMARY KEY(fid,file));
CREATE TABLE IF NOT EXISTS ledger(n INTEGER PRIMARY KEY AUTOINCREMENT,ts TEXT,action TEXT,detail TEXT,prev TEXT,hash TEXT);"""
now = lambda: datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
fmt = lambda ts: datetime.fromtimestamp(ts / 1000, timezone.utc).strftime("%d/%m/%Y %H:%M:%S") if ts else ""

def db():
    os.makedirs(DB_DIR, exist_ok=True)
    c = sqlite3.connect(DB); c.row_factory = sqlite3.Row; c.executescript(SCHEMA); return c

def load(c):
    q = lambda t: [dict(r) for r in c.execute("SELECT * FROM " + t + " ORDER BY rowid")]
    st = {"ev": q("evidence"), "tl": q("events"), "fd": q("findings"), "ioc": {r["k"]: r["v"] for r in c.execute("SELECT * FROM iocs")}}
    st["dec"] = {d["fid"] + "|" + d["file"]: d for d in q("decisions")}
    return st

def put(c, s):
    for t in ("evidence", "events", "findings", "iocs"): c.execute("DELETE FROM " + t)
    c.executemany("INSERT INTO evidence VALUES(?,?,?,?,?,?,?,?,?)", [(e["name"], e["size"], e["mod"], e["sha"], e["scope"], e["ent"], e["kind"], e.get("sc", 0), e.get("pr", "P4")) for e in s["ev"]])
    c.executemany("INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)", [(t.get("ts"), t["file"], t["type"], t["detail"], t["sev"], str(t.get("line", "-")), t.get("eid"), t.get("proc"), t.get("host"), t.get("usr"), t.get("ip"), t.get("attck"), t.get("nbytes")) for t in s["tl"]])
    c.executemany("INSERT INTO findings VALUES(?,?,?,?,?,?)", [(f["id"], f["file"], f["sev"], f["t"], f.get("w", ""), f.get("ts")) for f in s["fd"]])
    c.executemany("INSERT INTO iocs VALUES(?,?)", list(s["ioc"].items()))

VAULT = os.path.join(DB_DIR, "evidence")
def file_sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""): h.update(b)
    return h.hexdigest()
def vault_store(c, name, data):
    sha = hashlib.sha256(data).hexdigest(); os.makedirs(VAULT, exist_ok=True); p = os.path.join(VAULT, sha[:16] + "_" + re.sub(r"[^\w.-]", "_", name))
    new = not c.execute("SELECT 1 FROM vault WHERE sha=?", (sha,)).fetchone()
    if not os.path.exists(p):
        with open(p, "wb") as f: f.write(data)
        try: os.chmod(p, 0o444)
        except Exception: pass
    c.execute("INSERT OR IGNORE INTO vault VALUES(?,?,?,?)", (sha, name, p, len(data))); return sha, new
def vault_check(c): return [r["name"] for r in c.execute("SELECT * FROM vault") if not os.path.exists(r["path"]) or file_sha(r["path"]) != r["sha"]]
def full(st):
    rows, model = enrich(st); st = dict(st); st["leads"] = leads(rows); st["model"] = model; return st

def ledger(c, action, detail):
    r = c.execute("SELECT hash FROM ledger ORDER BY n DESC LIMIT 1").fetchone(); prev = r[0] if r else "GENESIS"; ts = now()
    c.execute("INSERT INTO ledger(ts,action,detail,prev,hash) VALUES(?,?,?,?,?)", (ts, action, detail, prev, hashlib.sha256((prev + ts + action + detail).encode()).hexdigest()))

def verify(c):
    prev, rows = "GENESIS", [dict(r) for r in c.execute("SELECT * FROM ledger ORDER BY n")]
    for r in rows:
        if r["prev"] != prev or hashlib.sha256((prev + r["ts"] + r["action"] + r["detail"]).encode()).hexdigest() != r["hash"]: return rows, False, r["n"]
        prev = r["hash"]
    return rows, True, None

def csv_bytes(st):
    rows, _ = enrich(st); leads(rows); o = io.StringIO(); w = csv.writer(o)
    w.writerow(["Index", "Timestamp", "EventID", "ProcessName", "ExecutionCount", "PayloadSize", "EventDescription", "Anomaly_Score", "Triage_Priority", "Severity", "ATTCK_Technique", "Source_File", "Source_SHA256", "Source_Line", "Lead_ID", "Why_Flagged"])
    for i, r in enumerate(rows):
        t = r["t"]; w.writerow([i, fmt(t["ts"]), r["eid"], r["proc"], r["count"], r["size"], t["type"] + ": " + t["detail"], r["score"], r["pri"], SV[t["sev"]], mitre(t["type"]), t["file"], r["sha"], t["line"], r["lead"] or "", "; ".join(r["why"])])
    return o.getvalue().encode("utf-8-sig")

def pdf_bytes(st, case, exm, led, ok):
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Table, TableStyle, Spacer
    rows, model = enrich(st); dg = digest(st, rows); LD = leads(rows); ss = getSampleStyleSheet()
    b = ParagraphStyle("b", parent=ss["BodyText"], fontSize=9, leading=12); sm = ParagraphStyle("s", parent=b, fontSize=7, leading=9)
    h = ParagraphStyle("h", parent=ss["Heading2"], fontSize=12, textColor=colors.HexColor("#14365d"), spaceBefore=12)
    P = lambda t, s=b: Paragraph(t, s)
    def T(hd, data, w):
        d = [[P("<b>%s</b>" % x, sm) for x in hd]] + [[P(xe(str(c)).replace("\n", "<br/>"), sm) for c in r] for r in data]
        t = Table(d, colWidths=w, repeatRows=1); t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#dde6f0")), ("GRID", (0, 0), (-1, -1), .25, colors.grey), ("VALIGN", (0, 0), (-1, -1), "TOP")])); return t
    SUP = {"Brute-force pattern": "Failed logon", "Successful logon after brute force": "Successful logon"}
    def support(f):
        ty = SUP.get(f["t"], f["t"]); return "\n".join("L%s: %s" % (t["line"], t["detail"][:85]) for t in st["tl"] if t["file"] == f["file"] and t["type"] == ty)[:600] if False else "\n".join("L%s: %s" % (t["line"], t["detail"][:85]) for t in [t for t in st["tl"] if t["file"] == f["file"] and t["type"] == ty][:3])
    fd = sorted(st["fd"], key=lambda f: -f["sev"]); n = [sum(1 for f in fd if f["sev"] == i) for i in range(5)]
    S = [P("<b>DIGITAL FORENSIC TRIAGE REPORT</b>", ParagraphStyle("t", parent=b, fontSize=18, leading=22, textColor=colors.HexColor("#14365d"))),
         P("ISNAD: explainable AI evidence triage with a verifiable chain of custody"), Spacer(1, 8),
         T(["Field", "Value"], [["Case ID", case], ["Examiner", exm or "[to be completed]"], ["Generated (UTC)", now()], ["Engine / model", ENGINE + "; " + model],
             ["Results digest (SHA-256)", dg], ["Custody ledger", "%d entries, chain %s" % (len(led), "VERIFIED" if ok else "BROKEN")], ["Status", "PRELIMINARY: decision support only, pending examiner validation"]], [110, 413]),
         P("1. Scope and summary", h), P("%d evidence item(s) were hashed and analysed, producing %d normalised timeline events and %d findings (Critical %d, High %d, Medium %d, Low %d)." % (len(st["ev"]), len(rows), len(fd), n[4], n[3], n[2], n[1])),
         P("2. Evidence integrity", h), P("Each item was read without modification and hashed with SHA-256 at intake; the hash is recorded in the custody ledger (Appendix A). The system refuses analysis if a previously recorded item is presented with a different hash."),
         T(["Item", "Type", "Size (B)", "SHA-256", "Scope", "Priority"], [[e["name"], e["kind"], e["size"], e["sha"], e["scope"], e["pr"]] for e in st["ev"]], [80, 70, 45, 235, 48, 45]),
         P("3. Methodology", h), P("(a) File-signature identification and extension comparison; (b) Shannon entropy; (c) timestamp normalisation to UTC; (d) rule-based event classification mapped to MITRE ATT&amp;CK; (e) burst, scan and transfer detection; (f) signature carving; (g) indicator extraction; (h) unsupervised anomaly scoring: " + xe(model) + ". Anomaly_Score -1 marks a statistical outlier and 1 a typical event. Every finding records the rule that produced it so it can be reproduced and challenged."),
         P("3A. Ranked investigative leads (examiner review required)", h),
         T(["Lead", "Pri", "Entities", "Window (UTC)", "Events", "ATT&amp;CK", "Why flagged", "Examiner decision"],
            [[l["id"], l["pri"], ", ".join(l["entities"][:4]), fmt(l["start"]) + " to " + fmt(l["end"]), l["n"], ", ".join(l["techniques"]), "; ".join(l["reasons"]) + "\nRefs: " + ", ".join(l["refs"][:3]), (lambda d: d["decision"].upper() + " by " + d["examiner"] if d else "Awaiting review")(st["dec"].get(l["id"] + "|*lead*"))] for l in LD] or [["-"] * 8], [28, 24, 70, 78, 28, 60, 165, 70]),
         P("4. Findings with supporting records", h),  T(["ID", "Sev", "Finding / basis", "ATT&amp;CK", "Source", "Time (UTC)", "Supporting records", "Examiner decision"],
            [[f["id"], SV[f["sev"]], f["t"] + ": " + f["w"], mitre(f["t"]), f["file"], fmt(f.get("ts")), support(f), (lambda d: d["decision"].upper() + " by " + d["examiner"] if d else "Awaiting review")(st["dec"].get(f["id"] + "|" + f["file"]))] for f in fd], [26, 34, 150, 52, 52, 50, 104, 55]),
         P("5. Anomalous events (model output)", h),
         T(["Time (UTC)", "EventID", "Process", "Count", "Size", "Description", "Priority"], [[fmt(r["t"]["ts"]), r["eid"], r["proc"], r["count"], r["size"], r["t"]["type"] + ": " + r["t"]["detail"][:110], r["pri"]] for r in rows if r["score"] == -1][:60], [62, 38, 52, 30, 30, 240, 71]),
         P("6. Indicators of compromise", h), P(xe("; ".join(k.replace("|", ": ") for k in list(st["ioc"])[:40])) or "None extracted."),
         P("7. Limitations", h), P("Prototype scope: no filesystem mounting, EVTX or registry parsing, or recovery of deleted files from filesystem metadata; carved signatures are candidates only; files above 64 MB are analysed on their first 64 MB; the unsupervised model has not yet been validated against labelled ground truth. Indicators suggest but do not prove malicious activity; legitimate administration can look similar."),
         P("8. Conclusion (draft for examiner review)", h), P("Of %d item(s), %d Critical and %d High findings were recorded. %s These results support, and do not replace, examiner judgement and must be verified against the source records using validated tools before reliance." % (len(st["ev"]), n[4], n[3], "The indicators are consistent with unauthorised access and warrant priority examination of the highest-ranked items." if n[3] + n[4] else "No high-severity indicators were identified by the current rules.")),
         P("Appendix A. Chain-of-custody ledger", h), T(["#", "Time (UTC)", "Action", "Detail", "Entry hash"], [[r["n"], r["ts"], r["action"], r["detail"][:160], r["hash"][:24] + "..."] for r in led], [20, 62, 62, 300, 79]),
         P("Declaration", h), P("I confirm that I have reviewed the automated results in this report and that its contents are accurate to the best of my knowledge.<br/><br/>Name: ______________________ Signature: ______________________ Date: ____________")]
    def foot(cv, doc):
        cv.saveState(); cv.setFont("Helvetica", 7); cv.drawString(36, 20, "%s | ISNAD preliminary report: examiner validation required | digest %s" % (case, dg[:16])); cv.drawRightString(559, 20, "Page %d" % doc.page); cv.restoreState()
    o = io.BytesIO(); SimpleDocTemplate(o, pagesize=A4, leftMargin=36, rightMargin=36, topMargin=36, bottomMargin=36, title="ISNAD Report " + case).build(S, onFirstPage=foot, onLaterPages=foot); return o.getvalue()

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def reply(self, code, body, ct="application/json", extra=None):
        self.send_response(code); self.send_header("Content-Type", ct + ("; charset=utf-8" if ct.startswith("text") or ct == "application/json" else ""))
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items(): self.send_header(k, v)
        self.end_headers(); self.wfile.write(body)
    def page(self, f):
        try: self.reply(200, open(os.path.join(W, f), "rb").read(), "text/html")
        except FileNotFoundError: self.reply(404, b"missing " + f.encode(), "text/plain")
    def do_GET(self):
        u = urlparse(self.path); q = parse_qs(u.query); p = u.path
        if p == "/": return self.page("index.html")
        if p == "/siem": return self.page("siem.html")
        if p == "/events": return self.stream()
        with lock:
            c = db(); st = load(c)
            if p == "/api/state": return self.reply(200, json.dumps(full(st)).encode())
            if p == "/api/ledger": rows, ok, bad = verify(c); return self.reply(200, json.dumps({"rows": rows, "valid": ok, "bad": bad}).encode())
            if p == "/api/triage.csv":
                return self.reply(200, csv_bytes(st), "text/csv", {"Content-Disposition": 'attachment; filename="ISNAD_Triage_Report.csv"'})
            if p == "/api/report.pdf":
                if not st["ev"]: return self.reply(400, b'{"error":"no evidence loaded"}')
                case, exm = q.get("case", ["ISNAD-CASE"])[0], q.get("examiner", [""])[0]
                rows, _ = enrich(st); ledger(c, "REPORT_GENERATED", "case=%s examiner=%s digest=%s" % (case, exm, digest(st, rows))); c.commit()
                led, ok, _ = verify(c)
                return self.reply(200, pdf_bytes(st, case, exm, led, ok), "application/pdf", {"Content-Disposition": 'attachment; filename="ISNAD_Court_Report.pdf"'})
        self.reply(404, b"not found", "text/plain")
    def vault(self, name):
        data = self.rfile.read(int(self.headers["Content-Length"]))
        with lock:
            c = db(); sha, new = vault_store(c, name, data)
            if new: ledger(c, "VAULT", "%s stored read-only sha256=%s" % (name, sha))
            c.commit()
        res = analyze_bytes(name, data) or {}
        self.reply(200, json.dumps(dict(sha=sha, parsed=bool(res), **res)).encode())
    def do_POST(self):
        u = urlparse(self.path)
        if u.path == "/api/vault": return self.vault(parse_qs(u.query).get("name", ["file"])[0])
        try: body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        except Exception: return self.reply(400, b'{"error":"bad json"}')
        with lock:
            c = db()
            if self.path == "/api/decision":
                ledger(c, "DECISION", "%s %s -> %s by %s" % (body["fid"], body["file"], body["decision"], body["examiner"]))
                c.execute("INSERT OR REPLACE INTO decisions VALUES(?,?,?,?,?)", (body["fid"], body["file"], body["decision"], body["examiner"], now()))
                c.commit(); self.broadcast(load(c)); return self.reply(200, b'{"ok":true}')
            if self.path != "/api/state" or not all(k in body for k in ("ev", "tl", "fd", "ioc")): return self.reply(400, b'{"error":"bad state"}')
            old = {e["name"]: e["sha"] for e in c.execute("SELECT name,sha FROM evidence")}
            bad = sorted({e["name"] for e in body["ev"] if e["name"] in old and old[e["name"]] != e["sha"]})
            bad = bad or vault_check(c)
            if bad:
                ledger(c, "TAMPER_DETECTED", "analysis refused, hash mismatch: " + ", ".join(bad)); c.commit()
                return self.reply(409, json.dumps({"error": "TAMPER", "items": bad}).encode())
            for e in body["ev"]:
                if e["name"] not in old: ledger(c, "INTAKE", "%s size=%s sha256=%s scope=%s" % (e["name"], e["size"], e["sha"], e["scope"]))
            put(c, body); st = load(c); dg = ""
            if body["ev"]:
                rows, _ = enrich(st); dg = digest(st, rows)
                ledger(c, "ANALYSIS", "engine=%s evidence=%d events=%d digest=%s" % (ENGINE, len(st["ev"]), len(rows), dg))
            else: ledger(c, "CASE_CLEARED", "working state reset by examiner")
            c.commit(); self.broadcast(st)
        self.reply(200, json.dumps({"ok": True, "digest": dg}).encode())
    def broadcast(self, st):
        m = json.dumps(full(st))
        for q in subs: q.put(m)
    def stream(self):
        self.send_response(200); self.send_header("Content-Type", "text/event-stream"); self.send_header("Cache-Control", "no-cache"); self.end_headers()
        q = queue.Queue()
        with lock: subs.append(q)
        try:
            while True:
                try: self.wfile.write(("data: " + q.get(timeout=15) + "\n\n").encode())
                except queue.Empty: self.wfile.write(b": keepalive\n\n")
                self.wfile.flush()
        except OSError: pass
        finally:
            with lock:
                if q in subs: subs.remove(q)

# --- Vercel WSGI Adapter Entrypoint ---
def app(environ, start_response):
    path = environ.get('PATH_INFO', '')
    query = environ.get('QUERY_STRING', '')
    if query:
        path += '?' + query
    method = environ.get('REQUEST_METHOD', 'GET')
    content_length = int(environ.get('CONTENT_LENGTH') or 0)
    body = environ['wsgi.input'].read(content_length) if content_length > 0 else b''
    
    rfile = io.BytesIO(body)
    wfile = io.BytesIO()
    
    class DummyClient:
        def makefile(self, mode, *args, **kwargs):
            return rfile if 'r' in mode else wfile

    try:
        req_handler = H(DummyClient(), ('127.0.0.1', 80), None)
        req_handler.command = method
        req_handler.path = path
        req_handler.request_version = 'HTTP/1.1'
        req_handler.headers = {}
        
        for k, v in environ.items():
            if k.startswith('HTTP_'):
                req_handler.headers[k[5:].replace('_', '-').title()] = v
            elif k in ('CONTENT_TYPE', 'CONTENT_LENGTH'):
                req_handler.headers[k.replace('_', '-').title()] = v

        if method == 'GET':
            req_handler.do_GET()
        elif method == 'POST':
            req_handler.do_POST()
        else:
            req_handler.send_error(405, "Method Not Allowed")
            
        output = wfile.getvalue()
        header_data, response_body = output.split(b'\r\n\r\n', 1) if b'\r\n\r\n' in output else (b'', output)
        
        header_lines = header_data.decode('latin1').split('\r\n')
        status_line = header_lines[0] if header_lines else 'HTTP/1.1 200 OK'
        parts = status_line.split(' ', 2)
        status = f"{parts[1]} {parts[2]}" if len(parts) > 2 else "200 OK"
        
        headers = []
        for line in header_lines[1:]:
            if ':' in line:
                k, v = line.split(':', 1)
                headers.append((k.strip(), v.strip()))
                
        start_response(status, headers)
        return [response_body]
    except Exception as e:
        start_response('500 Internal Server Error', [('Content-Type', 'text/plain')])
        return [str(e).encode('utf-8')]

if __name__ == "__main__":
    os.makedirs(os.path.dirname(DB), exist_ok=True); db().close()
    print("ISNAD running at http://127.0.0.1:8000  (SIEM: /siem)")
    from http.server import ThreadingHTTPServer
    ThreadingHTTPServer(("127.0.0.1", 8000), H).serve_forever()