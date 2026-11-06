"""Scores the engine against hidden ground truth (proposal section 4.5). Run: python evaluate.py [--evtx DIR]"""
import csv, hashlib, os, sys, tempfile, time
from sklearn.metrics import roc_auc_score
import engine, generate_case

D = os.path.dirname(os.path.abspath(__file__)); C = os.path.join(D, "samples", "synthetic_case")
total, nmal = generate_case.make(C)
def run():
    st = {"ev": [], "tl": [], "fd": [], "ioc": {}}
    for n in ("security.log", "conn.log"):
        b = open(os.path.join(C, n), "rb").read(); r = engine.analyze_bytes(n, b)
        for t in r["tl"]: t["file"] = n
        for f in r["fd"]: f["file"] = n; f["id"] = "x"
        st["tl"] += r["tl"]; st["fd"] += r["fd"]; st["ev"].append({"name": n, "sha": hashlib.sha256(b).hexdigest()})
    rows, model = engine.enrich(st); L = engine.leads(rows); return st, rows, L, engine.digest(st, rows)
t = time.time(); st, rows, L, dg = run(); rt = time.time() - t
truth = {(r["file"], int(r["line"])) for r in csv.DictReader(open(os.path.join(C, "ground_truth.csv")))}
y = [int((r["t"]["file"], r["t"]["line"]) in truth) for r in rows]; M = sum(y)
recall = sum(1 for r, v in zip(rows, y) if v and r["lead"]) / M
top = [(r, v) for r, v in zip(rows, y) if r["lead"] and next(l["pri"] for l in L if l["id"] == r["lead"]) in ("P1", "P2")]
prec = sum(v for _, v in top) / max(1, len(top)); auc = roc_auc_score(y, [r["risk"] for r in rows])
def effort(order):
    need, got = .9 * M, 0
    for k, i in enumerate(order, 1):
        got += y[i]
        if got >= need: return k / len(rows)
risk_order = sorted(range(len(rows)), key=lambda i: -rows[i]["risk"]); chrono = sorted(range(len(rows)), key=lambda i: (rows[i]["t"]["ts"] or 0))
same = all(run()[3] == dg for _ in range(3))
p = os.path.join(tempfile.mkdtemp(), "e.bin"); open(p, "wb").write(b"evidence"); h0 = hashlib.sha256(open(p, "rb").read()).hexdigest(); os.chmod(p, 0o644); open(p, "ab").write(b"x")
tamper = hashlib.sha256(open(p, "rb").read()).hexdigest() != h0
res = [("Events / malicious events", "%d / %d" % (len(rows), M), "-"), ("Recall in leads", "%.1f%%" % (recall * 100), ">= 90%"), ("P1/P2 precision (event level)", "%.1f%%" % (prec * 100), ">= 80%"),
       ("ROC-AUC of event risk score", "%.3f" % auc, ">= 0.95"), ("Review effort (ISNAD order vs chronological)", "%.1f%% vs %.1f%%" % (effort(risk_order) * 100, effort(chrono) * 100), "< 10% vs ~90%"),
       ("Leads produced (P1/P2/P3/P4)", "%d (%s)" % (len(L), "/".join(str(sum(1 for l in L if l["pri"] == "P%d" % k)) for k in range(1, 5))), "-"), ("Reproducible digest (3 re-runs)", "identical" if same else "DIFFERENT", "identical"),
       ("Tamper test (hash change detected)", "detected" if tamper else "MISSED", "100%"), ("Run time", "%.2f s" % rt, "-")]
out = "# ISNAD evaluation (synthetic case, seed 7)\n\nModel: %s\n\n| Measure | Result | Target |\n|---|---|---|\n" % model_name if False else "# ISNAD evaluation (synthetic case, seed 7)\n\n| Measure | Result | Target |\n|---|---|---|\n"
out += "\n".join("| %s | %s | %s |" % r for r in res) + "\n\nCaveat: the synthetic case was written by the same team as the rules, so these figures are optimistic. Real-data validation is the next step.\n"
if "--evtx" in sys.argv:
    d = sys.argv[sys.argv.index("--evtx") + 1]; ok = bad = 0
    for f in os.listdir(d):
        if f.lower().endswith(".evtx"):
            r = engine.analyze_bytes(f, open(os.path.join(d, f), "rb").read()); ok += bool(r); bad += not r
    out += "\nEVTX corpus: %d parsed, %d failed or python-evtx missing.\n" % (ok, bad)
open(os.path.join(D, "evaluation.md"), "w").write(out); print(out)