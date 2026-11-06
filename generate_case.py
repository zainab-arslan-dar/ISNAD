"""Synthetic case with hidden ground truth: ~10 users, 11 hosts, 3 days, 3 hidden attacks.
Writes security.log + conn.log (evidence) and ground_truth.csv (labels, never shown to the engine)."""
import csv, os, random
from datetime import datetime, timezone, timedelta

H = ["DC01", "FS01", "MAIL01"] + ["WS0%d" % i for i in range(1, 9)]
U = "alice bob carol dave erin frank grace heidi ivan judy".split()
IPS = {h: "10.0.0.%d" % (10 + i) for i, h in enumerate(H)}
PROCS = ["explorer.exe", "chrome.exe", "outlook.exe", "winword.exe", "excel.exe", "teams.exe", "notepad.exe"]

def make(out, seed=7):
    R = random.Random(seed); os.makedirs(out, exist_ok=True); sec, zk = [], []
    t0 = datetime(2026, 11, 2, tzinfo=timezone.utc); S = lambda d, h, m=0, s=0: t0 + timedelta(days=d, hours=h, minutes=m, seconds=s)
    iso = lambda t: t.strftime("%Y-%m-%dT%H:%M:%SZ")
    ev = lambda t, h, eid, u, proc, msg, mal=None, extra="": sec.append((t, "%s %s EventID %d user=%s proc=%s %s%s" % (iso(t), h, eid, u, proc, msg, extra), mal))
    for d in range(3):
        for i, u in enumerate(U):
            h = "WS0%d" % (i % 8 + 1); ev(S(d, 8, R.randint(0, 90)), h, 4624, u, "explorer.exe", "Successful logon", extra=" LogonType=2")
            for _ in range(R.randint(25, 40)): ev(S(d, 9, R.randint(0, 520), R.randint(0, 59)), h, 4688, u, R.choice(PROCS), "Process created")
            for _ in range(R.randint(3, 6)): ev(S(d, 10, R.randint(0, 400)), "FS01", 5145, u, "System", "Network share access \\\\FS01\\docs")
            c = S(d, 9, R.randint(0, 500))
            for _ in range(R.randint(30, 50)): zk.append((c + timedelta(seconds=R.randint(0, 3000)), IPS[h], R.choice(["10.0.0.11", "10.0.0.12", "8.8.8.8"]), R.choice([53, 80, 443, 445]), R.randint(200, 9000), R.randint(500, 40000), "SF", None))
        for h in R.sample(H, 3): ev(S(d, 2, R.randint(0, 40)), h, 7045, "SYSTEM", "services.exe", "Service installed wuauserv Windows Update (scheduled patching)")
    A = "203.0.113.77"; w5 = IPS["WS05"]  # ransomware via exposed RDP host WS05
    for k in range(45): zk.append((S(2, 1, 0, k * 2), A, w5, 3389, 100, 0, "S0", "ransomware"))
    ev(S(2, 1, 5), "WS05", 4624, "admin", "winlogon.exe", "Successful logon", "ransomware", " LogonType=10 from %s" % A)
    for k, (p, m) in enumerate([("powershell.exe", 'cmd="powershell -nop -enc SQBFAFgA"'), ("vssadmin.exe", "cmd=\"vssadmin delete shadows /all /quiet\""), ("cipher.exe", "cmd=\"cipher /w:C:\"")]): ev(S(2, 1, 6 + k), "WS05", 4688, "admin", p, "Process created " + m, "ransomware")
    for k in range(40): ev(S(2, 1, 10, k), "WS05", 4688, "admin", "enc.exe", "FileRename report%d.docx.locked" % k, "ransomware")
    ev(S(2, 1, 12), "WS05", 4688, "admin", "enc.exe", "README_DECRYPT.txt created", "ransomware")
    for k in range(60): ev(S(1, 21, 20, k * 5), "WS02", 5145, "bob", "System", "Network share access \\\\FS01\\finance\\file%d.xlsx" % k, "insider")  # insider theft
    ev(S(1, 21, 30), "WS02", 4688, "bob", "7z.exe", 'Process created cmd="7z a -pS3cret finance.7z \\\\FS01\\finance"', "insider")
    for k in range(3): zk.append((S(1, 21, 40 + k), IPS["WS02"], "198.51.100.20", 443, 200_000_000, 4000, "SF", "insider"))
    ev(S(2, 3, 0), "WS03", 4688, "carol", "procdump.exe", 'Process created cmd="procdump -ma lsass.exe lsass.dmp"', "lateral")  # lateral movement
    for k, h in enumerate(["FS01", "DC01"]):
        ev(S(2, 3, 2 + k), "WS03", 4688, "carol", "psexec.exe", 'Process created cmd="psexec \\\\%s cmd"' % h, "lateral"); ev(S(2, 3, 3 + k), h, 4624, "carol", "svchost.exe", "Successful logon", "lateral", " LogonType=3 from %s" % IPS["WS03"])
        for _ in range(3): zk.append((S(2, 3, 2 + k, _), IPS["WS03"], IPS[h], 445, 3000, 9000, "SF", "lateral"))
    for h in ("MAIL01",): zk.append((S(2, 3, 5), IPS["WS03"], IPS[h], 445, 3000, 9000, "SF", "lateral"))
    sec.sort(key=lambda x: x[0]); zk.sort(key=lambda x: x[0]); truth = []
    with open(os.path.join(out, "security.log"), "w") as f:
        for i, (_, line, mal) in enumerate(sec, 1):
            f.write(line + "\n")
            if mal: truth.append(("security.log", i, mal))
    hdr = ["#separator \\x09", "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state"]
    with open(os.path.join(out, "conn.log"), "w") as f:
        f.write("\n".join(hdr) + "\n")
        for i, (t, s, d, p, ob, rb, st, mal) in enumerate(zk, 3):
            f.write("%.6f\tC%d\t%s\t%d\t%s\t%d\ttcp\t-\t0.1\t%d\t%d\t%s\n" % (t.timestamp(), i, s, 40000 + i % 2000, d, p, ob, rb, st))
            if mal: truth.append(("conn.log", i, mal))
    with open(os.path.join(out, "ground_truth.csv"), "w", newline="") as f:
        w = csv.writer(f); w.writerow(["file", "line", "scenario"]); w.writerows(truth)
    return len(sec) + len(zk), len(truth)

if __name__ == "__main__": print(make(os.path.join(os.path.dirname(os.path.abspath(__file__)), "samples", "synthetic_case")))