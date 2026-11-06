# ISNAD evaluation (synthetic case, seed 7)

| Measure | Result | Target |
|---|---|---|
| Events / malicious events | 2455 / 166 | - |
| Recall in leads | 98.2% | >= 90% |
| P1/P2 precision (event level) | 81.1% | >= 80% |
| ROC-AUC of event risk score | 0.996 | >= 0.95 |
| Review effort (ISNAD order vs chronological) | 7.5% vs 67.3% | < 10% vs ~90% |
| Leads produced (P1/P2/P3/P4) | 8 (2/6/0/0) | - |
| Reproducible digest (3 re-runs) | identical | identical |
| Tamper test (hash change detected) | detected | 100% |
| Run time | 1.17 s | - |

Caveat: the synthetic case was written by the same team as the rules, so these figures are optimistic. Real-data validation is the next step.
