# ISNAD: run guide
1. VS Code: File > Open Folder > ISNAD
2. Terminal: `python -m venv .venv` then activate (Windows: `.venv\Scripts\activate`), then `pip install -r requirements.txt`
3. `python server.py` -> open http://127.0.0.1:8000 (SIEM: button in header, or /siem)
4. Drop evidence from `samples/` (see below) or click "Load demo case".
5. Evaluation for the proposal: `python evaluate.py` (writes evaluation.md). Regenerate data: `python generate_case.py`.
Evidence files are copied into data/evidence/ (read-only) and re-hashed before every analysis. Database: data/isnad.db. Delete data/ to reset.