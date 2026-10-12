# SentinelSC — AI Smart Contract Security Auditor

A local-first portfolio MVP for Solidity security review. It combines:
- Heuristic source-code checks for selected risky patterns.
- A small retrieval layer that surfaces relevant security guidance.
- Optional LLM explanations via an OpenAI-compatible API configuration.
- Streamlit UI with JSON and Markdown report downloads.
- Unit tests and vulnerable/secure sample contracts.

## Important scope note
This is a learning and portfolio project, not a production auditor. Regex-based checks can miss issues or flag safe code. It does not parse Solidity ASTs, compile contracts, execute tests, or prove exploitability. Findings must be validated manually. Do not use it as the sole basis for deploying a contract.

## Run locally
Python 3.10+ recommended.

```bash
python -m venv .venv
# Windows PowerShell:
.venv\Scripts\Activate.ps1
# macOS/Linux:
source .venv/bin/activate

pip install -r requirements.txt
streamlit run app.py
```

Open the local URL Streamlit prints, usually http://localhost:8501.

## Optional LLM explanations
1. Copy `.env.example` to `.env`.
2. Set `OPENAI_API_KEY` and optionally `OPENAI_MODEL`.
3. Export variables in your shell before launching Streamlit. The app intentionally does not automatically load `.env`; install `python-dotenv` and add `load_dotenv()` if you prefer that workflow.

PowerShell example:
```powershell
$env:OPENAI_API_KEY="your-key"
$env:OPENAI_MODEL="gpt-4o-mini"
streamlit run app.py
```

Without an API key, all deterministic checks and local retrieval still work.

## Run tests
```bash
pytest -q
```

## Project architecture
```text
Solidity source
   ├──> Heuristic checks (auditor.py)
   ├──> Retrieval of relevant guidance (rag.py)
   └──> Optional LLM explanation
              |
              v
       JSON / Markdown report + Streamlit UI
```

## Current checks
- SC001: Sensitive-looking external function without a common access modifier (heuristic).
- SC002: External value call before nearby state update (possible reentrancy; heuristic).
- SC003: `tx.origin` usage.
- SC004: Low-level `.call(...)` usage requiring review.
- SC005: Potentially unbounded loop.

## Suggested next milestones
1. Add Solidity AST analysis using Slither JSON output.
2. Replace keyword-overlap retrieval with embeddings and a vector store.
3. Add a labelled evaluation set and report precision/recall per rule.
4. Add a Dockerfile and deploy a demo.
5. Add CI to run tests and linting on each push.

