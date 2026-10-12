import os
import re
from rag import retrieve_guidance

RULES = [
    {
        "id": "SC001", "category": "access-control", "title": "Missing access control on sensitive function",
        "severity": "High",
        "pattern": re.compile(r"function\s+(?:setOwner|setAdmin|setTreasury|withdraw|mint|pause|upgrade\w*)\s*\([^)]*\)\s*(?:public|external)", re.I),
        "description": "A sensitive-looking function is declared public/external, but this lightweight check did not find a common access-control modifier in its declaration.",
        "recommendation": "Review whether the function must be restricted. Add an appropriate authorization check (for example onlyOwner or role-based access control) and test unauthorized callers.",
        "evidence_group": 0,
        "check": "sensitive-function-without-modifier"
    },
    {
        "id": "SC002", "category": "reentrancy", "title": "External call before state update (possible reentrancy)",
        "severity": "High",
        "pattern": re.compile(r"call\s*\{[^}]*value\s*:[^}]*\}\s*\([^)]*\)[\s\S]{0,180}(?:balances?\s*\[[^\]]+\]\s*[-+]?=|[A-Za-z_]\w*\s*[-+]?=)", re.I),
        "description": "An external value-transfer call appears before a nearby state update. This ordering can create a reentrancy risk depending on the full control flow.",
        "recommendation": "Prefer checks-effects-interactions: update internal accounting before external calls, consider a reentrancy guard, and add adversarial tests.",
        "evidence_group": 0,
        "check": "external-call-before-state-update"
    },
    {
        "id": "SC003", "category": "arithmetic", "title": "Use of tx.origin for authorization",
        "severity": "High",
        "pattern": re.compile(r"tx\.origin"),
        "description": "tx.origin is referenced. Using it for authorization can enable phishing-style call-chain attacks.",
        "recommendation": "Use msg.sender and explicit role/ownership checks for authorization. Review every tx.origin occurrence.",
        "evidence_group": 0,
        "check": "tx-origin"
    },
    {
        "id": "SC004", "category": "low-level-call", "title": "Low-level call result may need validation",
        "severity": "Medium",
        "pattern": re.compile(r"\.call\s*(?:\{[^}]*\})?\s*\("),
        "description": "A low-level call is present. Its success status and failure behavior should be checked, and the call site should be reviewed for reentrancy.",
        "recommendation": "Check the returned success value, handle failure explicitly, and assess reentrancy and target-address trust.",
        "evidence_group": 0,
        "check": "low-level-call"
    },
    {
        "id": "SC005", "category": "unchecked-input", "title": "Potentially unbounded loop",
        "severity": "Medium",
        "pattern": re.compile(r"for\s*\([^;]*;\s*[^;]*(?:\.length|<\s*\w+)[^;]*;"),
        "description": "A loop may depend on a variable-sized collection or bound. If it can grow without limit, transactions may run out of gas.",
        "recommendation": "Bound iterations, consider pagination or pull-based processing, and test worst-case gas consumption.",
        "evidence_group": 0,
        "check": "unbounded-loop"
    },
]

def _snippet(source, match, radius=100):
    start = max(0, match.start() - radius)
    end = min(len(source), match.end() + radius)
    return " ".join(source[start:end].split())[:280]

def _llm_explain(finding, source):
    key = os.getenv("OPENAI_API_KEY")
    if not key:
        return None
    try:
        from openai import OpenAI
        client = OpenAI(api_key=key)
        model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
        prompt = (
            "You are assisting a human Solidity security reviewer. Explain the finding in 3-5 concise sentences. "
            "Do not claim certainty beyond the evidence. Mention what must be manually verified. "
            f"\nFinding: {finding['title']}\nDescription: {finding['description']}\nEvidence: {finding['evidence']}\n"
            f"Relevant source:\n{source[:12000]}"
        )
        response = client.chat.completions.create(
            model=model,
            messages=[{"role": "system", "content": "Be precise, cautious, and security-focused."},
                      {"role": "user", "content": prompt}],
            temperature=0.1,
        )
        return response.choices[0].message.content
    except Exception as exc:
        return f"LLM explanation unavailable ({type(exc).__name__}). Deterministic finding retained."

def audit_contract(source, use_llm=False):
    findings = []
    for rule in RULES:
        for match in rule["pattern"].finditer(source):
            snippet = _snippet(source, match)
            finding = {
                "id": rule["id"], "category": rule["category"], "title": rule["title"],
                "severity": rule["severity"], "description": rule["description"],
                "evidence": snippet, "recommendation": rule["recommendation"],
                "check": rule["check"],
            }
            # Avoid repeating the same rule excessively for identical broad patterns.
            if not any(x["id"] == finding["id"] and x["evidence"] == finding["evidence"] for x in findings):
                if use_llm:
                    finding["llm_explanation"] = _llm_explain(finding, source)
                findings.append(finding)
    return {
        "tool": "SentinelSC",
        "version": "0.1.0",
        "checks_run": len(RULES),
        "findings": findings,
        "limitations": [
            "Pattern matching can produce false positives and false negatives.",
            "This MVP does not build a full Solidity AST or perform symbolic execution.",
            "Compile and test the contract; use specialist tools such as Slither and manual review before deployment.",
            "Retrieved guidance is supporting context, not proof that a finding is exploitable."
        ]
    }
