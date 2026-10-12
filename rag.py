"""Small local retrieval layer for security guidance; no external service required."""
import re

KNOWLEDGE = [
    {"title": "Checks-Effects-Interactions", "category": "reentrancy",
     "text": "Validate inputs and authorization, update contract state, and only then interact with external contracts. Add a reentrancy guard where appropriate and test callback-based attacks."},
    {"title": "Solidity Security Considerations", "category": "reentrancy",
     "text": "External calls hand control to another contract and may allow re-entry. Review all external calls, state changes, and assumptions about called contracts."},
    {"title": "Access Control", "category": "access-control",
     "text": "Restrict administrative and asset-moving functions using explicit authorization. Test calls from both authorized and unauthorized accounts."},
    {"title": "Avoid tx.origin Authorization", "category": "access-control",
     "text": "Do not use tx.origin as an authorization mechanism. Prefer msg.sender plus explicit ownership or role checks."},
    {"title": "Low-Level Call Safety", "category": "low-level-call",
     "text": "Low-level calls return a success flag and may fail. Validate return values, handle failure deliberately, and assess the destination and reentrancy implications."},
    {"title": "Gas and Denial of Service", "category": "unchecked-input",
     "text": "Loops over growing collections can exceed block gas limits. Bound work, paginate operations, or redesign processing to avoid unbounded on-chain iteration."},
    {"title": "Arithmetic and Compiler Versions", "category": "arithmetic",
     "text": "Use a supported Solidity compiler version and understand checked arithmetic behavior. Review casts, rounding, precision loss, and unchecked blocks."},
]

def _tokens(s):
    return set(re.findall(r"[a-z0-9]+", s.lower()))

def retrieve_guidance(category, top_k=2):
    query = _tokens(category.replace("-", " ") + " security smart contract")
    scored = []
    for item in KNOWLEDGE:
        text = item["title"] + " " + item["category"] + " " + item["text"]
        tokens = _tokens(text)
        overlap = len(query & tokens) / max(1, len(query | tokens))
        if item["category"] == category:
            overlap += 0.5
        scored.append((overlap, item))
    scored.sort(key=lambda x: x[0], reverse=True)
    return [item for score, item in scored[:top_k]]
