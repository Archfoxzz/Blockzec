from auditor import audit_contract
from rag import retrieve_guidance

def test_detects_tx_origin():
    report = audit_contract("contract A { function auth() public view returns(address) { return tx.origin; } }")
    assert any(f["id"] == "SC003" for f in report["findings"])

def test_detects_low_level_call():
    report = audit_contract('contract A { function x(address a) external { a.call(""); } }')
    assert any(f["id"] == "SC004" for f in report["findings"])

def test_guidance_retrieval():
    results = retrieve_guidance("reentrancy", top_k=2)
    assert len(results) == 2
    assert any("Reentrancy" in x["title"] or "Checks-Effects" in x["title"] for x in results)

def test_empty_contract_returns_report():
    report = audit_contract("")
    assert report["findings"] == []
    assert report["checks_run"] > 0
