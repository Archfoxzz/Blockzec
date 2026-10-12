import streamlit as st
from auditor import audit_contract
from rag import retrieve_guidance

st.set_page_config(page_title="Blockzec | AI Contract Auditor", page_icon="🛡️", layout="wide")
st.title(" Blockzec")
st.caption("A portfolio-ready MVP combining Solidity pattern checks, retrieval-grounded security guidance, and optional LLM explanations.")
st.warning("Educational tool only. Findings are heuristic and must be validated by a qualified auditor. This is not a substitute for a full security audit.")

SAMPLE = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VulnerableVault {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "Transfer failed");
        balances[msg.sender] -= amount;
    }

    function setTreasury(address newTreasury) external {
        treasury = newTreasury;
    }

    address public treasury;
}
"""
with st.sidebar:
    st.header("Settings")
    use_llm = st.checkbox("Use optional LLM explanations", value=False)
    st.caption("Without an API key, the app still runs locally using deterministic checks and local retrieval.")
    st.markdown("**Optional environment variables**")
    st.code("OPENAI_API_KEY=...\nOPENAI_MODEL=gpt-4o-mini", language="bash")

code = st.text_area("Paste Solidity contract", value=SAMPLE, height=360)
contract_name = st.text_input("Contract label", value="Pasted contract")
if st.button("Run security analysis", type="primary"):
    if not code.strip():
        st.error("Paste a Solidity contract first.")
    else:
        with st.spinner("Analyzing contract…"):
            report = audit_contract(code, use_llm=use_llm)
            st.session_state["report"] = report
            st.session_state["contract_name"] = contract_name

if "report" in st.session_state:
    report = st.session_state["report"]
    findings = report["findings"]
    c1, c2, c3 = st.columns(3)
    c1.metric("Findings", len(findings))
    c2.metric("High severity", sum(f["severity"] == "High" for f in findings))
    c3.metric("Checks run", report["checks_run"])
    st.subheader("Findings")
    if not findings:
        st.success("No supported patterns were detected. This does not prove the contract is secure.")
    for i, f in enumerate(findings, 1):
        with st.expander(f'{i}. [{f["severity"]}] {f["title"]}', expanded=(i == 1)):
            st.write(f["description"])
            st.markdown(f'**Evidence:** `{f["evidence"]}`')
            st.markdown(f'**Recommendation:** {f["recommendation"]}')
            guidance = retrieve_guidance(f["category"], top_k=2)
            st.markdown("**Retrieved security guidance**")
            for item in guidance:
                st.markdown(f'- **{item["title"]}:** {item["text"]}')
            if f.get("llm_explanation"):
                st.markdown("**LLM explanation**")
                st.write(f["llm_explanation"])
    st.subheader("Limitations and review notes")
    for note in report["limitations"]:
        st.markdown(f"- {note}")
    st.download_button("Download JSON report", json.dumps(report, indent=2), file_name="sentinelsc_report.json", mime="application/json")
    markdown = ["# SentinelSC Audit Report", "", f"**Contract:** {st.session_state.get('contract_name', 'Contract')}", "",
                f"**Findings:** {len(findings)}", ""]
    for i, f in enumerate(findings, 1):
        markdown += [f"## {i}. [{f['severity']}] {f['title']}", "", f["description"], "",
                     f"**Evidence:** `{f['evidence']}`", "", f"**Recommendation:** {f['recommendation']}", ""]
    st.download_button("Download Markdown report", "\n".join(markdown), file_name="sentinelsc_report.md", mime="text/markdown")
