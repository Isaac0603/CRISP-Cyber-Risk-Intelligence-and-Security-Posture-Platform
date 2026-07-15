import streamlit as st
import json
import re

# Set up page layout
st.set_page_config(page_title="CRISP Platform", page_icon="🛡️", layout="wide")

st.title("🛡️ CRISP: Cyber Risk Intelligence & Security Posture Platform")
st.markdown("Automating the translation of static infrastructure configurations into threat-informed intelligence.")
st.markdown("---")

# Load rules database safely
try:
    with open("database.json", "r") as f:
        rules_db = json.load(f)
except FileNotFoundError:
    st.error("Error: database.json file not found. Ensure it exists in the root directory.")
    rules_db = []

# File upload panel
uploaded_file = st.file_uploader("Upload Raw Server Configuration File (e.g., mock_sshd_config.txt)", type=["txt", "conf"])

if uploaded_file is not None:
    # Read text streams from the uploaded object
    file_content = uploaded_file.read().decode("utf-8")
    
    st.subheader(f"🔍 Analyzing System Configuration: {uploaded_file.name}")
    
    findings = []
    
    # Core scanning loop using Python regex
    for rule in rules_db:
        if re.search(rule["pattern"], file_content):
            findings.append(rule)
            
    # Display Posture Output Matrix
    if findings:
        high_severity = sum(1 for f in findings if f["severity"] == "High")
        med_severity = sum(1 for f in findings if f["severity"] == "Medium")
        
        # Summary KPI Cards
        col1, col2, col3 = st.columns(3)
        col1.metric(label="Total Misconfigurations", value=len(findings))
        col2.metric(label="High Risk Vectors", value=high_severity)
        col3.metric(label="Medium Risk Vectors", value=med_severity)
        
        st.markdown("### 🔴 Identified Exploit Surface Map")
        
        # Expanders detailing individual threat definitions
        for index, item in enumerate(findings):
            with st.expander(f"{index + 1}. {item['issue']} [{item['severity']} Severity]"):
                st.write(f"**Target Pattern Identified:** `{item['pattern']}`")
                st.write(f"**Mapped MITRE ATT&CK ID:** {item['mitre_id']}")
                st.write(f"**Adversary Technique Focus:** {item['technique']}")
                st.info(f"**Recommended Hardening Step:** {item['remediation']}")
    else:
        st.success("✅ Secure Posture Verified! The uploaded log matches structural security baselines.")