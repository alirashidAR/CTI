import streamlit as st
import re
import requests
import time
from transformers import AutoTokenizer, AutoModelForTokenClassification, pipeline

# ========================
# Page Configuration
# ========================
st.set_page_config(
    page_title="IoC NER Analysis",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ========================
# CSS Styling
# ========================
st.markdown("""
<style>
    .main {
        padding-top: 2rem;
    }
    
    .stTitle {
        font-size: 3rem !important;
        background: linear-gradient(90deg, #1e3c72 0%, #2a5298 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        text-align: center;
        margin-bottom: 2rem;
    }
    
    .stSubheader {
        color: #1e3c72;
        border-bottom: 2px solid #e0e0e0;
        padding-bottom: 0.5rem;
        margin-top: 2rem;
    }
    
    .highlight-container {
        background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
        padding: 1.5rem;
        border-radius: 10px;
        border: 1px solid #e0e0e0;
        margin: 1rem 0;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
    }
    
    mark {
        padding: 2px 4px;
        border-radius: 3px;
    }
</style>
""", unsafe_allow_html=True)

# ========================
# Config & Constants
# ========================
MODEL_PATH = "D:/cti/ner/NERModel"
AGG_STRATEGY = "simple"
BASE_CTI_URL = "https://cti-4kzl.onrender.com/federated"

ENTITY_COLORS = {
    "IP": "#FFB6C1",
    "DOM": "#ADD8E6",
    "URL": "#90EE90",
    "SHA": "#FFD700",
    "FILE": "#FFA07A",
    "EMAIL": "#9370DB",
    "APT": "#20B2AA",
    "VULNAME": "#FF6347"
}

# ========================
# Load Model
# ========================
@st.cache_resource
def load_model():
    tokenizer = AutoTokenizer.from_pretrained(MODEL_PATH)
    model = AutoModelForTokenClassification.from_pretrained(MODEL_PATH)
    ner_pipe = pipeline("ner", model=model, tokenizer=tokenizer, aggregation_strategy=AGG_STRATEGY)
    return tokenizer, model, ner_pipe

tokenizer, model, ner_pipeline = load_model()

# ========================
# Utilities
# ========================
def clean_ioc(ioc: str) -> str:
    return re.sub(r"\s+", "", ioc).strip()

def regex_extract(text: str):
    regex_iocs = {"IPs": set(), "Domains": set(), "URLs": set(), 
                  "Hashes": set(), "Files": set(), "Emails": set()}
    regex_iocs["IPs"].update(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text))
    regex_iocs["Domains"].update(re.findall(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b", text))
    regex_iocs["URLs"].update(re.findall(r"https?://[^\s]+", text))
    regex_iocs["Hashes"].update(re.findall(r"\b[a-fA-F0-9]{32,64}\b", text))
    regex_iocs["Emails"].update(re.findall(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", text))
    regex_iocs["Files"].update(re.findall(r"\b[\w\-_]+\.(?:exe|pdf|docx?|xls[xm]?|pptx?|zip)\b", text))
    for k in regex_iocs:
        regex_iocs[k] = set(clean_ioc(i) for i in regex_iocs[k] if i)
    return regex_iocs

def merge_ner_and_regex(final_iocs, regex_iocs):
    for k in final_iocs:
        if k in regex_iocs:
            final_iocs[k] = final_iocs[k].union(regex_iocs[k])
    return final_iocs

def split_into_sentences(text):
    sentences = re.split(r'(?<=[.!?])\s+|\n+', text.strip())
    return [s.strip() for s in sentences if s.strip()]

def build_highlighted_text(text_input, highlights):
    last_idx = 0
    highlighted_text = ""
    for start, end, word, label, color, confidence in sorted(highlights, key=lambda x: x[0]):
        highlighted_text += text_input[last_idx:start]
        tooltip = f"{label} (Confidence: {confidence:.2%})"
        highlighted_text += f'<mark style="background-color: {color};" title="{tooltip}">{text_input[start:end]}</mark>'
        last_idx = end
    highlighted_text += text_input[last_idx:]
    return highlighted_text

def query_cti(indicators):
    results = {}
    for ind in indicators:
        url = f"{BASE_CTI_URL}/{ind}?summarize=true"
        try:
            resp = requests.get(url)
            if resp.status_code == 200:
                results[ind] = resp.json()
            else:
                results[ind] = {"error": f"HTTP {resp.status_code}", "body": resp.text}
        except Exception as e:
            results[ind] = {"error": str(e)}
    return results

# ========================
# Main App
# ========================
def main():
    st.title("🔍 IoC Enrichment with Advanced NER Analysis")
    st.markdown("### Analyze cybersecurity text sentence by sentence and show combined results with enrichment")

    # Initialize session state
    if "analysis_done" not in st.session_state:
        st.session_state.analysis_done = False
        st.session_state.all_highlights = []
        st.session_state.all_final_iocs = {"IPs": set(), "Domains": set(), "URLs": set(), "Hashes": set(),
                                          "Files": set(), "Emails": set(), "APTs": set(), "Vulnerabilities": set()}
        st.session_state.text_input = ("Researchers from Check Point identified a phishing campaign using "
                                       "secure-login-update.com on March 12, 2023. The malicious actors "
                                       "distributed malware via email attachments to admin@company.com and "
                                       "used the IP address 192.168.1.100 for command and control.")

    # Input area
    st.text_area("Enter cybersecurity text", height=150, key="text_input_area", value=st.session_state.text_input)

    # Form for analysis
    with st.form("analysis_form"):
        submitted = st.form_submit_button("🚀 Analyze Text")
        if submitted:
            st.session_state.text_input = st.session_state.text_input_area
            with st.spinner("Analyzing text..."):
                sentences = split_into_sentences(st.session_state.text_input)
                all_highlights = []
                all_final_iocs = {"IPs": set(), "Domains": set(), "URLs": set(), "Hashes": set(),
                                  "Files": set(), "Emails": set(), "APTs": set(), "Vulnerabilities": set()}

                offset = 0
                for sentence in sentences:
                    ner_results = ner_pipeline(sentence)
                    highlights = []
                    final_iocs = {"IPs": set(), "Domains": set(), "URLs": set(), "Hashes": set(),
                                  "Files": set(), "Emails": set(), "APTs": set(), "Vulnerabilities": set()}

                    for entity in ner_results:
                        start, end, word, label, conf = entity["start"], entity["end"], entity["word"], entity["entity_group"], entity["score"]
                        highlights.append((start + offset, end + offset, word, label, ENTITY_COLORS.get(label, "#D3D3D3"), conf))
                        word_clean = clean_ioc(word)
                        if "IP" in label: final_iocs["IPs"].add(word_clean)
                        elif "DOM" in label: final_iocs["Domains"].add(word_clean)
                        elif "URL" in label: final_iocs["URLs"].add(word_clean)
                        elif "SHA" in label: final_iocs["Hashes"].add(word_clean)
                        elif "FILE" in label: final_iocs["Files"].add(word_clean)
                        elif "EMAIL" in label: final_iocs["Emails"].add(word_clean)
                        elif "APT" in label: final_iocs["APTs"].add(word_clean)
                        elif "VULNAME" in label: final_iocs["Vulnerabilities"].add(word_clean)

                    regex_iocs = regex_extract(sentence)
                    final_iocs = merge_ner_and_regex(final_iocs, regex_iocs)

                    for key in all_final_iocs:
                        all_final_iocs[key].update(final_iocs[key])

                    all_highlights.extend(highlights)
                    offset += len(sentence) + 1  # for separator

                st.session_state.all_highlights = all_highlights
                st.session_state.all_final_iocs = all_final_iocs
                st.session_state.analysis_done = True

    # Display results if analysis is done
    if st.session_state.analysis_done:
        st.subheader("🎯 Highlighted Text")
        highlighted_text = build_highlighted_text(st.session_state.text_input, st.session_state.all_highlights)
        st.markdown(f'<div class="highlight-container">{highlighted_text}</div>', unsafe_allow_html=True)

        st.subheader("📋 Extracted Indicators of Compromise")
        for key, icon in [("IPs", "🌐"), ("Domains", "🔗"), ("URLs", "🔗"),
                          ("Hashes", "🔒"), ("Files", "📁"), ("Emails", "📧")]:
            items = st.session_state.all_final_iocs[key]
            if items:
                st.markdown(f"**{icon} {key}:**")
                for item in sorted(items):
                    st.code(item)
            else:
                st.info(f"No {key.lower()} found.")

        # CTI Enrichment
        st.subheader("🔍 CTI Enrichment")
        enrichable = list(st.session_state.all_final_iocs["IPs"] | st.session_state.all_final_iocs["Domains"] |
                          st.session_state.all_final_iocs["Hashes"] | st.session_state.all_final_iocs["URLs"])
        if enrichable:
            st.markdown("The following indicators can be enriched from threat intelligence sources:")
            for ioc in enrichable[:5]:
                st.markdown(f"• `{ioc}`")
            if len(enrichable) > 5:
                st.markdown(f"• ... and {len(enrichable)-5} more")

            # Form for CTI Query
            with st.form("cti_form"):
                query_submitted = st.form_submit_button("🚀 Query CTI Sources")
                if query_submitted:
                    with st.spinner("Querying threat intelligence sources..."):
                        results = query_cti(enrichable)
                        st.success("✅ CTI enrichment completed!")
                        st.json(results)
        else:
            st.info("No enrichable IoCs found.")

if __name__ == "__main__":
    main()
