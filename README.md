# AegisAgent 🛡️

**Enterprise-Grade Defense-in-Depth Security Middleware & Deterministic Policy Gate for Autonomous AI Agents**

---

## Overview

AegisAgent protects autonomous LLM agents and multi-agent workflows against **prompt injection attacks**, **jailbreaks**, **RAG/memory poisoning**, and the **Lethal Trifecta** (untrusted data + tool execution + sensitive data access).

### Defense-in-Depth Architecture

1. **Multi-Layer Injection Detector**:
   - Transformer-based sequence classification (`protectai/deberta-v3-base-prompt-injection-v2`).
   - Token sliding-window chunking for long context (>450 tokens).
   - Regex heuristic filters and Unicode NFKC normalization.
   - Base64 de-obfuscation and zero-width character stripping.

2. **Passive Context Sanitizer & Encapsulation**:
   - Strips malicious executable tags (`<script>`, `<iframe>`, `<embed>`) and Markdown image exfiltration payloads.
   - Computes SHA-256 payload hashes.
   - Strictly encapsulates untrusted data inside `<untrusted_context>` XML boundaries with non-executable system directives.

3. **Runtime Taint Tracking**:
   - Lineage and provenance tracking across tool and context boundaries.
   - Transitions context from `TRUSTED` to `UNTRUSTED` upon external data ingestion and `QUARANTINED` upon exploit detection.

4. **Deterministic Policy Gate & Blast Radius Containment**:
   - Embeds user root intent using `sentence-transformers/all-MiniLM-L6-v2`.
   - Computes semantic cosine similarity against proposed agent tool actions.
   - Blocks unauthorized `HIGH_IMPACT_WRITE` tools even when an injection bypasses neural detectors (**Blast Radius Containment**).

5. **Tamper-Evident Audit Logging**:
   - Thread-safe structured logging to `aegis_audit.jsonl` recording cryptographically hashed payloads and security verdicts.

6. **Interactive Security Console (Streamlit)**:
   - Real-time testing, sensitivity sliders, breadcrumbs, and live audit telemetry.

---

## Installation

```bash
git clone https://github.com/pal0912/aegis_agent.git
cd aegis_agent
pip install -r requirements.txt
```

---

## Running the Security Console

Launch the Streamlit dashboard:

```bash
streamlit run app.py
```

---

## Running Benchmarks

Evaluate AegisAgent across 12 adversarial attack vectors and 10 benign enterprise documents:

```bash
python -m evals.benchmark
```

---

## License

Apache 2.0
