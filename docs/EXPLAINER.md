# Conceptual Guide: Vulnerability Triage and Grounding

This document explains the core intuition behind the Vulnerability Triage Agent, why language models struggle with vulnerability triage, and how deterministic verification ensures reliability.

---

## The Challenge: Translating Scanner Outputs

Automated security scanners (e.g., OWASP ZAP, Burp Suite, Nmap) detect potential vulnerabilities by sending test payloads and observing server responses. However, raw scanner output is written for automated consumption:

```
[ALERT] Type: SQL Injection
Path: /product?id=1
Payload: 1' OR '1'='1
Evidence: MySQL error string in response body.
```

Security teams and developers need actionable, contextual reports that explain:
- **What happened:** What vulnerability was identified.
- **Why it matters:** The practical severity and business impact.
- **How to reproduce:** Specific, testable steps to verify the issue.
- **How to remediate:** Concrete, defensive programming guidance.

Translating raw findings into structured vulnerability reports is time-consuming and follows a predictable structure—making it an ideal candidate for automation.

---

## Why Direct LLM Prompting Fails

Passing raw scanner findings directly to a language model often produces fluent but untrustworthy reports due to several failure modes:

### 1. Fabricated CVE Citations
Language models are trained on large corpora of security documentation and advisories where vulnerability descriptions frequently include Common Vulnerabilities and Exposures (CVE) identifiers. When asked to triage custom application code, models frequently generate believable but entirely fabricated CVE identifiers (e.g., citing `CVE-2019-4471`). 

In a professional security assessment, citing a nonexistent CVE destroys the credibility of the entire report.

### 2. Inconsistent CVSS Scoring
Language models are generative token predictors rather than mathematical calculators. When asked to provide a CVSS score, models often hallucinate scores that contradict their own severity assessments or violate CVSS v3.1 mathematical formulas.

### 3. Misclassification and Hallucinated Scope
Models may misclassify weaknesses (e.g., confusing SQL Injection with Path Traversal) or invent reproduction URLs and parameters that the scanner never touched.

### 4. Self-Auditing Limitations
Asking an LLM to evaluate its own output does not solve hallucination. The same process that generated a fabricated citation will confidently confirm that the citation is real.

---

## The Solution: Deterministic Architecture

The Vulnerability Triage Agent solves these failure modes by enforcing strict operational boundaries between model generation and code-enforced validation:

### 1. Fixed Schema Constrained Output
The model never generates free-form text. It must respond with structured JSON adhering to a strict schema (`TRIAGE_SCHEMA`). If a completion deviates from the schema, the agent automatically retries with diagnostic feedback.

### 2. Algorithmic CVSS Calculation
The model is never permitted to output a numeric CVSS score. Instead, it selects eight qualitative CVSS v3.1 metrics (e.g., Attack Vector, Attack Complexity, Privileges Required). Application code calculates the base score deterministically using official FIRST CVSS v3.1 formulas.

### 3. Deterministic Grounding Checks
All generated claims are evaluated by Python code against two sources of truth:
1. **The Scanner Evidence:** The raw text and findings provided by the scanner.
2. **The Local CWE Catalogue:** An authoritative weakness dictionary.

---

## Verification vs. Redaction

The system enforces clear distinctions between different validation states:

- **Redacted Content:** Fabricated CVE numbers and unsupported impact claims (claims not present in the scan evidence) are redacted and replaced with visible warning tags (`[UNVERIFIED REFERENCE REMOVED]`).
- **Flagged Content:** Valid CWE identifiers that mismatch the scanner's reported vulnerability class, unverified URLs, or mathematical discrepancies are retained in the finding but explicitly marked in a warning banner for human review.
- **Human Gating:** If any finding contains ungrounded claims or failed processing, the CLI exits with status code `1`, preventing unreviewed reports from shipping in automated pipelines.
