# Vulnerability Assessment Report

**Target:** https://demo.vulnerable.example  
**Date:** 2026-11-03  
**Findings:** 5 (1 duplicate merged)

## Executive summary

The assessment identified **1 critical** and **0 high** severity issues. The most serious is *SQL Injection in id at https://demo.vulnerable.example/product?id=1*, scoring 9.8 (Critical). Issues at this level should be remediated before the next release.

| Severity | Count |
|---|---|
| Critical | 1 |
| Medium | 4 |

> **2 finding(s) contain claims that could not be traced to the scan data.** They are marked below and must be reviewed before this report is sent.

## Findings

### 1. SQL Injection in id at https://demo.vulnerable.example/product?id=1

**Severity:** Critical (9.8)  
**CVSS v3.1:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`  
**Source:** VS-001 (also seen as VS-002)

The id parameter is concatenated into a SQL query. A crafted value changes the meaning of the query, exposing the database behind https://demo.vulnerable.example/product?id=1.

**Reproduction**

Send a GET request to https://demo.vulnerable.example/product?id=1 with id=1' OR '1'='1 and compare the response against a benign value.

**Remediation**

Use parameterised queries so id is bound as a value and never parsed as SQL.

**⚠ Needs review before sending:**

- CWE not in catalogue: CWE-781
- classification mismatch: scanner reported 'SQL Injection' (commonly CWE-89), but finding was assigned CWE-781 — manual verification recommended

---

### 2. Cross-Site Request Forgery in the request body at https://demo.vulnerable.example/account/email

**Severity:** Medium (6.5)  
**CVSS v3.1:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N`  
**Weakness:** CWE-352 — Cross-Site Request Forgery  
**Source:** VS-004

The endpoint at https://demo.vulnerable.example/account/email performs a state change without verifying the request originated from the application itself.

**Reproduction**

Host a page that auto-submits a POST to https://demo.vulnerable.example/account/email, then load it while authenticated; the change is applied.

**Remediation**

Require an unpredictable per-session token on state-changing requests and set SameSite on the session cookie.

---

### 3. Insecure Direct Object Reference in invoice_id at https://demo.vulnerable.example/invoice

**Severity:** Medium (6.5)  
**CVSS v3.1:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`  
**Weakness:** CWE-639 — Authorization Bypass Through User-Controlled Key  
**Source:** VS-005

The invoice_id value selects a record without checking that the authenticated user owns it, so any user can read another user data via https://demo.vulnerable.example/invoice.

**Reproduction**

Authenticate, then request https://demo.vulnerable.example/invoice with invoice_id set to an identifier belonging to a different user.

**Remediation**

Check the authenticated user owns the referenced object on every request (IDOR). Check ownership server-side on every request rather than trusting the identifier supplied by the client.

---

### 4. Reflected XSS in q at https://demo.vulnerable.example/search

**Severity:** Medium (6.1)  
**CVSS v3.1:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`  
**Weakness:** CWE-79 — Cross-site Scripting  
**Source:** VS-003

Input supplied in q is reflected into the response without encoding, so an attacker-supplied script executes in a victim browser. This corresponds to [UNVERIFIED REFERENCE REMOVED].

**Reproduction**

Request https://demo.vulnerable.example/search with q=<svg onload=alert(1)> and observe the payload rendered unencoded in the HTML body.

**Remediation**

Encode output for the context it lands in, and prefer textContent over innerHTML when inserting untrusted text.

**⚠ Needs review before sending:**

- invented CVE reference: CVE-2019-3253

---

### 5. Verbose Error Message in id at https://demo.vulnerable.example/product

**Severity:** Medium (5.3)  
**CVSS v3.1:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`  
**Weakness:** CWE-209 — Information Exposure Through an Error Message  
**Source:** VS-006

An unhandled error at https://demo.vulnerable.example/product returns a stack trace, disclosing framework version and server file paths that assist further attacks.

**Reproduction**

Request https://demo.vulnerable.example/product with id=id=abc to trigger the error and observe the trace in the response body.

**Remediation**

Return a generic error to the client and log the detail server-side only.

---

## About this report

Findings were triaged with an LLM under a fixed output schema. CVSS scores are computed from the selected metrics by code, not stated by the model, and every claim is checked against the scanner output and a local CWE catalogue before inclusion. Claims that could not be traced are flagged above rather than silently removed.

Backend: `mock`. Schema retries: 0.