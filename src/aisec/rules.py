# ruff: noqa: E501, UP006, UP035 -- Complete prose and Python 3.9 typing.
"""Rule registry for source and public-URL scanning."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Dict

from .models import Confidence, Rule, Severity


def _rule(
    rule_id: str,
    title: str,
    description: str,
    severity: Severity,
    confidence: Confidence,
    category: str,
    impact: str,
    remediation: str,
    verification: str,
    *references: str,
) -> Rule:
    return Rule(
        rule_id,
        title,
        description,
        severity,
        confidence,
        category,
        impact,
        remediation,
        verification,
        list(references),
    )


RULES: Dict[str, Rule] = {
    rule.rule_id: rule
    for rule in (
        _rule(
            "AISEC001",
            "Hard-coded secret",
            "A credential-like value is embedded in source and may be recoverable from history or build artifacts.",
            Severity.HIGH,
            Confidence.HIGH,
            "secrets",
            "Anyone who can read the source, a package, or retained Git history may be able to impersonate the credential owner and access connected services.",
            "Revoke the exposed value, remove it from history where practical, and load replacements from a secret manager or environment variable.",
            "Confirm the old credential is rejected, search the current tree and history for the value, and run this rule again after the replacement is injected at runtime.",
            "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
        ),
        _rule(
            "AISEC002",
            "Private key material in source",
            "A private-key header appears in a source-controlled file.",
            Severity.CRITICAL,
            Confidence.HIGH,
            "secrets",
            "Possession of the private key may permit authentication, decryption, or artifact signing as the affected identity.",
            "Revoke or rotate the key, remove the material from repository history, and store keys outside the repository.",
            "Verify the corresponding public key or certificate has been replaced at every trust point, then rescan the tree and history for private-key headers.",
        ),
        _rule(
            "AISEC101",
            "Model output reaches dynamic code execution",
            "Output that appears to originate from an LLM is passed to eval, exec, compile, or a similar dynamic-code sink.",
            Severity.CRITICAL,
            Confidence.HIGH,
            "ai-code-execution",
            "A crafted model response can execute arbitrary code with the application's identity, exposing data and control of the host environment.",
            "Do not execute model output. Use a constrained parser and an allow-listed operation schema, then validate every field before use.",
            "Exercise the model-output path with malformed and code-like payloads and confirm they are rejected before any dynamic-code API is reached.",
            "https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/",
        ),
        _rule(
            "AISEC102",
            "Model output reaches a command sink",
            "Output that appears to originate from an LLM is passed to a shell or process-launch API.",
            Severity.CRITICAL,
            Confidence.HIGH,
            "ai-command-execution",
            "A manipulated model response can launch unintended programs or arguments, potentially reading data, changing the system, or escaping application boundaries.",
            "Map model choices to fixed commands and arguments. Avoid a shell, use an allow-list, and enforce least-privilege sandboxing.",
            "Test adversarial model outputs containing shell metacharacters and unexpected executables; confirm only fixed allow-listed argv values reach the process launcher.",
            "https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/",
        ),
        _rule(
            "AISEC103",
            "Untrusted data mixed into privileged instructions",
            "Request or user-controlled data appears to be interpolated directly into a system or privileged prompt.",
            Severity.HIGH,
            Confidence.MEDIUM,
            "prompt-injection",
            "Untrusted content can alter privileged instructions and induce unauthorized tool calls, data disclosure, or policy bypass.",
            "Keep instructions and untrusted content in separate structured fields, delimit content, restrict tool permissions, and validate model actions independently.",
            "Run prompt-injection cases through the affected path and verify untrusted text cannot change tool permissions or bypass independent action validation.",
            "https://genai.owasp.org/llmrisk/llm012025-prompt-injection/",
        ),
        _rule(
            "AISEC104",
            "Unsafe model or artifact loading",
            "Code loads a serialized model or remote implementation through an API that can execute embedded code.",
            Severity.HIGH,
            Confidence.MEDIUM,
            "model-supply-chain",
            "A tampered model or serialized artifact may execute code during loading and compromise the process before inference begins.",
            "Use a non-executable format such as safetensors, pin an expected digest and source, disable remote code, and load only trusted artifacts.",
            "Attempt to load an artifact with an unapproved digest or executable format and confirm it is rejected before deserialization; rescan to confirm unsafe loader options are gone.",
            "https://genai.owasp.org/llmrisk/llm032025-supply-chain/",
        ),
        _rule(
            "AISEC105",
            "TLS verification disabled",
            "A network client appears configured to skip certificate verification.",
            Severity.HIGH,
            Confidence.HIGH,
            "transport-security",
            "An on-path attacker may impersonate the remote service and read or modify model inputs, outputs, credentials, or downloaded artifacts.",
            "Enable certificate and hostname verification. Configure a trusted CA bundle for private infrastructure instead of bypassing verification.",
            "Connect through a test endpoint with an untrusted or hostname-mismatched certificate and confirm the client refuses the connection.",
        ),
        _rule(
            "AISEC201",
            "Potential client-side HTML injection",
            "Untrusted or model-produced content may be written to an HTML execution sink.",
            Severity.HIGH,
            Confidence.MEDIUM,
            "client-xss",
            "Attacker-controlled or model-generated markup may execute script in a user's browser, enabling session theft or actions as that user.",
            "Render text with textContent or a framework's escaped binding. If rich HTML is required, sanitize it with a maintained allow-list sanitizer.",
            "Render payloads containing script, event-handler, and dangerous-URL markup and confirm the browser displays inert text or sanitized output without execution.",
            "https://owasp.org/www-community/attacks/xss/",
        ),
        _rule(
            "AISEC202",
            "Permissive source CORS configuration",
            "Application source appears to allow every origin, potentially including credentialed cross-origin requests.",
            Severity.MEDIUM,
            Confidence.MEDIUM,
            "cors",
            "Untrusted websites may be able to read API responses in a visitor's browser, with greater impact if credentials are accepted.",
            "Allow only explicitly trusted HTTPS origins and never combine a wildcard or reflected origin with credentials.",
            "Send preflight and actual requests from both trusted and untrusted Origin values and confirm only the allow-listed origins receive access headers.",
        ),
        _rule(
            "AISEC301",
            "Recommended browser security header missing",
            "A public HTML response omits a defense-in-depth browser security header.",
            Severity.LOW,
            Confidence.HIGH,
            "web-headers",
            "The browser loses a defense-in-depth control that can reduce exploitation or data leakage when another application flaw is present.",
            "Add the named response header with a policy appropriate for the application, then verify it across all HTML routes.",
            "Request every public HTML route and confirm the named header is present with the intended value on successful and error responses.",
            "https://owasp.org/www-project-secure-headers/",
        ),
        _rule(
            "AISEC302",
            "Cookie security attribute missing",
            "A response cookie lacks one or more recommended transport or script-access restrictions.",
            Severity.MEDIUM,
            Confidence.HIGH,
            "cookie-security",
            "The affected cookie may be exposed over plaintext transport, to injected script, or in unintended cross-site requests, depending on the missing attribute.",
            "Set Secure on HTTPS cookies, HttpOnly on session cookies, and an explicit SameSite policy compatible with the application.",
            "Inspect Set-Cookie headers for login, refresh, and logout flows and confirm every sensitive cookie has the intended Secure, HttpOnly, and SameSite attributes.",
        ),
        _rule(
            "AISEC303",
            "Password form uses an unsafe transport or method",
            "A password field may be submitted with GET or to an unencrypted HTTP action.",
            Severity.HIGH,
            Confidence.HIGH,
            "form-security",
            "Credentials may leak through URLs, logs, browser history, network interception, or submission to an attacker-controlled origin.",
            "Submit credentials with POST to an HTTPS same-origin endpoint and avoid placing secrets in URLs.",
            "Inspect the rendered form action and submit a test login while recording requests; confirm the password appears only in a POST body sent to the expected HTTPS origin.",
        ),
        _rule(
            "AISEC304",
            "Client exposes AI integration details",
            "Public markup reveals an AI endpoint, privileged prompt, or credential-like client configuration.",
            Severity.MEDIUM,
            Confidence.MEDIUM,
            "ai-exposure",
            "Publicly disclosed credentials or privileged instructions can enable provider abuse, prompt extraction, or more targeted attacks against the AI endpoint.",
            "Keep provider credentials and privileged prompts server-side. Treat disclosed endpoints as untrusted and enforce authentication, quotas, and authorization server-side.",
            "Inspect built browser assets and returned markup, then confirm provider secrets and privileged prompts are absent and exposed endpoints reject unauthorized requests.",
        ),
        _rule(
            "AISEC305",
            "Permissive CORS response",
            "The response grants cross-origin access broadly or combines a broad origin policy with credentials.",
            Severity.HIGH,
            Confidence.HIGH,
            "cors",
            "An untrusted origin may read response data in a user's browser; credential-enabled broad access can expose authenticated information.",
            "Return Access-Control-Allow-Origin only for allow-listed origins and do not enable credentials with a wildcard or reflected origin.",
            "Send requests with trusted and attacker-controlled Origin headers and confirm only exact allow-listed origins receive access-control response headers.",
        ),
    )
}


def get_rule(rule_id: str) -> Rule:
    try:
        return RULES[rule_id.upper()]
    except KeyError as exc:
        raise KeyError(f"unknown aisec rule: {rule_id}") from exc


def iter_rules() -> Iterable[Rule]:
    return (RULES[key] for key in sorted(RULES))
