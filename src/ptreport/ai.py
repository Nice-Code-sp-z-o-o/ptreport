"""Optional writing assistant backed by a local Ollama server.

Everything in this module is about keeping the feature local and contained:

* the Ollama URL may only point at a loopback host (SSRF guard, also re-checked
  on every request, with redirects refused and environment proxies ignored),
* prompts only ever contain the fields of the one finding being edited,
* model output is returned as plain text; the browser shows it with
  ``textContent`` / a textarea value and never as HTML.

All prompts live here so they are easy to review and adjust.
"""

from __future__ import annotations

import ipaddress
import json
import re
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

DEFAULT_URL = "http://127.0.0.1:11434"
ALLOWED_HOSTS = ("127.0.0.1", "::1", "localhost")
TIMEOUT_SECONDS = 120
TAGS_TIMEOUT_SECONDS = 10
MAX_URL_LEN = 200
MAX_MODEL_LEN = 100
MAX_FIELD_CHARS = 20_000      # text sent for one field
MAX_TITLE_CHARS = 300
MAX_OUTPUT_CHARS = 50_000     # longer answers are cut
MAX_RESPONSE_BYTES = 4 * 1024 * 1024

FIELDS = ("description", "impact", "technical_details", "remediation")
ACTIONS = ("draft", "improve", "shorten", "translate_en", "translate_pl")
CONTEXT_FIELDS = ("description", "impact", "technical_details", "remediation")

_MODEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,99}$")
_THINK_RE = re.compile(r"<think>.*?</think>", re.DOTALL | re.IGNORECASE)


class AiError(Exception):
    """A problem the user can act on (shown as is)."""

    def __init__(self, message: str, status: int = 502):
        super().__init__(message)
        self.message = message
        self.status = status


# ------------------------------------------------------------------ URL guard --

def url_problem(url: str) -> str | None:
    """Why ``url`` is not an acceptable Ollama base URL, or None when it is."""
    if not url:
        return "Ollama URL is required."
    if len(url) > MAX_URL_LEN:
        return f"Ollama URL must be at most {MAX_URL_LEN} characters."
    if any(ch.isspace() for ch in url) or any(ord(ch) < 32 or ord(ch) == 127 for ch in url):
        return "Ollama URL must not contain spaces or control characters."
    try:
        parts = urllib.parse.urlsplit(url)
        port = parts.port
    except ValueError:
        return "Ollama URL is not a valid URL."
    if parts.scheme not in ("http", "https"):
        return "Ollama URL must start with http:// or https://."
    if parts.username is not None or parts.password is not None or "@" in parts.netloc:
        return "Ollama URL must not contain a user name or password."
    host = (parts.hostname or "").lower()
    if host not in ALLOWED_HOSTS:
        return "Only a local Ollama is allowed: use 127.0.0.1, ::1 or localhost as the host."
    if port is not None and not 1 <= port <= 65535:
        return "Ollama URL has an invalid port."
    if parts.path not in ("", "/") or parts.query or parts.fragment:
        return "Ollama URL must be just scheme, host and port, e.g. http://127.0.0.1:11434."
    return None


def normalise_url(url: str) -> str:
    return url.strip().rstrip("/")


def model_problem(model: str) -> str | None:
    if not model:
        return "Model is required."
    if len(model) > MAX_MODEL_LEN or not _MODEL_RE.match(model):
        return "Model name may contain letters, digits and . _ : / + - (e.g. qwen2.5:3b)."
    return None


def _check_resolves_to_loopback(host: str, port: int) -> None:
    """``localhost`` comes from /etc/hosts; make sure it really is loopback."""
    if host != "localhost":
        return
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except OSError as exc:
        raise AiError("Could not resolve localhost.") from exc
    for info in infos:
        address = info[4][0].split("%", 1)[0]
        if not ipaddress.ip_address(address).is_loopback:
            raise AiError("localhost does not resolve to a loopback address; use 127.0.0.1 instead.", 400)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, "Redirects are not followed", headers, fp)


# No ProxyHandler entries: an http_proxy variable must never send prompts off the machine.
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())


def _request(base_url: str, path: str, payload: dict | None, timeout: float) -> dict:
    problem = url_problem(base_url)
    if problem:
        raise AiError(problem, 400)
    base = normalise_url(base_url)
    parts = urllib.parse.urlsplit(base)
    _check_resolves_to_loopback((parts.hostname or "").lower(),
                                parts.port or (443 if parts.scheme == "https" else 80))
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    # scheme is http(s) and host is loopback: checked by url_problem() above
    req = urllib.request.Request(  # noqa: S310
        base + path, data=data, method="POST" if data is not None else "GET",
        headers={"Content-Type": "application/json", "Accept": "application/json"})
    try:
        with _OPENER.open(req, timeout=timeout) as resp:
            raw = resp.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as exc:
        detail = ""
        try:
            detail = str(json.loads(exc.read(64 * 1024) or b"{}").get("error", ""))
        except (ValueError, AttributeError, OSError):
            pass
        if exc.code == 404 and "model" in detail.lower():
            raise AiError("The model is not installed in Ollama. Pick one with “Load models” in Settings, "
                          "or install it with `ollama pull <model>`.", 502) from exc
        if 300 <= exc.code < 400:
            raise AiError("Ollama answered with a redirect, which is not followed.") from exc
        raise AiError(f"Ollama returned HTTP {exc.code}" + (f": {detail[:200]}" if detail else ".")) from exc
    except TimeoutError as exc:
        raise AiError(f"Ollama did not answer within {int(timeout)} seconds. A bigger model may need more "
                      "time to load; try again or use a smaller model.", 504) from exc
    except urllib.error.URLError as exc:
        if isinstance(exc.reason, TimeoutError):
            raise AiError(f"Ollama did not answer within {int(timeout)} seconds.", 504) from exc
        raise AiError(f"Ollama is not reachable at {base}. Is it running? Start it with `ollama serve`.") from exc
    except OSError as exc:
        raise AiError(f"Ollama is not reachable at {base}. Is it running? Start it with `ollama serve`.") from exc
    if len(raw) > MAX_RESPONSE_BYTES:
        raise AiError("Ollama's answer is too large.")
    try:
        body = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise AiError("Ollama's answer is not valid JSON. Is the URL really an Ollama server?") from exc
    if not isinstance(body, dict):
        raise AiError("Ollama's answer has an unexpected format.")
    return body


def list_models(base_url: str) -> list[str]:
    body = _request(base_url, "/api/tags", None, TAGS_TIMEOUT_SECONDS)
    models = body.get("models")
    if not isinstance(models, list):
        raise AiError("Ollama's model list has an unexpected format.")
    names = []
    for m in models:
        name = m.get("name") if isinstance(m, dict) else None
        if isinstance(name, str) and not model_problem(name):
            names.append(name)
    return sorted(set(names))


def test_connection(base_url: str, model: str) -> str:
    """A short success message, or AiError with what is wrong."""
    models = list_models(base_url)
    if not models:
        raise AiError("Ollama is running but has no models. Install one, e.g. `ollama pull qwen2.5:3b`.")
    if model and model not in models and f"{model}:latest" not in models:
        raise AiError(f"Ollama is running, but the model “{model}” is not installed. "
                      f"Available: {', '.join(models[:10])}.")
    if not model:
        return f"Ollama is running with {len(models)} model(s). Choose one and save."
    return f"Ollama is running and “{model}” is available."


def clean_output(text: str) -> str:
    """Drop reasoning blocks and wrapping code fences some models add; keep plain text."""
    text = _THINK_RE.sub("", text).replace("\r\n", "\n").replace("\x00", "")
    text = text.strip()
    fence = re.match(r"^```(?:markdown|md|text)?\n(.*)\n```$", text, re.DOTALL)
    if fence:
        text = fence.group(1).strip()
    return text[:MAX_OUTPUT_CHARS]


def chat(base_url: str, model: str, messages: list[dict], timeout: float = TIMEOUT_SECONDS) -> str:
    body = _request(base_url, "/api/chat", {
        "model": model,
        "messages": messages,
        "stream": False,
        "options": {"temperature": 0.3},
    }, timeout)
    if body.get("error"):
        raise AiError(f"Ollama: {str(body['error'])[:200]}")
    message = body.get("message")
    content = message.get("content") if isinstance(message, dict) else None
    if not isinstance(content, str):
        raise AiError("Ollama's answer has an unexpected format.")
    text = clean_output(content)
    if not text:
        raise AiError("The model returned an empty answer. Try again or use another model.")
    return text


# -------------------------------------------------------------------- prompts --

LANGUAGE_NAMES = {"en": "English", "pl": "Polish"}

FIELD_NAMES = {
    "en": {"description": "Description", "impact": "Impact", "technical_details": "Technical details",
           "remediation": "Recommendation (remediation)"},
    "pl": {"description": "Opis", "impact": "Wpływ", "technical_details": "Szczegóły techniczne",
           "remediation": "Rekomendacja (sposób naprawy)"},
}

FIELD_GOALS = {
    "en": {
        "description": "what the vulnerability is, where it was found and why it happens",
        "impact": "what an attacker can achieve and the business consequences",
        "technical_details": "root cause, affected parameters/endpoints and versions, in technical terms",
        "remediation": "concrete, prioritised steps to fix the issue and prevent it in future",
    },
    "pl": {
        "description": "na czym polega podatność, gdzie ją znaleziono i z czego wynika",
        "impact": "co może osiągnąć atakujący i jakie są skutki biznesowe",
        "technical_details": "przyczyna źródłowa, podatne parametry/endpointy i wersje, językiem technicznym",
        "remediation": "konkretne kroki naprawy w kolejności ważności oraz zapobieganie w przyszłości",
    },
}

SYSTEM_PROMPT = {
    "en": (
        "You are a writing assistant for penetration test reports. You help a professional security tester "
        "write one field of one finding. Write in a clear, factual, professional tone, as in a report for a "
        "client. Do not invent facts, hosts, versions, parameters or test results that are not in the input; "
        "where details are missing, keep the text general instead of guessing. "
        "Output format: plain text that may use only this light Markdown: paragraphs separated by a blank line, "
        "'- ' bullet lists, **bold**, `inline code`, fenced ``` code blocks. No HTML, no headings with the field "
        "name, no tables unless the input already has one. "
        "Answer with the text of the field only: no introduction, no explanation, no closing remarks."
    ),
    "pl": (
        "Jesteś asystentem pisania raportów z testów penetracyjnych. Pomagasz profesjonalnemu pentesterowi "
        "napisać jedno pole jednej podatności. Pisz jasno, rzeczowo i profesjonalnie, jak w raporcie dla "
        "klienta. Nie wymyślaj faktów, hostów, wersji, parametrów ani wyników testów, których nie ma w danych; "
        "gdy brakuje szczegółów, pisz ogólnie zamiast zgadywać. "
        "Format odpowiedzi: zwykły tekst, który może używać tylko lekkiego Markdown: akapity oddzielone pustą "
        "linią, listy '- ', **pogrubienie**, `kod w linii`, bloki kodu ```. Bez HTML, bez nagłówka z nazwą pola, "
        "bez tabel, chyba że dane już ją zawierają. "
        "Odpowiedz wyłącznie treścią pola: bez wstępu, wyjaśnień i podsumowań."
    ),
}

ACTION_INSTRUCTIONS = {
    "en": {
        "draft": "Write the “{field}” field for this finding ({goal}). Base it on the title, CWE and the other "
                 "fields given below. Write it in {lang}. Keep it concise: one to three short paragraphs or a short "
                 "list.",
        "improve": "Improve the wording of the “{field}” text below: fix grammar and style, make it clear and "
                   "professional, keep every fact, code block and value exactly as it is. Keep the language of "
                   "the text ({lang} expected).",
        "shorten": "Shorten the “{field}” text below to about half its length. Keep the key facts, values and "
                   "code blocks, drop repetition. Keep the language of the text ({lang} expected).",
        "translate": "Translate the “{field}” text below into {lang}. Use standard security terminology in "
                     "{lang}. Keep code blocks, inline code, URLs, parameter names and payloads unchanged.",
    },
    "pl": {
        "draft": "Napisz pole „{field}” dla tej podatności ({goal}). Oprzyj się na tytule, CWE i pozostałych "
                 "polach podanych niżej. Pisz po {lang_pl}. Zwięźle: od jednego do trzech krótkich akapitów "
                 "albo krótka lista.",
        "improve": "Popraw styl tekstu pola „{field}” podanego niżej: popraw gramatykę i styl, niech będzie jasny "
                   "i profesjonalny; zachowaj bez zmian wszystkie fakty, bloki kodu i wartości. Zachowaj język "
                   "tekstu (oczekiwany: {lang_pl}).",
        "shorten": "Skróć tekst pola „{field}” podany niżej do około połowy. Zachowaj kluczowe fakty, wartości "
                   "i bloki kodu, usuń powtórzenia. Zachowaj język tekstu (oczekiwany: {lang_pl}).",
        "translate": "Przetłumacz tekst pola „{field}” podany niżej na {lang_acc}. Używaj standardowej "
                     "terminologii bezpieczeństwa. Bloki kodu, kod w linii, adresy URL, nazwy parametrów "
                     "i payloady pozostaw bez zmian.",
    },
}

_PL_LANG = {"en": ("angielsku", "angielski"), "pl": ("polsku", "polski")}

CONTEXT_LABELS = {
    "en": {"title": "Title", "cwe": "CWE", "severity": "Severity", "input": "Text to work on",
           "context": "Finding"},
    "pl": {"title": "Tytuł", "cwe": "CWE", "severity": "Krytyczność", "input": "Tekst do przetworzenia",
           "context": "Podatność"},
}


@dataclass
class AssistRequest:
    field: str
    action: str
    report_language: str
    title: str = ""
    cwe: str = ""
    cwe_name: str = ""
    severity: str = ""
    fields: dict[str, str] = field(default_factory=dict)

    @property
    def output_language(self) -> str:
        if self.action == "translate_en":
            return "en"
        if self.action == "translate_pl":
            return "pl"
        return self.report_language


def build_messages(req: AssistRequest) -> list[dict]:
    """System + user messages for one action. Uses only the fields in ``req`` (one finding)."""
    ui = req.report_language if req.report_language in SYSTEM_PROMPT else "en"
    out = req.output_language
    action = "translate" if req.action.startswith("translate") else req.action
    template = ACTION_INSTRUCTIONS[ui][action]
    instruction = template.format(
        field=FIELD_NAMES[ui][req.field],
        goal=FIELD_GOALS[ui][req.field],
        lang=LANGUAGE_NAMES[out],
        lang_pl=_PL_LANG[out][0],
        lang_acc=f"język {_PL_LANG[out][1]}",
    )
    labels = CONTEXT_LABELS[ui]
    lines = [instruction, "", f"### {labels['context']}"]
    if req.title:
        lines.append(f"{labels['title']}: {req.title}")
    if req.cwe:
        lines.append(f"{labels['cwe']}: {req.cwe}" + (f" ({req.cwe_name})" if req.cwe_name else ""))
    if req.severity:
        lines.append(f"{labels['severity']}: {req.severity}")
    if action == "draft":
        for name in CONTEXT_FIELDS:
            value = req.fields.get(name, "").strip()
            if name != req.field and value:
                lines += ["", f"### {FIELD_NAMES[ui][name]}", value]
    else:
        lines += ["", f"### {labels['input']} ({FIELD_NAMES[ui][req.field]})", req.fields.get(req.field, "")]
    return [
        {"role": "system", "content": SYSTEM_PROMPT[out if action == "translate" else ui]},
        {"role": "user", "content": "\n".join(lines)},
    ]


# ---------------------------------------------------------------- rate limit --

class TokenBucket:
    """Simple per-process token bucket: ``capacity`` requests, refilled at ``rate`` per second."""

    def __init__(self, capacity: int, rate: float):
        self.capacity = capacity
        self.rate = rate
        self.tokens = float(capacity)
        self.updated = time.monotonic()
        self.lock = threading.Lock()

    def take(self) -> bool:
        with self.lock:
            now = time.monotonic()
            self.tokens = min(self.capacity, self.tokens + (now - self.updated) * self.rate)
            self.updated = now
            if self.tokens >= 1:
                self.tokens -= 1
                return True
            return False
