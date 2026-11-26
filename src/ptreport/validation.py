"""Server-side validation for every write path (web forms, JSON API, import).

Each ``validate_*`` function takes a mapping (``request.form`` or a JSON dict)
and returns ``(clean_data, errors)``. ``errors`` maps field name -> message;
when it is non-empty ``clean_data`` must not be persisted.
"""

from __future__ import annotations

import hashlib
import re
import unicodedata
from collections.abc import Mapping
from datetime import date
from typing import Any

from ptreport import ids
from ptreport.cvss_service import VERSIONS as CVSS_VERSIONS
from ptreport.cvss_service import CvssInvalid, score_vector

SEVERITIES = ("critical", "high", "medium", "low", "info")
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}
FINDING_STATUSES = (
    "open", "partially_fixed", "not_fixed", "fixed", "risk_accepted", "wont_fix", "false_positive", "not_a_bug",
    "cannot_verify",
)
# Statuses that still need work: counted as "open" in report lists, summaries and the CLI.
OPEN_STATUSES = ("open", "partially_fixed", "not_fixed")
CONFIDENCE_LEVELS = ("certain", "probable", "unknown")
RETEST_RESULTS = ("fixed", "partially_fixed", "not_fixed", "not_tested")
TARGET_KINDS = ("web", "api", "host", "network", "mobile", "cloud", "wireless", "other")
LANGUAGES = ("en", "pl")

SHORT = 300
LONG = 200_000
HTTP_MESSAGE_MAX = 5_000_000
IMAGE_MAX_BYTES = 10 * 1024 * 1024
IMAGE_MAX_PER_FINDING = 50
# Evidence files (any type). Stored in SQLite, so the limits keep the database and JSON exports manageable.
FILE_MAX_BYTES = 25 * 1024 * 1024          # per file
FILE_MAX_TOTAL_PER_FINDING = 100 * 1024 * 1024
FILE_MAX_PER_FINDING = 50
FILENAME_MAX = 180
IMAGE_MAX_SIDE = 20_000  # pixels; an edited screenshot can never be larger than its original either

_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_PREFIX_RE = re.compile(r"^[A-Z][A-Z0-9]{0,9}$")
_CWE_RE = re.compile(r"^(?:CWE-)?(\d{1,5})$", re.IGNORECASE)
_EXTERNAL_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,31}$")
_PERSON_EXTRA_CHARS = set(" .,'-&")
_VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,19}$")


class Validator:
    def __init__(self, data: Mapping[str, Any]):
        self.data = data
        self.clean: dict[str, Any] = {}
        self.errors: dict[str, str] = {}

    def _raw(self, name: str) -> Any:
        return self.data.get(name, None)

    def text(
        self,
        name: str,
        *,
        required: bool = False,
        max_len: int = SHORT,
        multiline: bool = False,
        strip: bool = True,
        label: str | None = None,
    ) -> str:
        label = label or name.replace("_", " ").capitalize()
        value = self._raw(name)
        if value is None:
            value = ""
        if not isinstance(value, str):
            self.errors[name] = f"{label} must be text."
            return ""
        value = value.replace("\x00", "")
        if multiline:
            value = value.replace("\r\n", "\n").replace("\r", "\n")
            if strip:
                value = value.strip("\n").rstrip()
        else:
            value = value.strip()
            if "\n" in value or "\r" in value or _CONTROL_CHARS.search(value):
                self.errors[name] = f"{label} must be a single line without control characters."
                return value
        if required and not value:
            self.errors[name] = f"{label} is required."
        elif len(value) > max_len:
            self.errors[name] = f"{label} must be at most {max_len} characters."
        self.clean[name] = value
        return value

    def choice(self, name: str, choices: tuple[str, ...], default: str, label: str | None = None) -> str:
        label = label or name.replace("_", " ").capitalize()
        value = self._raw(name)
        if value in (None, ""):
            value = default
        if not isinstance(value, str) or value not in choices:
            self.errors[name] = f"{label} must be one of: {', '.join(c or '(none)' for c in choices)}."
            return default
        self.clean[name] = value
        return value

    def iso_date(self, name: str, label: str | None = None) -> date | None:
        label = label or name.replace("_", " ").capitalize()
        value = self._raw(name)
        if value in (None, ""):
            self.clean[name] = None
            return None
        if not isinstance(value, str):
            self.errors[name] = f"{label} must be a date (YYYY-MM-DD)."
            return None
        try:
            parsed = date.fromisoformat(value.strip())
        except ValueError:
            self.errors[name] = f"{label} must be a valid date (YYYY-MM-DD)."
            return None
        if not (date(1990, 1, 1) <= parsed <= date(2100, 12, 31)):
            self.errors[name] = f"{label} must be between 1990-01-01 and 2100-12-31."
            return None
        self.clean[name] = parsed.isoformat()
        return parsed

    def id_list(self, name: str, values: Any) -> list[int]:
        if values is None:
            values = []
        if isinstance(values, (str, int)):
            values = [values]
        if not isinstance(values, (list, tuple)):
            self.errors[name] = "Must be a list of identifiers."
            return []
        ids: list[int] = []
        for v in values:
            if isinstance(v, bool):
                self.errors[name] = "Invalid identifier."
                return []
            if isinstance(v, int):
                ids.append(v)
            elif isinstance(v, str) and v.strip().isdigit():
                ids.append(int(v.strip()))
            else:
                self.errors[name] = "Invalid identifier."
                return []
        ids = sorted(set(i for i in ids if i > 0))
        self.clean[name] = ids
        return ids


def _switch(data: Mapping[str, Any], field: str, default: int) -> int:
    """On/off value. Forms send a hidden "0" plus the checkbox "1" when ticked; JSON sends a boolean.
    A missing field keeps the default (older exports and API clients)."""
    values = data.getlist(field) if hasattr(data, "getlist") else (
        [] if data.get(field) is None else [data.get(field)])
    if not values:
        return default
    return 1 if any(x in (True, 1, "1", "on", "true") for x in values) else 0


def _is_person_list(value: str) -> bool:
    """Names of people (optionally comma separated): letters, spaces, . , ' - & only."""
    return any(ch.isalpha() for ch in value) and all(
        ch.isalpha() or ch in _PERSON_EXTRA_CHARS for ch in value
    )


def validate_report(data: Mapping[str, Any]) -> tuple[dict, dict]:
    v = Validator(data)
    v.text("title", required=True, max_len=SHORT, label="Report title")
    v.text("client_name", max_len=SHORT, label="Client")
    assessor = v.text("assessor", max_len=SHORT, label="Assessor(s)")
    if assessor and "assessor" not in v.errors and not _is_person_list(assessor):
        v.errors["assessor"] = (
            "Assessor(s) may contain only letters, spaces, commas, dots, apostrophes, "
            "hyphens and '&' (no digits)."
        )
    start = v.iso_date("start_date", label="Start date")
    end = v.iso_date("end_date", label="End date")
    if start and end and end < start:
        v.errors["end_date"] = "End date cannot be before the start date."
    v.choice("language", LANGUAGES, "en", label="Report language")

    prefix_raw = data.get("finding_prefix")
    if isinstance(prefix_raw, str):
        prefix = prefix_raw.strip().upper() or "VULN"
        if not _PREFIX_RE.match(prefix):
            v.errors["finding_prefix"] = (
                "Finding ID prefix must start with a letter and contain 1-10 letters/digits (A-Z, 0-9)."
            )
        v.clean["finding_prefix"] = prefix
    elif prefix_raw is None:
        v.clean["finding_prefix"] = "VULN"
    else:
        v.errors["finding_prefix"] = "Finding ID prefix must be text."

    v.text("vendor_name", max_len=SHORT, label="Prepared by (company)")
    v.text("vendor_contact", max_len=SHORT, label="Contact")
    report_version = v.text("report_version", max_len=20, label="Report version")
    if report_version and "report_version" not in v.errors and not _VERSION_RE.match(report_version):
        v.errors["report_version"] = "Report version may contain letters, digits, '.', '-' and '_' (e.g. 1.0, 2.1-rc)."
    v.iso_date("report_date", label="Report date")
    v.text("classification", max_len=60, label="Confidentiality label")
    id_format = v.text("id_format", max_len=ids.MAX_TEMPLATE_LEN, label="Finding ID format")
    if id_format and "id_format" not in v.errors:
        error = ids.template_error(id_format)
        if error:
            v.errors["id_format"] = error

    for field in ("executive_summary", "scope", "methodology"):
        v.text(field, max_len=LONG, multiline=True)
    for field in ("show_version_history", "show_finding_history"):
        v.clean[field] = _switch(data, field, default=1)
    v.clean["group_by_cwe"] = _switch(data, "group_by_cwe", default=0)
    return v.clean, v.errors


_HEX_COLOR_RE = re.compile(r"^#?([0-9A-Fa-f]{6})$")
DEFAULT_BRAND_COLOR = "1D3557"


def validate_brand_color(value: Any) -> tuple[str | None, str | None]:
    """Returns (RRGGBB, error)."""
    if not isinstance(value, str) or not _HEX_COLOR_RE.match(value.strip()):
        return None, "Colour must be a hex value like #1D3557."
    return _HEX_COLOR_RE.match(value.strip()).group(1).upper(), None


def validate_settings(data: Mapping[str, Any]) -> tuple[dict, dict]:
    v = Validator(data)
    id_format = v.text("id_format", required=True, max_len=ids.MAX_TEMPLATE_LEN, label="ID format")
    if id_format and "id_format" not in v.errors:
        error = ids.template_error(id_format)
        if error:
            v.errors["id_format"] = error
    start = v.text("id_start", required=True, max_len=4, label="First number")
    if start and "id_start" not in v.errors:
        if not start.isdigit() or int(start) > ids.MAX_START:
            v.errors["id_start"] = f"First number must be a whole number from 0 to {ids.MAX_START}."
        else:
            v.clean["id_start"] = int(start)
    v.choice("default_language", LANGUAGES, "en", label="Default report language")
    prefix = v.text("default_prefix", required=True, max_len=10, label="Default prefix").upper()
    if prefix and "default_prefix" not in v.errors:
        if not _PREFIX_RE.match(prefix):
            v.errors["default_prefix"] = "Prefix must start with a letter and contain 1-10 letters/digits (A-Z, 0-9)."
        v.clean["default_prefix"] = prefix
    return v.clean, v.errors


def validate_ai_settings(data: Mapping[str, Any]) -> tuple[dict, dict]:
    """Ollama assistant settings. The URL may only point at this machine (SSRF guard)."""
    from ptreport import ai

    v = Validator(data)
    enabled = data.get("enabled") in ("1", "on", "true", True)
    v.clean["enabled"] = enabled
    url = ai.normalise_url(v.text("url", required=True, max_len=ai.MAX_URL_LEN, label="Ollama URL"))
    if "url" not in v.errors:
        problem = ai.url_problem(url)
        if problem:
            v.errors["url"] = problem
        v.clean["url"] = url
    model = v.text("model", max_len=ai.MAX_MODEL_LEN, label="Model")
    if "model" not in v.errors:
        if model or enabled:
            problem = ai.model_problem(model)
            if problem:
                v.errors["model"] = problem if model else "Choose a model to enable the assistant."
    return v.clean, v.errors


def validate_target(data: Mapping[str, Any]) -> tuple[dict, dict]:
    v = Validator(data)
    v.text("name", required=True, max_len=200, label="Target name")
    v.choice("kind", TARGET_KINDS, "web", label="Target type")
    v.text("address", max_len=2048, label="Address / URL / IP range")
    v.text("description", max_len=LONG, multiline=True)
    return v.clean, v.errors


def normalize_cwe(value: str) -> str | None:
    m = _CWE_RE.match(value.strip())
    if not m:
        return None
    number = int(m.group(1))
    return f"CWE-{number}" if number > 0 else None


def validate_finding(data: Mapping[str, Any], target_ids_raw: Any = None) -> tuple[dict, dict]:
    v = Validator(data)
    v.text("title", required=True, max_len=SHORT, label="Vulnerability title")
    v.choice("status", FINDING_STATUSES, "open")

    version = v.choice("cvss_version", ("",) + CVSS_VERSIONS, "", label="CVSS version")
    vector = v.text("cvss_vector", max_len=512, label="CVSS vector")
    v.clean["cvss_score"] = None
    if version and "cvss_vector" not in v.errors:
        if not vector:
            v.errors["cvss_vector"] = "Select all base metrics or paste a CVSS vector."
        else:
            try:
                result = score_vector(vector, expected_version=version)
            except CvssInvalid as exc:
                v.errors["cvss_vector"] = str(exc)
            else:
                v.clean["cvss_vector"] = result.vector
                v.clean["cvss_score"] = result.score
    elif not version:
        v.clean["cvss_vector"] = ""

    # Severity is the tester's own risk assessment and is never derived from CVSS; the CVSS rating
    # (None/Low/Medium/High/Critical) is computed from the score wherever it is shown.
    if data.get("severity") in (None, ""):
        v.errors["severity"] = "Choose the severity (your risk assessment)."
    else:
        v.choice("severity", SEVERITIES, "info", label="Severity")

    v.choice("confidence", ("",) + CONFIDENCE_LEVELS, "", label="Confidence")
    v.choice("retest_result", ("",) + RETEST_RESULTS, "", label="Retest result")
    v.iso_date("retest_date", label="Retest date")
    v.text("retest_notes", max_len=LONG, multiline=True, label="Retest notes")

    external_id = v.text("external_id", max_len=32, label="Finding ID")
    if external_id and "external_id" not in v.errors and not _EXTERNAL_ID_RE.match(external_id):
        v.errors["external_id"] = (
            "Finding ID may contain letters, digits, '.', '_', ':' and '-' (max 32), starting with a letter or digit."
        )

    cwe = v.text("cwe", max_len=12, label="CWE")
    if cwe and "cwe" not in v.errors:
        normalized = normalize_cwe(cwe)
        if normalized is None:
            v.errors["cwe"] = "CWE must look like CWE-79 (or just 79)."
        else:
            v.clean["cwe"] = normalized

    for field in ("description", "impact", "technical_details", "poc", "remediation", "refs"):
        v.text(field, max_len=LONG, multiline=True)

    raw_ids = target_ids_raw if target_ids_raw is not None else data.get("target_ids")
    v.id_list("target_ids", raw_ids)
    return v.clean, v.errors


def validate_evidence(data: Mapping[str, Any]) -> tuple[dict, dict]:
    v = Validator(data)
    v.text("title", max_len=SHORT, label="Evidence title")
    request = v.text("request", max_len=HTTP_MESSAGE_MAX, multiline=True, strip=False,
                     label="HTTP request")
    v.text("response", max_len=HTTP_MESSAGE_MAX, multiline=True, strip=False, label="HTTP response")
    v.choice("source", ("manual", "burp", "import"), "manual")
    if not request.strip() and "request" not in v.errors:
        v.errors["request"] = "HTTP request is required."
    return v.clean, v.errors


def _author(v: Validator) -> None:
    author = v.text("author", max_len=200, label="Author")
    if author and "author" not in v.errors and not _is_person_list(author):
        v.errors["author"] = "Author may contain only letters, spaces, commas, dots, apostrophes, hyphens and '&'."


def validate_report_version(data: Mapping[str, Any]) -> tuple[dict, dict]:
    v = Validator(data)
    version = v.text("version", required=True, max_len=20, label="Version")
    if version and "version" not in v.errors and not _VERSION_RE.match(version):
        v.errors["version"] = "Version may contain letters, digits, '.', '-' and '_' (e.g. 0.1, 1.0)."
    v.iso_date("date", label="Date")
    _author(v)
    v.text("description", max_len=SHORT, label="Description")
    return v.clean, v.errors


def validate_history_entry(data: Mapping[str, Any]) -> tuple[dict, dict]:
    """A manual entry in a finding's history (status changes are recorded automatically)."""
    v = Validator(data)
    v.iso_date("date", label="Date")
    if not v.clean.get("date") and "date" not in v.errors:
        v.errors["date"] = "Date is required."
    _author(v)
    v.text("description", required=True, max_len=SHORT, label="Description")
    kind = data.get("kind") or "note"
    if kind not in ("note", "status"):
        v.errors["kind"] = "Unknown entry type."
    v.clean["kind"] = kind
    for field in ("status_from", "status_to"):
        value = data.get(field) or ""
        if value and value not in FINDING_STATUSES:
            v.errors[field] = "Unknown status."
        v.clean[field] = value
    if kind == "status" and not v.clean["status_to"]:
        v.errors["status_to"] = "A status entry needs the new status."
    if kind == "status" and "description" in v.errors and v.clean["status_to"]:
        del v.errors["description"]  # status entries describe themselves
    return v.clean, v.errors


# PNG and JPEG only: they are what the LaTeX/PDF export can embed (GIF/WebP cannot be typeset).
_IMAGE_SIGNATURES = (
    (b"\x89PNG\r\n\x1a\n", "image/png"),
    (b"\xff\xd8\xff", "image/jpeg"),
)


def sniff_image(data: bytes) -> str | None:
    """MIME type from the file's magic bytes (never from its name or the client). SVG, GIF, WebP are not accepted."""
    for signature, mime in _IMAGE_SIGNATURES:
        if data.startswith(signature):
            return mime
    return None


def validate_attachment(caption: Any, data: bytes | None) -> tuple[dict, dict]:
    v = Validator({"caption": caption})
    v.text("caption", max_len=SHORT, label="Caption")
    if not data:
        v.errors["file"] = "Choose an image file."
    elif len(data) > IMAGE_MAX_BYTES:
        v.errors["file"] = f"Image must be at most {IMAGE_MAX_BYTES // (1024 * 1024)} MB."
    else:
        mime = sniff_image(data)
        if mime is None:
            v.errors["file"] = "Only PNG and JPEG images are accepted (they can be embedded in the PDF)."
        else:
            v.clean["mime"] = mime
            v.clean["data"] = data
    return v.clean, v.errors


# ------------------------------------------------------------------ evidence files --

# MIME type by extension, from this fixed table only: the client's Content-Type and the system's mimetypes
# database are never used. Unknown extensions become application/octet-stream.
FILE_TYPES = {
    "txt": "text/plain", "log": "text/plain", "md": "text/markdown", "nmap": "text/plain", "gnmap": "text/plain",
    "csv": "text/csv", "tsv": "text/tab-separated-values",
    "json": "application/json", "har": "application/json", "xml": "application/xml", "yaml": "application/yaml",
    "yml": "application/yaml", "html": "text/html", "htm": "text/html", "xhtml": "application/xhtml+xml",
    "svg": "image/svg+xml", "js": "text/javascript", "mjs": "text/javascript", "css": "text/css",
    "py": "text/x-python", "sh": "application/x-sh", "ps1": "text/plain", "rb": "text/x-ruby",
    "pl": "text/x-perl", "php": "application/x-httpd-php", "sql": "application/sql",
    "pdf": "application/pdf", "zip": "application/zip", "gz": "application/gzip", "tgz": "application/gzip",
    "tar": "application/x-tar", "7z": "application/x-7z-compressed", "bz2": "application/x-bzip2",
    "xz": "application/x-xz", "rar": "application/vnd.rar",
    "pcap": "application/vnd.tcpdump.pcap", "pcapng": "application/vnd.tcpdump.pcap",
    "cap": "application/vnd.tcpdump.pcap", "png": "image/png", "jpg": "image/jpeg", "jpeg": "image/jpeg",
}
# Types a download may be labelled with. Everything else (HTML, SVG, XML, JS, PDF, scripts ...) is served as
# application/octet-stream, so a browser can never render it as active content, even outside the attachment
# disposition.
SAFE_DOWNLOAD_TYPES = frozenset({
    "text/plain", "text/csv", "text/tab-separated-values", "application/json", "application/zip",
    "application/gzip", "application/x-tar", "application/x-7z-compressed", "application/x-bzip2",
    "application/x-xz", "application/vnd.rar", "application/vnd.tcpdump.pcap", "image/png", "image/jpeg",
})
_FILE_KINDS = {
    "text": ("txt", "log", "md", "csv", "tsv", "nmap", "gnmap"),
    "code": ("json", "har", "xml", "yaml", "yml", "html", "htm", "xhtml", "svg", "js", "mjs", "css", "py", "sh",
             "ps1", "rb", "pl", "php", "sql", "bat", "go", "java", "c", "ts"),
    "archive": ("zip", "gz", "tgz", "tar", "7z", "bz2", "xz", "rar"),
    "capture": ("pcap", "pcapng", "cap"),
}
_EXT_KIND = {ext: kind for kind, exts in _FILE_KINDS.items() for ext in exts}
_RESERVED_FILENAME_CHARS = re.compile(r'[<>:"|?*]')
_WINDOWS_DEVICE = re.compile(r"^(con|prn|aux|nul|com[0-9]|lpt[0-9])(\.|$)", re.IGNORECASE)
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$")


def file_extension(filename: str) -> str:
    stem, dot, ext = filename.rpartition(".")
    return ext.lower() if dot and stem else ""


def guess_file_type(filename: str) -> str:
    return FILE_TYPES.get(file_extension(filename), "application/octet-stream")


def file_kind(filename: str) -> str:
    """Icon family of a file: text, code, archive, capture or file."""
    return _EXT_KIND.get(file_extension(filename), "file")


def download_type(mime: str) -> str:
    return mime if mime in SAFE_DOWNLOAD_TYPES else "application/octet-stream"


def sanitize_filename(value: Any) -> str:
    """A display/download name: no directories, control or format characters (e.g. right-to-left override),
    no characters reserved on Windows, no leading dots, at most FILENAME_MAX characters (extension kept).
    Returns '' when nothing usable is left."""
    if not isinstance(value, str):
        return ""
    name = unicodedata.normalize("NFC", value).replace("\\", "/").rsplit("/", 1)[-1]
    name = "".join(ch for ch in name if unicodedata.category(ch)[0] != "C")
    name = _RESERVED_FILENAME_CHARS.sub("_", name)
    name = re.sub(r"\s+", " ", name).strip(" .")
    if not name or not any(ch.isalnum() for ch in name):
        return ""
    if _WINDOWS_DEVICE.match(name):
        name = "_" + name
    if len(name) > FILENAME_MAX:
        stem, dot, ext = name.rpartition(".")
        if dot and stem and len(ext) <= 16:
            name = stem[: FILENAME_MAX - len(ext) - 1].rstrip(" .") + "." + ext
        else:
            name = name[:FILENAME_MAX].rstrip(" .")
    return name


def validate_file(filename: Any, description: Any, data: bytes | None) -> tuple[dict, dict]:
    """An evidence file upload. The SHA-256 and the MIME type are always computed here, on the server."""
    v = Validator({"description": description})
    v.text("description", max_len=SHORT, label="Description")
    name = sanitize_filename(filename)
    if not name:
        v.errors["file"] = "The file needs a usable name (letters or digits, not only dots or slashes)."
    elif data is None:
        v.errors["file"] = "Choose a file."
    elif len(data) == 0:
        v.errors["file"] = f"{name}: the file is empty."
    elif len(data) > FILE_MAX_BYTES:
        v.errors["file"] = f"{name}: files must be at most {FILE_MAX_BYTES // (1024 * 1024)} MB."
    else:
        v.clean.update(filename=name, mime=guess_file_type(name), data=data, size=len(data),
                       sha256=hashlib.sha256(data).hexdigest())
    return v.clean, v.errors


def check_file_quota(existing_count: int, existing_bytes: int, new_sizes: list[int]) -> str | None:
    """Per-finding limits (number of files and total size); returns an error message or None."""
    if existing_count + len(new_sizes) > FILE_MAX_PER_FINDING:
        return f"A finding can have at most {FILE_MAX_PER_FINDING} files."
    if existing_bytes + sum(new_sizes) > FILE_MAX_TOTAL_PER_FINDING:
        left = max(0, FILE_MAX_TOTAL_PER_FINDING - existing_bytes) / (1024 * 1024)
        return (f"Files of one finding can take at most {FILE_MAX_TOTAL_PER_FINDING // (1024 * 1024)} MB "
                f"in total ({left:.1f} MB left).")
    return None


def validate_uploads(uploads: list, description: Any, existing: tuple[int, int]) -> tuple[list[dict], dict]:
    """Validate a batch of uploaded files (werkzeug FileStorage), all or nothing, including the per-finding
    limits given the finding's current (count, bytes). Shared by the web UI and the API."""
    cleaned, problems, errors = [], [], {}
    uploads = [u for u in uploads if u is not None and (u.filename or u.content_length)]
    if not uploads:
        errors["file"] = "Choose at least one file."
    elif existing[0] + len(uploads) > FILE_MAX_PER_FINDING:
        errors["file"] = check_file_quota(existing[0], existing[1], [0] * len(uploads))
        return [], errors  # checked before reading anything into memory
    for upload in uploads:
        data = upload.read(FILE_MAX_BYTES + 1)
        clean, errs = validate_file(upload.filename, description, data)
        if "description" in errs:
            errors["description"] = errs["description"]
        if "file" in errs:
            problems.append(errs["file"])
        else:
            cleaned.append(clean)
    if problems:
        errors["file"] = " ".join(problems[:10])
    if not errors:
        quota = check_file_quota(*existing, [c["size"] for c in cleaned])
        if quota:
            errors["file"] = quota
    return cleaned, errors


def is_sha256(value: Any) -> bool:
    return isinstance(value, str) and bool(_SHA256_RE.match(value))


def is_timestamp(value: Any) -> bool:
    return isinstance(value, str) and bool(_TIMESTAMP_RE.match(value))


_JPEG_SOF = {0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF}


def image_dimensions(data: bytes) -> tuple[int, int] | None:
    """(width, height) read from a PNG IHDR or a JPEG SOF segment; None when the header is malformed."""
    mime = sniff_image(data)
    if mime == "image/png":
        if len(data) < 33 or data[12:16] != b"IHDR":
            return None
        width, height = int.from_bytes(data[16:20], "big"), int.from_bytes(data[20:24], "big")
        return (width, height) if width and height else None
    if mime == "image/jpeg":
        pos = 2
        while pos + 4 <= len(data):
            if data[pos] != 0xFF:
                return None
            marker = data[pos + 1]
            if marker == 0xFF:  # fill byte
                pos += 1
                continue
            if marker in (0xD8, 0x01) or 0xD0 <= marker <= 0xD7:  # markers without a length
                pos += 2
                continue
            if marker in (0xD9, 0xDA):  # end of image / start of scan before any frame header
                return None
            length = int.from_bytes(data[pos + 2:pos + 4], "big")
            if length < 2:
                return None
            if marker in _JPEG_SOF:
                if pos + 9 > len(data):
                    return None
                height = int.from_bytes(data[pos + 5:pos + 7], "big")
                width = int.from_bytes(data[pos + 7:pos + 9], "big")
                return (width, height) if width and height else None
            pos += 2 + length
    return None


def validate_edited_image(data: bytes | None, source: bytes) -> tuple[dict, dict]:
    """An edited screenshot from the in-browser editor: a real PNG/JPEG within the upload limits whose
    dimensions are sane and not larger than the image it was made from (the editor only crops)."""
    clean, errors = validate_attachment("", data)
    if errors:
        return {}, errors
    size = image_dimensions(clean["data"])
    if size is None:
        return {}, {"file": "The edited image is damaged (its header cannot be read)."}
    if clean["mime"] == "image/png" and not clean["data"].endswith(b"IEND\xaeB`\x82"):
        return {}, {"file": "The edited image is incomplete."}
    width, height = size
    if width > IMAGE_MAX_SIDE or height > IMAGE_MAX_SIDE:
        return {}, {"file": f"The edited image must be at most {IMAGE_MAX_SIDE} pixels wide and high."}
    limit = image_dimensions(source)
    if limit is not None and (width > limit[0] or height > limit[1]):
        return {}, {"file": f"The edited image ({width}×{height}) is larger than the original "
                            f"({limit[0]}×{limit[1]})."}
    clean.pop("caption", None)
    clean["width"], clean["height"] = width, height
    return clean, {}


# Built-in section kinds; "text" is a custom section whose body is stored with it.
SECTION_KINDS = ("executive_summary", "scope", "methodology", "findings_table", "charts", "summary", "findings",
                 "retest_summary", "text")


def validate_section(data: Mapping[str, Any]) -> tuple[dict, dict]:
    v = Validator(data)
    v.choice("kind", SECTION_KINDS, "text", label="Section type")
    v.text("title", required=v.clean.get("kind") == "text", max_len=SHORT, label="Title")
    v.text("body", max_len=LONG, multiline=True, label="Text")
    level = data.get("level")
    v.clean["level"] = 2 if str(level) == "2" else 1
    v.clean["numbered"] = _switch(data, "numbered", default=1)
    v.clean["new_page"] = _switch(data, "new_page", default=0)
    v.clean["enabled"] = _switch(data, "enabled", default=1)
    return v.clean, v.errors


def validate_cwe_note(data: Mapping[str, Any]) -> tuple[dict, dict]:
    v = Validator(data)
    cwe = data.get("cwe") or ""
    if cwe and normalize_cwe(str(cwe)) is None:
        v.errors["cwe"] = "CWE must look like CWE-79."
    v.clean["cwe"] = normalize_cwe(str(cwe)) if cwe else ""
    v.text("title", max_len=SHORT, label="Group title")
    v.text("description", max_len=LONG, multiline=True, label="Description")
    v.text("mitigation", max_len=LONG, multiline=True, label="Mitigation")
    return v.clean, v.errors


TEMPLATE_FIELDS = (
    "title", "severity", "cvss_version", "cvss_vector", "cwe", "description", "impact", "technical_details",
    "poc", "remediation", "refs",
)


def validate_template(data: Mapping[str, Any]) -> tuple[dict, dict]:
    """A finding template: the reusable part of a finding (no targets, status, evidence) plus language and tags."""
    clean, errors = validate_finding(data, target_ids_raw=[])
    out = {f: clean.get(f, "") for f in TEMPLATE_FIELDS}
    errors = {k: v for k, v in errors.items() if k in TEMPLATE_FIELDS}
    v = Validator(data)
    v.choice("language", LANGUAGES, "en", label="Language")
    v.text("tags", max_len=SHORT, label="Tags")
    out.update(v.clean)
    errors.update(v.errors)
    return out, errors


def validate_note(data: Mapping[str, Any]) -> tuple[dict, dict]:
    """A working note of a report: title, free text (same mark-up as other text fields), pinned flag."""
    v = Validator(data)
    v.text("title", required=True, max_len=SHORT, label="Title")
    v.text("body", max_len=LONG, multiline=True, strip=False, label="Note")
    v.clean["body"] = v.clean.get("body", "").rstrip()
    pinned = data.get("pinned")
    v.clean["pinned"] = 1 if pinned in (True, 1, "1", "on", "true") else 0
    return v.clean, v.errors
