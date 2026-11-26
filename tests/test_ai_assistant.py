"""Local writing assistant (Ollama): SSRF guard, settings, endpoint and error handling.

Ollama is replaced by a tiny threaded HTTP server on 127.0.0.1.
"""

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from ptreport import ai, repo
from ptreport.db import connect


class MockOllama:
    def __init__(self):
        self.requests = []
        self.models = ["qwen2.5:3b", "llama3.2:latest"]
        self.reply = "Suggested **text** <script>alert(1)</script>"
        self.mode = "ok"
        mock = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _send(self, code, body, ctype="application/json", headers=None):
                raw = body if isinstance(body, bytes) else json.dumps(body).encode()
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(raw)))
                for k, v in (headers or {}).items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(raw)

            def do_GET(self):
                mock.requests.append(("GET", self.path, None))
                if self.path == "/api/tags":
                    self._send(200, {"models": [{"name": m} for m in mock.models]})
                else:
                    self._send(404, {"error": "not found"})

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                mock.requests.append(("POST", self.path, body))
                if mock.mode == "slow":
                    time.sleep(1.5)
                if mock.mode == "missing":
                    return self._send(404, {"error": f'model "{body["model"]}" not found, try pulling it first'})
                if mock.mode == "redirect":
                    return self._send(302, {}, headers={"Location": "http://example.com/steal"})
                if mock.mode == "garbage":
                    return self._send(200, b"<html>not json</html>", "text/html")
                if mock.mode == "error":
                    return self._send(500, {"error": "CUDA out of memory"})
                self._send(200, {"model": body["model"], "done": True,
                                 "message": {"role": "assistant", "content": "<think>hmm</think>\n" + mock.reply}})

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()

    @property
    def chats(self):
        return [r[2] for r in self.requests if r[1] == "/api/chat"]


@pytest.fixture()
def ollama():
    mock = MockOllama()
    yield mock
    mock.close()


def _closed_port_url():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), BaseHTTPRequestHandler)
    port = srv.server_address[1]
    srv.server_close()
    return f"http://127.0.0.1:{port}"


def enable(client, csrf, url, model="qwen2.5:3b"):
    resp = client.post("/settings/ai", data={"_csrf": csrf, "enabled": "1", "url": url, "model": model})
    assert resp.status_code == 302, resp.get_data(as_text=True)


def assist(client, csrf, report_id, **overrides):
    body = {"report_id": report_id, "field": "description", "action": "improve", "title": "SQL injection",
            "cwe": "CWE-89", "severity": "high", "description": "the app is vulnerable to sqli in id param",
            "impact": "", "technical_details": "", "remediation": ""}
    body.update(overrides)
    return client.post("/ai/assist", json=body, headers={"X-CSRF-Token": csrf})


# ------------------------------------------------------------------ URL guard --

@pytest.mark.parametrize("url", [
    "http://127.0.0.1:11434", "http://127.0.0.1:11434/", "http://localhost:11434", "https://[::1]:11434",
    "http://LOCALHOST:8080", "http://127.0.0.1",
])
def test_url_guard_accepts_loopback(url):
    assert ai.url_problem(url) is None


@pytest.mark.parametrize("url", [
    "", "http://example.com:11434", "http://10.0.0.5:11434", "http://192.168.1.10:11434",
    "http://169.254.169.254/latest/meta-data", "http://169.254.169.254", "http://0.0.0.0:11434",
    "http://127.0.0.2:11434", "http://127.1:11434", "http://2130706433", "http://[::ffff:127.0.0.1]:11434",
    "file:///etc/passwd", "ftp://127.0.0.1", "gopher://127.0.0.1:11434", "javascript:alert(1)",
    "http://user:pw@127.0.0.1:11434", "http://127.0.0.1@evil.com", "http://evil.com#@127.0.0.1",
    "http://127.0.0.1.nip.io:11434", "http://127.0.0.1:11434/api/../x", "http://127.0.0.1:11434?x=1",
    "http://127.0.0.1:99999", "http://127.0.0.1:11434\n", "http:// 127.0.0.1", "http://" + "a" * 300,
])
def test_url_guard_rejects_everything_else(url):
    assert ai.url_problem(url)


def test_request_layer_rechecks_url():
    with pytest.raises(ai.AiError) as exc:
        ai.list_models("http://169.254.169.254")
    assert exc.value.status == 400


# ------------------------------------------------------------------- settings --

def test_settings_default_off_and_save(client, csrf):
    page = client.get("/settings").get_data(as_text=True)
    assert 'id="ai-assistant"' in page and "http://127.0.0.1:11434" in page
    assert 'name="enabled" value="1" checked' not in page
    conn = connect(client.application.config["DATABASE"])
    assert repo.get_ai_settings(conn) == {"enabled": False, "url": "http://127.0.0.1:11434", "model": ""}
    enable(client, csrf, "http://localhost:11434/", "llama3.2:3b")
    assert repo.get_ai_settings(conn) == {"enabled": True, "url": "http://localhost:11434", "model": "llama3.2:3b"}
    assert 'name="enabled" value="1" checked' in client.get("/settings").get_data(as_text=True)
    # switching off keeps URL and model
    client.post("/settings/ai", data={"_csrf": csrf, "url": "http://localhost:11434", "model": "llama3.2:3b"})
    assert repo.get_ai_settings(conn)["enabled"] is False
    conn.close()


@pytest.mark.parametrize("form, field", [
    ({"enabled": "1", "url": "http://169.254.169.254", "model": "x"}, "url"),
    ({"enabled": "1", "url": "file:///etc/passwd", "model": "x"}, "url"),
    ({"enabled": "1", "url": "http://ollama.example.com:11434", "model": "x"}, "url"),
    ({"enabled": "1", "url": "", "model": "x"}, "url"),
    ({"enabled": "1", "url": "http://127.0.0.1:11434", "model": ""}, "model"),
    ({"enabled": "1", "url": "http://127.0.0.1:11434", "model": "bad model; rm -rf"}, "model"),
    ({"url": "http://127.0.0.1:11434", "model": "x" * 101}, "model"),
])
def test_settings_validation(client, csrf, form, field):
    resp = client.post("/settings/ai", data={"_csrf": csrf, **form})
    assert resp.status_code == 422
    assert f'aria-describedby="ai-{field}-error"' in resp.get_data(as_text=True)
    conn = connect(client.application.config["DATABASE"])
    assert repo.get_ai_settings(conn)["enabled"] is False
    conn.close()


def test_settings_csrf(client):
    assert client.post("/settings/ai", data={"enabled": "1", "url": "http://127.0.0.1:11434",
                                             "model": "x"}).status_code == 400
    assert client.post("/settings/ai/models", json={"url": "http://127.0.0.1:11434"}).status_code == 400
    assert client.post("/settings/ai/test", json={"url": "http://127.0.0.1:11434"}).status_code == 400
    assert client.post("/ai/assist", json={}).status_code == 400


def test_load_models_and_test_connection(client, csrf, ollama):
    h = {"X-CSRF-Token": csrf}
    resp = client.post("/settings/ai/models", json={"url": ollama.url}, headers=h)
    assert resp.status_code == 200 and resp.get_json() == {"models": ["llama3.2:latest", "qwen2.5:3b"]}
    resp = client.post("/settings/ai/test", json={"url": ollama.url, "model": "qwen2.5:3b"}, headers=h)
    assert resp.status_code == 200 and "is available" in resp.get_json()["message"]
    resp = client.post("/settings/ai/test", json={"url": ollama.url, "model": "llama3.2"}, headers=h)
    assert resp.status_code == 200  # "llama3.2" means "llama3.2:latest"
    resp = client.post("/settings/ai/test", json={"url": ollama.url, "model": "mistral:7b"}, headers=h)
    assert resp.status_code == 502 and "not installed" in resp.get_json()["error"]
    ollama.models = []
    resp = client.post("/settings/ai/test", json={"url": ollama.url, "model": ""}, headers=h)
    assert resp.status_code == 502 and "no models" in resp.get_json()["error"]


def test_models_endpoint_refuses_remote_hosts(client, csrf, ollama):
    h = {"X-CSRF-Token": csrf}
    for url in ("http://169.254.169.254", "file:///etc/passwd", "http://example.com", 5):
        resp = client.post("/settings/ai/models", json={"url": url}, headers=h)
        assert resp.status_code == 400
    assert client.post("/settings/ai/models", data="nope", headers=h,
                       content_type="application/json").status_code == 400
    assert ollama.requests == []


def test_ollama_down_gives_clear_message(client, csrf):
    url = _closed_port_url()
    resp = client.post("/settings/ai/models", json={"url": url}, headers={"X-CSRF-Token": csrf})
    assert resp.status_code == 502
    assert "not reachable" in resp.get_json()["error"] and "ollama serve" in resp.get_json()["error"]


# --------------------------------------------------------------- finding form --

def test_assist_buttons_only_when_enabled(client, csrf, make_report, make_finding, ollama):
    rid = make_report()
    fid = make_finding(rid)
    for url in (f"/findings/{fid}/edit", f"/reports/{rid}/findings/new"):
        page = client.get(url).get_data(as_text=True)
        assert "data-ai-menu" not in page and "ai-dialog" not in page and "ai.js" not in page
    enable(client, csrf, ollama.url)
    for url in (f"/findings/{fid}/edit", f"/reports/{rid}/findings/new"):
        page = client.get(url).get_data(as_text=True)
        assert page.count("data-ai-menu") == 4
        assert 'data-ai-action="translate_pl" data-ai-field="remediation"' in page
        assert 'id="ai-dialog"' in page and "ai.js" in page
        assert 'data-ai-field="poc"' not in page


def test_assist_disabled_returns_404(client, csrf, make_report, ollama):
    rid = make_report()
    resp = assist(client, csrf, rid)
    assert resp.status_code == 404 and "turned off" in resp.get_json()["error"]
    enable(client, csrf, ollama.url)
    client.post("/settings/ai", data={"_csrf": csrf, "url": ollama.url, "model": "qwen2.5:3b"})
    assert assist(client, csrf, rid).status_code == 404
    assert ollama.requests == []


# ------------------------------------------------------------------- assist --

def test_assist_happy_path_and_prompt_contents(client, csrf, make_report, make_finding, ollama):
    rid = make_report()
    other = make_report(title="Other client", client_name="Globex")
    make_finding(other, title="Globex secret finding", description="GLOBEX-ONLY-TEXT")
    enable(client, csrf, ollama.url)
    resp = assist(client, csrf, rid)
    assert resp.status_code == 200 and resp.mimetype == "application/json"
    data = resp.get_json()
    # reasoning block stripped; the rest returned as plain text (the browser never renders it as HTML)
    assert data == {"text": ollama.reply, "field": "description", "action": "improve"}
    sent = ollama.chats[-1]
    assert sent["model"] == "qwen2.5:3b" and sent["stream"] is False
    prompt = "\n".join(m["content"] for m in sent["messages"])
    assert "SQL injection" in prompt and "sqli in id param" in prompt
    assert "CWE-89" in prompt and "Improper Neutralization" in prompt
    assert "GLOBEX" not in prompt and "Globex" not in prompt
    assert sent["messages"][0]["role"] == "system" and "Do not invent facts" in sent["messages"][0]["content"]


def test_assist_draft_uses_other_fields_and_report_language(client, csrf, make_report, ollama):
    rid = make_report(language="pl")
    enable(client, csrf, ollama.url)
    resp = assist(client, csrf, rid, action="draft", field="remediation", description="", impact="Wyciek danych",
                  remediation="old text")
    assert resp.status_code == 200
    sent = ollama.chats[-1]["messages"]
    assert "Jesteś asystentem" in sent[0]["content"]
    assert "Napisz pole „Rekomendacja" in sent[1]["content"] and "po polsku" in sent[1]["content"]
    assert "Wyciek danych" in sent[1]["content"] and "old text" not in sent[1]["content"]


def test_assist_translate_direction(client, csrf, make_report, ollama):
    rid = make_report(language="pl")
    enable(client, csrf, ollama.url)
    assert assist(client, csrf, rid, action="translate_en").status_code == 200
    sent = ollama.chats[-1]["messages"]
    assert "You are a writing assistant" in sent[0]["content"]
    assert "na język angielski" in sent[1]["content"]
    assert assist(client, csrf, rid, action="translate_pl").status_code == 200
    assert "na język polski" in ollama.chats[-1]["messages"][1]["content"]


def test_assist_validation(client, csrf, make_report, ollama):
    rid = make_report()
    enable(client, csrf, ollama.url)
    h = {"X-CSRF-Token": csrf}
    assert assist(client, csrf, rid, field="poc").status_code == 400
    assert assist(client, csrf, rid, field="refs").status_code == 400
    assert assist(client, csrf, rid, action="hack").status_code == 400
    assert assist(client, csrf, rid, title=["x"]).status_code == 400
    assert assist(client, csrf, "1").status_code == 400
    assert assist(client, csrf, True).status_code == 400
    assert assist(client, csrf, 9999).status_code == 404
    resp = assist(client, csrf, rid, description="   ")
    assert resp.status_code == 422 and "empty" in resp.get_json()["error"]
    resp = assist(client, csrf, rid, action="draft", title="")
    assert resp.status_code == 422 and "title" in resp.get_json()["error"]
    resp = assist(client, csrf, rid, description="x" * (ai.MAX_FIELD_CHARS + 1))
    assert resp.status_code == 413 and "too long" in resp.get_json()["error"]
    assert assist(client, csrf, rid, title="t" * 301).status_code == 413
    assert client.post("/ai/assist", data="[1]", headers=h, content_type="application/json").status_code == 400
    big = json.dumps({"report_id": rid, "field": "description", "action": "improve", "description": "x" * 300_000})
    assert client.post("/ai/assist", data=big, headers=h, content_type="application/json").status_code == 413
    assert ollama.chats == []
    # a long *other* field is only context: it is cut, not refused
    resp = assist(client, csrf, rid, impact="y" * (ai.MAX_FIELD_CHARS + 500))
    assert resp.status_code == 200
    assert "y" * (ai.MAX_FIELD_CHARS + 1) not in ollama.chats[-1]["messages"][1]["content"]


@pytest.mark.parametrize("mode, status, words", [
    ("missing", 502, "not installed"),
    ("redirect", 502, "redirect"),
    ("garbage", 502, "not valid JSON"),
    ("error", 502, "CUDA out of memory"),
])
def test_assist_ollama_errors(client, csrf, make_report, ollama, mode, status, words):
    rid = make_report()
    enable(client, csrf, ollama.url)
    ollama.mode = mode
    resp = assist(client, csrf, rid)
    assert resp.status_code == status and words in resp.get_json()["error"]


def test_assist_timeout(app, client, csrf, make_report, ollama):
    app.config["AI_TIMEOUT"] = 0.3
    rid = make_report()
    enable(client, csrf, ollama.url)
    ollama.mode = "slow"
    resp = assist(client, csrf, rid)
    assert resp.status_code == 504 and "did not answer" in resp.get_json()["error"]


def test_assist_ollama_down(client, csrf, make_report):
    rid = make_report()
    enable(client, csrf, _closed_port_url())
    resp = assist(client, csrf, rid)
    assert resp.status_code == 502 and "not reachable" in resp.get_json()["error"]


def test_assist_rate_limit(app, client, csrf, make_report, ollama):
    app.config.update(AI_RATE_CAPACITY=2, AI_RATE_PER_SECOND=0.0001)
    rid = make_report()
    enable(client, csrf, ollama.url)
    assert assist(client, csrf, rid).status_code == 200
    assert assist(client, csrf, rid).status_code == 200
    resp = assist(client, csrf, rid)
    assert resp.status_code == 429 and "Too many" in resp.get_json()["error"]
    assert len(ollama.chats) == 2


def test_proxy_environment_is_ignored(monkeypatch, client, csrf, make_report, ollama):
    monkeypatch.setenv("http_proxy", "http://203.0.113.1:3128")
    monkeypatch.setenv("HTTP_PROXY", "http://203.0.113.1:3128")
    monkeypatch.delenv("no_proxy", raising=False)
    monkeypatch.delenv("NO_PROXY", raising=False)
    rid = make_report()
    enable(client, csrf, ollama.url)
    assert assist(client, csrf, rid).status_code == 200


# ---------------------------------------------------------------- unit bits --

def test_clean_output_and_token_bucket():
    assert ai.clean_output("<think>a\nb</think>\n\nHello") == "Hello"
    assert ai.clean_output("```markdown\n- a\n- b\n```") == "- a\n- b"
    assert ai.clean_output("```python\nprint(1)\n```") == "```python\nprint(1)\n```"
    assert len(ai.clean_output("x" * (ai.MAX_OUTPUT_CHARS + 10))) == ai.MAX_OUTPUT_CHARS
    bucket = ai.TokenBucket(1, 1000)
    assert bucket.take()
    time.sleep(0.01)
    assert bucket.take()
    slow = ai.TokenBucket(1, 0.0001)
    assert slow.take() and not slow.take()


def test_build_messages_only_uses_given_fields():
    req = ai.AssistRequest(field="impact", action="shorten", report_language="en", title="XSS",
                           fields={"impact": "Long impact text", "description": "desc"})
    msgs = ai.build_messages(req)
    assert "Long impact text" in msgs[1]["content"] and "desc" not in msgs[1]["content"]
    assert "Shorten" in msgs[1]["content"]
