from ptreport.rendering import reference_list, richtext


def test_richtext_escapes_html():
    html = str(richtext("<script>alert(1)</script> and `<b>`"))
    assert "<script>" not in html
    assert "&lt;script&gt;" in html
    assert "<code>&lt;b&gt;</code>" in html


def test_richtext_code_fences():
    html = str(richtext("Steps:\n```http\nGET /?q=<x> HTTP/1.1\n```\nDone"))
    assert '<pre><code class="lang-http">GET /?q=&lt;x&gt; HTTP/1.1</code></pre>' in html
    assert "Steps:" in html and "Done" in html


def test_unclosed_fence_is_plain_text():
    html = str(richtext("```\nno end"))
    assert "<pre>" not in html


def test_reference_list_only_links_http_urls():
    html = str(reference_list("https://owasp.org/x\njavascript:alert(1)\nOWASP ASVS V5"))
    assert '<a href="https://owasp.org/x"' in html
    assert 'href="javascript' not in html
    assert "<li>javascript:alert(1)</li>" in html
