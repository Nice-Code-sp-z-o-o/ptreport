"""Seed a ptreport data dir with demo engagements through the app's own forms (validation included)."""
import re
import sys

from ptreport.app import create_app

app = create_app({"DATA_DIR": sys.argv[1]})
c = app.test_client()
tok = re.search(r'name="_csrf" value="([^"]+)"', c.get("/reports/new").text).group(1)


def post(url, **data):
    r = c.post(url, data={"_csrf": tok, **data})
    assert r.status_code == 302, (url, r.status_code, r.text[:400])


post("/reports/new", title="ACME Customer Portal – Web Application Penetration Test", client_name="ACME Corp",
     assessor="Jan Kowalski, Anna Nowak", finding_prefix="ACME", language="pl", start_date="2026-11-03",
     end_date="2026-11-14",
     executive_summary="Testy wykazały 5 podatności, w tym jedną krytyczną umożliwiającą odczyt całej bazy danych klientów.\n\nZalecamy priorytetowe usunięcie podatności ACME-001.",
     scope="Testy w modelu grey-box z kontem zwykłego użytkownika.",
     methodology="OWASP WSTG v4.2, OWASP ASVS 4.0.3 (poziom 2).")
post("/reports/1/targets/new", name="Customer portal", kind="web", address="https://portal.acme.example")
post("/reports/1/targets/new", name="Public API", kind="api", address="https://api.acme.example/v2")
post("/reports/1/targets/new", name="Admin panel", kind="web", address="https://admin.acme.example")
post("/reports/1/findings/new", title="SQL Injection w parametrze id (/api/v2/orders)", severity="critical", cvss_version="4.0",
     cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", cwe="89", target_ids=["2"],
     description="Parametr `id` jest bezpośrednio konkatenowany z zapytaniem SQL.",
     impact="Atakujący bez uwierzytelnienia może odczytać i zmodyfikować całą bazę danych.",
     technical_details="Backend: PostgreSQL 15. Błąd występuje w endpointcie GET /api/v2/orders.",
     poc="1. Wyślij żądanie z payloadem boolean-based:\n```\nsqlmap -u 'https://api.acme.example/v2/orders?id=1' --batch --dbs\n```\n2. sqlmap potwierdza podatność i listuje bazy.",
     remediation="Stosować zapytania parametryzowane (prepared statements).",
     refs="https://owasp.org/www-community/attacks/SQL_Injection\nhttps://cwe.mitre.org/data/definitions/89.html")
post("/reports/1/findings/new", title="IDOR – dostęp do zamówień innych użytkowników", severity="high", cvss_version="3.1",
     cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", cwe="639", target_ids=["2"],
     description="Zmiana identyfikatora zamówienia w ścieżce zwraca dane innego klienta.")
post("/reports/1/findings/new", title="Stored XSS w komentarzach", severity="medium", cvss_version="3.1",
     cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N", cwe="79", target_ids=["1"],
     description="Treść komentarza jest renderowana bez kodowania: <script>alert(document.domain)</script>",
     poc="```html\n<img src=x onerror=alert(document.domain)>\n```")
post("/reports/1/findings/new", title="Panel administracyjny dostępny z internetu", severity="medium", cvss_version="4.0",
     cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N", cwe="284", target_ids=["3"],
     status="risk_accepted")
post("/reports/1/findings/new", title="Brak nagłówków bezpieczeństwa", cvss_version="", severity="low", cwe="693",
     target_ids=["1", "2", "3"])
post("/findings/1/evidence", title="Boolean-based payload",
     request="GET /api/v2/orders?id=1%20AND%201=1 HTTP/1.1\nHost: api.acme.example\nAuthorization: Bearer eyJ...\n\n",
     response='HTTP/1.1 200 OK\nContent-Type: application/json\n\n[{"id":1,"total":129.99}]')

post("/reports/new", title="Internal network assessment Q4", client_name="Nordbank S.A.", assessor="Anna Nowak",
     finding_prefix="NB", language="en", start_date="2026-10-06", end_date="2026-10-17")
post("/reports/2/targets/new", name="Corporate LAN", kind="network", address="10.20.0.0/16")
post("/reports/2/findings/new", title="SMB signing not required", severity="high", cvss_version="3.1",
     cvss_vector="CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", cwe="294", target_ids=["4"])
post("/reports/2/findings/new", title="Default credentials on printer web panels", cvss_version="", severity="medium",
     cwe="1392", target_ids=["4"])

post("/reports/new", title="Mobile banking app – iOS & Android", client_name="Nordbank S.A.", assessor="Jan Kowalski",
     finding_prefix="MOB", language="en", start_date="2026-11-17")
print("seeded 3 reports")
