package ptreport.burp;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.persistence.Preferences;
import java.awt.image.BufferedImage;
import java.io.File;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.imageio.ImageIO;
import javax.swing.SwingUtilities;

/**
 * Runs the extension's own code (Message, ApiClient, Json, SendDialog) against a running ptreport, with Burp's
 * objects replaced by small stand-ins. Usage: java ... IntegrationCheck URL TOKEN REPORT_ID [screenshot.png]
 */
public final class IntegrationCheck {
    private static int failures;

    public static void main(String[] args) throws Exception {
        String url = args[0];
        String token = args[1];
        long reportId = Long.parseLong(args[2]);

        Settings settings = new Settings(preferences());
        settings.save(url, token);
        ApiClient api = new ApiClient(settings);

        // --- JSON round trip with awkward characters
        String tricky = "line1\r\nline2\t\"quoted\" \\ back \u0001 zażółć <html>";
        Object back = Json.parse(Json.write(Map.of("s", tricky)));
        check("JSON round trip", tricky.equals(Json.obj(back).get("s")));

        // --- connection and lists
        check("ping", !api.ping().isEmpty());
        check("reports listed", api.reports().stream().anyMatch(r -> Json.num(r, "id") == reportId));
        List<String[]> cwes = api.cwes();
        check("CWE catalogue loaded (" + cwes.size() + ")", cwes.size() > 900 && cwes.stream().anyMatch(c -> c[0].equals("CWE-79")));

        // --- a Burp request/response pair
        String rawReq = "POST /api/comments?debug=1 HTTP/1.1\r\nHost: shop.example.com\r\nContent-Type: application/json\r\n\r\n"
                + "{\"body\":\"<script>alert(1)</script>\",\"name\":\"Zażółć\"}";
        String rawResp = "HTTP/1.1 201 Created\r\nContent-Type: text/html\r\n\r\n<p><script>alert(1)</script></p>";
        Message m = Message.of(requestResponse("POST", "/api/comments", rawReq, rawResp, "shop.example.com", 443, true));
        check("message origin", m.origin().equals("https://shop.example.com"));
        check("message title", m.defaultTitle().equals("POST /api/comments"));
        check("UTF-8 kept", m.request().contains("Zażółć"));
        Message noResp = Message.of(requestResponse("GET", "/admin", "GET /admin HTTP/1.1\r\nHost: shop.example.com:8443\r\n\r\n",
                null, "shop.example.com", 8443, true));
        check("non-default port in origin", noResp.origin().equals("https://shop.example.com:8443"));
        check("no response -> empty", noResp.response().isEmpty());
        byte[] big = new byte[Message.MAX_CHARS + 1000];
        java.util.Arrays.fill(big, (byte) 'A');
        check("huge message truncated", Message.text(big).endsWith(Message.TRUNCATED));

        // --- new finding with target and two evidence items (what the dialog sends)
        long targetId = api.createTarget(reportId, m.host(), "web", m.origin());
        check("target created", targetId > 0);
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("title", "Stored XSS in comments (from Burp)");
        body.put("severity", "high");
        body.put("status", "open");
        body.put("cwe", "CWE-79");
        body.put("cvss_version", "");
        body.put("target_ids", List.of(targetId));
        body.put("evidence", List.of(m.evidence(m.defaultTitle(), true), noResp.evidence("GET /admin", true)));
        Map<String, Object> f = api.createFinding(reportId, body);
        long findingId = Json.num(f, "id");
        check("finding created " + Json.str(f, "display_id"), findingId > 0 && Json.num(f, "evidence_count") == 2);
        check("finding URL returned", Json.str(f, "url").contains("/findings/" + findingId));

        // --- add to an existing finding, response left out
        api.addEvidence(findingId, m.evidence("Replay without response", false));
        Map<String, Object> full = api.finding(findingId);
        List<Object> ev = Json.list(full.get("evidence"));
        check("evidence appended (3)", ev.size() == 3);
        Map<String, Object> last = Json.obj(ev.get(2));
        check("response omitted on request", Json.str(last, "response").isEmpty() && Json.str(last, "source").equals("burp"));
        check("raw request stored intact", Json.str(Json.obj(ev.get(0)), "request").contains("<script>alert(1)</script>"));
        check("finding listed", api.findings(reportId).stream().anyMatch(x -> Json.num(x, "id") == findingId));

        // --- errors are reported, not swallowed
        Map<String, Object> bad = new LinkedHashMap<>(body);
        bad.put("title", "");
        bad.put("severity", "huge");
        try {
            api.createFinding(reportId, bad);
            check("validation error raised", false);
        } catch (ApiClient.ApiException e) {
            check("422 with field errors", e.status == 422 && e.describe().contains("title") && e.describe().contains("severity"));
        }
        settings.save(url, "wrong-token");
        try {
            api.ping();
            check("bad token rejected", false);
        } catch (ApiClient.ApiException e) {
            check("401 explained", e.status == 401 && e.getMessage().contains("token"));
        }
        settings.save("http://127.0.0.1:9", token);
        try {
            api.ping();
            check("unreachable server reported", false);
        } catch (ApiClient.ApiException e) {
            check("unreachable server reported", e.getMessage().startsWith("Cannot reach ptreport"));
        }
        settings.save("file:///etc/passwd", token);
        try {
            api.ping();
            check("non-http URL refused", false);
        } catch (ApiClient.ApiException e) {
            check("non-http URL refused", e.getMessage().contains("http"));
        }
        settings.save(url, token);
        check("HTML in labels neutralised", SendDialog.plain("<HTML><img src=x>").startsWith(" "));

        // --- render the dialog (needs a display; skipped when headless)
        if (args.length > 3 && !java.awt.GraphicsEnvironment.isHeadless()) {
            List<Message> msgs = new ArrayList<>(List.of(m));
            SwingUtilities.invokeAndWait(() -> {
                SendDialog d = new SendDialog(null, api, settings, msgs, s -> { });
                d.setVisible(false);
                java.util.Timer t = new java.util.Timer(true);
                t.schedule(new java.util.TimerTask() {
                    public void run() {
                        SwingUtilities.invokeLater(() -> {
                            try {
                                d.pack();
                                BufferedImage img = new BufferedImage(d.getWidth(), d.getHeight(), BufferedImage.TYPE_INT_RGB);
                                d.getContentPane().paint(img.getGraphics());
                                ImageIO.write(img, "png", new File(args[3]));
                                System.out.println("Dialog rendered to " + args[3]);
                            } catch (Exception e) {
                                System.out.println("Render failed: " + e);
                            }
                            d.dispose();
                        });
                    }
                }, 2500);
            });
            Thread.sleep(4000);
        }

        System.out.println(failures == 0 ? "ALL CHECKS PASSED" : failures + " CHECK(S) FAILED");
        System.exit(failures == 0 ? 0 : 1);
    }

    private static void check(String name, boolean ok) {
        System.out.println((ok ? "PASS " : "FAIL ") + name);
        if (!ok) {
            failures++;
        }
    }

    // ---------------------------------------------------------- Burp stand-ins

    @SuppressWarnings("unchecked")
    private static <T> T stub(Class<T> type, Map<String, Object> values) {
        return (T) Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[] {type}, (proxy, method, a) -> {
            String n = method.getName();
            if (values.containsKey(n)) {
                return values.get(n);
            }
            if (n.equals("toString")) {
                return type.getSimpleName();
            }
            throw new UnsupportedOperationException(type.getSimpleName() + "." + n);
        });
    }

    private static ByteArray bytes(String s) {
        byte[] b = s.getBytes(StandardCharsets.UTF_8);
        return stub(ByteArray.class, Map.of("getBytes", b, "length", b.length));
    }

    private static HttpRequestResponse requestResponse(String method, String path, String rawReq, String rawResp,
                                                       String host, int port, boolean secure) {
        HttpService svc = stub(HttpService.class, Map.of("host", host, "port", port, "secure", secure));
        HttpRequest req = stub(HttpRequest.class, Map.of("method", method, "pathWithoutQuery", path,
                "toByteArray", bytes(rawReq), "httpService", svc));
        Map<String, Object> rr = new HashMap<>();
        rr.put("request", req);
        rr.put("httpService", svc);
        rr.put("hasResponse", rawResp != null);
        rr.put("response", rawResp == null ? null : stub(HttpResponse.class, Map.of("toByteArray", bytes(rawResp))));
        return stub(HttpRequestResponse.class, rr);
    }

    private static Preferences preferences() {
        Map<String, Object> store = new HashMap<>();
        return (Preferences) Proxy.newProxyInstance(Preferences.class.getClassLoader(), new Class<?>[] {Preferences.class},
                (proxy, method, a) -> {
                    String n = method.getName();
                    if (n.startsWith("set")) {
                        store.put((String) a[0], a[1]);
                        return null;
                    }
                    if (n.startsWith("get")) {
                        return store.get((String) a[0]);
                    }
                    if (n.startsWith("delete")) {
                        store.remove((String) a[0]);
                        return null;
                    }
                    return null;
                });
    }
}
