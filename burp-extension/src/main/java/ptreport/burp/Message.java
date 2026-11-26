package ptreport.burp;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

/** One request/response taken from Burp, ready to be sent to ptreport as HTTP evidence. */
record Message(String method, String path, String origin, String host, String request, String response) {
    /** ptreport accepts up to 5,000,000 characters per message; stay clearly below it. */
    static final int MAX_CHARS = 4_500_000;
    static final String TRUNCATED = "\n[... truncated by ptreport-burp ...]";

    static Message of(HttpRequestResponse rr) {
        HttpRequest req = rr.request();
        HttpService svc = rr.httpService() != null ? rr.httpService() : req.httpService();
        String origin = "";
        String host = "";
        if (svc != null) {
            host = svc.host();
            boolean defaultPort = (svc.secure() && svc.port() == 443) || (!svc.secure() && svc.port() == 80);
            origin = (svc.secure() ? "https://" : "http://") + svc.host() + (defaultPort ? "" : ":" + svc.port());
        }
        String response = rr.hasResponse() && rr.response() != null ? text(rr.response().toByteArray().getBytes()) : "";
        return new Message(req.method(), req.pathWithoutQuery(), origin, host, text(req.toByteArray().getBytes()), response);
    }

    static String text(byte[] raw) {
        String s = new String(raw, StandardCharsets.UTF_8).replace("\u0000", "");
        return s.length() > MAX_CHARS ? s.substring(0, MAX_CHARS) + TRUNCATED : s;
    }

    String defaultTitle() {
        String p = path == null || path.isEmpty() ? "/" : path;
        if (p.length() > 200) {
            p = p.substring(0, 200) + "...";
        }
        return method + " " + p;
    }

    Map<String, Object> evidence(String title, boolean withResponse) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("title", title);
        m.put("request", request);
        m.put("response", withResponse ? response : "");
        m.put("source", "burp");
        return m;
    }
}
