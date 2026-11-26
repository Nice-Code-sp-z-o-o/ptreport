package ptreport.burp;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Talks to the ptreport JSON API (/api/v1) with the bearer token from the settings tab. */
final class ApiClient {
    /** Thrown for HTTP errors; {@code fieldErrors} holds ptreport's 422 validation messages. */
    static final class ApiException extends Exception {
        final int status;
        final Map<String, Object> fieldErrors;

        ApiException(int status, String message, Map<String, Object> fieldErrors) {
            super(message);
            this.status = status;
            this.fieldErrors = fieldErrors;
        }

        String describe() {
            if (fieldErrors == null || fieldErrors.isEmpty()) {
                return getMessage();
            }
            StringBuilder b = new StringBuilder();
            for (Map.Entry<String, Object> e : fieldErrors.entrySet()) {
                if (b.length() > 0) {
                    b.append('\n');
                }
                b.append(e.getKey()).append(": ").append(e.getValue());
            }
            return b.toString();
        }
    }

    private final HttpClient http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .followRedirects(HttpClient.Redirect.NEVER)
            .build();
    private final Settings settings;
    private List<String[]> cweCache;

    ApiClient(Settings settings) {
        this.settings = settings;
    }

    String ping() throws ApiException {
        return Json.str(Json.obj(call("GET", "/ping", null)), "version");
    }

    List<Map<String, Object>> reports() throws ApiException {
        return objects(Json.obj(call("GET", "/reports", null)).get("reports"));
    }

    List<Map<String, Object>> targets(long reportId) throws ApiException {
        return objects(Json.obj(call("GET", "/reports/" + reportId + "/targets", null)).get("targets"));
    }

    List<Map<String, Object>> findings(long reportId) throws ApiException {
        return objects(Json.obj(call("GET", "/reports/" + reportId + "/findings", null)).get("findings"));
    }

    /** All CWEs as {id, name}; loaded once per session (the catalogue ships with ptreport). */
    synchronized List<String[]> cwes() throws ApiException {
        if (cweCache == null) {
            List<String[]> out = new ArrayList<>();
            for (Map<String, Object> m : objects(Json.obj(call("GET", "/cwe", null)).get("cwe"))) {
                out.add(new String[] {Json.str(m, "id"), Json.str(m, "name")});
            }
            cweCache = out;
        }
        return cweCache;
    }

    long createTarget(long reportId, String name, String kind, String address) throws ApiException {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("name", name);
        body.put("kind", kind);
        body.put("address", address);
        return Json.num(Json.obj(Json.obj(call("POST", "/reports/" + reportId + "/targets", body)).get("target")), "id");
    }

    Map<String, Object> createFinding(long reportId, Map<String, Object> body) throws ApiException {
        return Json.obj(Json.obj(call("POST", "/reports/" + reportId + "/findings", body)).get("finding"));
    }

    Map<String, Object> finding(long findingId) throws ApiException {
        return Json.obj(Json.obj(call("GET", "/findings/" + findingId, null)).get("finding"));
    }

    void addEvidence(long findingId, Map<String, Object> evidence) throws ApiException {
        call("POST", "/findings/" + findingId + "/evidence", evidence);
    }

    private Object call(String method, String path, Object body) throws ApiException {
        String base = settings.baseUrl();
        URI uri;
        try {
            uri = URI.create(base + "/api/v1" + path);
        } catch (IllegalArgumentException e) {
            throw new ApiException(0, "Invalid ptreport URL: " + base, null);
        }
        if (!"http".equals(uri.getScheme()) && !"https".equals(uri.getScheme())) {
            throw new ApiException(0, "The ptreport URL must start with http:// or https://", null);
        }
        HttpRequest.Builder req = HttpRequest.newBuilder(uri)
                .timeout(Duration.ofSeconds(60))
                .header("Authorization", "Bearer " + settings.token())
                .header("Accept", "application/json");
        if (body == null) {
            req.GET();
        } else {
            req.header("Content-Type", "application/json")
                    .method(method, HttpRequest.BodyPublishers.ofString(Json.write(body), StandardCharsets.UTF_8));
        }
        HttpResponse<String> resp;
        try {
            resp = http.send(req.build(), HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        } catch (IOException e) {
            throw new ApiException(0, "Cannot reach ptreport at " + base + " (is it running?): " + e.getMessage(), null);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new ApiException(0, "Interrupted", null);
        }
        Object parsed;
        try {
            parsed = resp.body().isEmpty() ? new LinkedHashMap<>() : Json.parse(resp.body());
        } catch (IllegalArgumentException e) {
            throw new ApiException(resp.statusCode(), "Unexpected answer from " + base + " (not ptreport?)", null);
        }
        int status = resp.statusCode();
        if (status >= 200 && status < 300) {
            return parsed;
        }
        Map<String, Object> err = Json.obj(parsed);
        if (status == 401) {
            throw new ApiException(status, "The API token was rejected. Copy it from ptreport: Settings -> API.", null);
        }
        if (status == 422) {
            throw new ApiException(status, "ptreport rejected the data", Json.obj(err.get("errors")));
        }
        String message = Json.str(err, "message");
        throw new ApiException(status, "ptreport answered " + status + (message.isEmpty() ? "" : ": " + message), null);
    }

    private static List<Map<String, Object>> objects(Object v) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (Object o : Json.list(v)) {
            out.add(Json.obj(o));
        }
        return out;
    }
}
