package ptreport.burp;

import burp.api.montoya.persistence.Preferences;

/** Extension settings, kept in Burp's user preferences (not in the project file). */
final class Settings {
    static final String DEFAULT_URL = "http://127.0.0.1:5055";
    private static final String KEY_URL = "ptreport.url";
    private static final String KEY_TOKEN = "ptreport.token";
    private static final String KEY_LAST_REPORT = "ptreport.lastReport";
    private static final String KEY_INCLUDE_RESPONSE = "ptreport.includeResponse";

    private final Preferences prefs;

    Settings(Preferences prefs) {
        this.prefs = prefs;
    }

    String baseUrl() {
        String v = prefs.getString(KEY_URL);
        v = v == null || v.isBlank() ? DEFAULT_URL : v.trim();
        while (v.endsWith("/")) {
            v = v.substring(0, v.length() - 1);
        }
        return v;
    }

    String token() {
        String v = prefs.getString(KEY_TOKEN);
        return v == null ? "" : v.trim();
    }

    void save(String url, String token) {
        prefs.setString(KEY_URL, url == null ? "" : url.trim());
        prefs.setString(KEY_TOKEN, token == null ? "" : token.trim());
    }

    boolean configured() {
        return !token().isEmpty();
    }

    long lastReport() {
        Long v = prefs.getLong(KEY_LAST_REPORT);
        return v == null ? -1 : v;
    }

    void lastReport(long id) {
        prefs.setLong(KEY_LAST_REPORT, id);
    }

    boolean includeResponse() {
        Boolean v = prefs.getBoolean(KEY_INCLUDE_RESPONSE);
        return v == null || v;
    }

    void includeResponse(boolean v) {
        prefs.setBoolean(KEY_INCLUDE_RESPONSE, v);
    }
}
