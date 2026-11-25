"use strict";
// Interactive CVSS calculator. Builds the vector from clicked metrics and asks
// the server (/cvss/score) for the authoritative score - scoring logic lives
// only on the server.
(function () {
  var root = document.querySelector("[data-cvss]");
  var defsEl = document.getElementById("cvss-defs");
  if (!root || !defsEl) return;

  var DEFS = JSON.parse(defsEl.textContent);
  var metricsEl = root.querySelector("[data-cvss-metrics]");
  var resultEl = root.querySelector("[data-cvss-result]");
  var vectorInput = document.getElementById("f-cvss_vector");
  var vectorField = root.querySelector("[data-cvss-vector-field]");
  var versionRadios = root.querySelectorAll("input[name=cvss_version]");
  var severitySelect = document.getElementById("f-severity");
  var severityHint = document.querySelector("[data-severity-hint]");

  var RATING_NAMES = { none: "None", low: "Low", medium: "Medium", high: "High", critical: "Critical" };
  var SEVERITY_NAMES = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Informational" };
  var state = { version: "", selected: {}, extra: [] };
  var requestSeq = 0;
  var debounceTimer = null;

  function currentVersion() {
    for (var i = 0; i < versionRadios.length; i++) if (versionRadios[i].checked) return versionRadios[i].value;
    return "";
  }

  function detectVersion(vector) {
    var m = /^CVSS:(4\.0|3\.1|3\.0)\//.exec(vector.trim());
    if (m) return m[1];
    return /(^|\/|\()AV:[LAN]\/AC:[HML]\/Au:/.test(vector) ? "2.0" : null;
  }

  function allMetrics(version) {
    var out = [];
    (DEFS[version] ? DEFS[version].groups : []).forEach(function (g) {
      g.metrics.forEach(function (m) { out.push({ metric: m, group: g }); });
    });
    return out;
  }

  function findMetric(version, key) {
    var list = allMetrics(version);
    for (var i = 0; i < list.length; i++) if (list[i].metric.key === key) return list[i];
    return null;
  }

  function parseVector(version, vector) {
    var selected = {};
    var extra = [];
    var parts = vector.trim().replace(/^CVSS2#/, "").replace(/^\(|\)$/g, "").split("/");
    parts.forEach(function (part, idx) {
      if (!part) return;
      if (idx === 0 && /^CVSS:/.test(part)) return;
      var kv = part.split(":");
      if (kv.length !== 2) { extra.push(part); return; }
      var found = findMetric(version, kv[0]);
      if (found && found.metric.values.some(function (v) { return v.key === kv[1]; })) {
        selected[kv[0]] = kv[1];
      } else {
        extra.push(part);
      }
    });
    return { selected: selected, extra: extra };
  }

  function buildVector() {
    var def = DEFS[state.version];
    if (!def) return "";
    var parts = def.prefix ? [def.prefix] : [];
    def.groups.forEach(function (g) {
      g.metrics.forEach(function (m) {
        var v = state.selected[m.key];
        if (v && v !== g.not_defined) parts.push(m.key + ":" + v);
      });
    });
    return parts.concat(state.extra).join("/");
  }

  function missingRequired() {
    var missing = [];
    allMetrics(state.version).forEach(function (x) {
      if (x.group.required && !state.selected[x.metric.key]) missing.push(x.metric.key);
    });
    return missing;
  }

  var SVG_NS = "http://www.w3.org/2000/svg";
  var last = { data: null, message: "", error: false };

  function el(tag, attrs, text) {
    var e = document.createElement(tag);
    Object.keys(attrs || {}).forEach(function (k) { e.setAttribute(k, attrs[k]); });
    if (text !== undefined) e.textContent = text;
    return e;
  }

  function icon(name) {
    var svg = document.createElementNS(SVG_NS, "svg");
    svg.setAttribute("class", "icon");
    svg.setAttribute("aria-hidden", "true");
    var use = document.createElementNS(SVG_NS, "use");
    use.setAttribute("href", "#i-" + name);
    svg.appendChild(use);
    return svg;
  }

  // Vector strip built from the same classes and tone data as the server markup.
  function buildStrip(large) {
    var def = DEFS[state.version];
    if (!def) return null;
    var groups = [];
    var byName = {};
    def.groups.forEach(function (g) {
      g.metrics.forEach(function (m) {
        var v = state.selected[m.key];
        if (!v || v === g.not_defined) return;
        var value = null;
        m.values.forEach(function (x) { if (x.key === v) value = x; });
        if (!value) return;
        var name = m.strip_group || g.name;
        if (!byName[name]) { byName[name] = { name: name, cells: [] }; groups.push(byName[name]); }
        byName[name].cells.push({ metric: m, value: value });
      });
    });
    if (!groups.length) return null;
    var list = el("ul", { "class": "vec" + (large ? " vec-lg" : ""), "aria-label": vectorInput.value });
    groups.forEach(function (g) {
      var li = el("li", { "class": "vec-group" });
      li.appendChild(el("span", { "class": "vec-group-name" }, g.name));
      var cells = el("ul", { "class": "vec-cells" });
      g.cells.forEach(function (c) {
        var cell = el("li", { "class": "vec-cell", "data-level": String(c.value.tone || 0), title: c.metric.name + ": " + c.value.name });
        cell.appendChild(el("span", { "class": "vec-k" }, c.metric.key));
        cell.appendChild(el("span", { "class": "vec-v" }, large ? c.value.name : c.value.key));
        cells.appendChild(cell);
      });
      li.appendChild(cells);
      list.appendChild(li);
    });
    return list;
  }

  function renderSummary() {
    resultEl.textContent = "";
    if (!state.version) return;
    var data = last.data;
    if (data) {
      var head = el("div", { "class": "vec-summary-head" });
      head.appendChild(el("span", { "class": "vec-version" }, "CVSS " + data.version));
      var rating = RATING_NAMES[data.rating] ? data.rating : "none";
      var chip = el("span", { "class": "cvss-chip cvss-chip-lg cv-" + rating, title: "CVSS " + data.version + " score and rating" });
      chip.appendChild(el("span", { "class": "cvss-chip-score" }, Number(data.score).toFixed(1)));
      chip.appendChild(el("span", { "class": "cvss-chip-rating" }, RATING_NAMES[rating]));
      head.appendChild(chip);
      if (data.base_score !== data.score) head.appendChild(el("span", { "class": "vec-version" }, "base " + Number(data.base_score).toFixed(1)));
      resultEl.appendChild(head);
    }
    var strip = buildStrip(true);
    if (strip) resultEl.appendChild(strip);
    if (last.message) {
      var p = el("p", { "class": last.error ? "field-error" : "hint" });
      if (last.error) p.appendChild(icon("alert"));
      p.appendChild(el("span", {}, last.message));
      resultEl.appendChild(p);
    }
  }

  function setMessage(message, isError, keepData) {
    last.message = message || "";
    last.error = !!isError;
    if (!keepData) last.data = null;
    renderSummary();
  }

  function render() {
    metricsEl.textContent = "";
    var def = DEFS[state.version];
    vectorField.hidden = !def;
    if (!def) { renderSummary(); return; }
    var touched = Object.keys(state.selected).length > 0;
    def.groups.forEach(function (g) {
      var group = el("section", { "class": "cvss-group", "aria-label": g.name });
      var title = el("h3", {}, g.name + " ");
      if (!g.required) title.appendChild(el("span", { "class": "opt" }, "(optional)"));
      group.appendChild(title);
      var grid = el("div", { "class": "cvss-grid" });
      g.metrics.forEach(function (m) {
        var current = state.selected[m.key] || (g.required ? null : g.not_defined);
        var missing = g.required && !current && touched;
        var box = el("div", { "class": "cvss-metric" + (missing ? " is-missing" : "") });
        var nameId = "m-" + state.version + "-" + m.key;
        var name = el("div", { "class": "cvss-metric-name", id: nameId });
        if (missing) name.appendChild(icon("alert"));
        name.appendChild(document.createTextNode(m.name + " "));
        name.appendChild(el("span", { "class": "abbr" }, m.key));
        box.appendChild(name);
        var seg = el("div", { "class": "segmented segmented-sm", role: "group", "aria-labelledby": nameId });
        m.values.forEach(function (v) {
          var b = el("button", { type: "button", "class": "seg-btn", "aria-pressed": String(current === v.key), title: m.key + ":" + v.key }, v.name);
          b.addEventListener("click", function () {
            state.selected[m.key] = v.key;
            vectorInput.value = buildVector();
            render();
            scheduleScore(0);
          });
          seg.appendChild(b);
        });
        box.appendChild(seg);
        if (missing) {
          var err = el("p", { "class": "field-error" });
          err.appendChild(icon("alert"));
          err.appendChild(el("span", {}, "Choose a value to calculate the score."));
          box.appendChild(err);
        }
        grid.appendChild(box);
      });
      group.appendChild(grid);
      metricsEl.appendChild(group);
    });
    renderSummary();
  }

  // Severity is the tester's own assessment. The CVSS rating is shown separately and only
  // pre-fills an empty severity as a suggestion.
  function suggestSeverity(data) {
    if (!severitySelect || severitySelect.value || !SEVERITY_NAMES[data.severity]) return;
    severitySelect.value = String(data.severity);
    if (severityHint) severityHint.textContent = "Suggested from the CVSS rating. Change it if your assessment differs.";
  }

  function scheduleScore(delay) {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(updateScore, delay);
  }

  function updateScore() {
    if (!state.version) { setMessage("", false); return; }
    var vector = vectorInput.value.trim();
    var missing = missingRequired();
    if (!vector || (missing.length && state.extra.length === 0)) {
      setMessage(missing.length && Object.keys(state.selected).length ? "Select: " + missing.join(", ") : "", false);
      return;
    }
    var seq = ++requestSeq;
    fetch("/cvss/score?vector=" + encodeURIComponent(vector), { headers: { "Accept": "application/json" }, credentials: "same-origin" })
      .then(function (r) { return r.ok ? r.json() : Promise.reject(new Error("HTTP " + r.status)); })
      .then(function (data) {
        if (seq !== requestSeq) return;
        if (!data || typeof data !== "object") throw new Error("Bad response");
        if (!data.valid) { setMessage(String(data.error || "Invalid vector"), true); return; }
        if (data.version !== state.version) {
          setMessage("Vector is CVSS " + data.version + " but CVSS " + state.version + " is selected.", true);
          return;
        }
        last.data = data;
        setMessage("", false, true);
        suggestSeverity(data);
      })
      .catch(function () {
        if (seq === requestSeq) setMessage("Could not calculate score.", true);
      });
  }

  function setVersion(version, keepSelection) {
    var prev = state.version;
    state.version = version;
    var compatible = (prev === "3.0" && version === "3.1") || (prev === "3.1" && version === "3.0");
    if (!keepSelection && !compatible) { state.selected = {}; state.extra = []; }
    if (version) {
      vectorInput.value = buildVector();
    }
    render();
    scheduleScore(0);
  }

  versionRadios.forEach(function (r) {
    r.addEventListener("change", function () { if (r.checked) setVersion(r.value, false); });
  });

  vectorInput.addEventListener("input", function () {
    var vector = vectorInput.value;
    var detected = detectVersion(vector);
    if (detected && detected !== state.version) {
      versionRadios.forEach(function (r) { r.checked = r.value === detected; });
      state.version = detected;
    }
    if (state.version) {
      var parsed = parseVector(state.version, vector);
      state.selected = parsed.selected;
      state.extra = parsed.extra;
    }
    render();
    scheduleScore(300);
  });

  // Initial state from the server-rendered form.
  state.version = currentVersion();
  if (state.version && vectorInput.value.trim()) {
    var initial = parseVector(state.version, vectorInput.value);
    state.selected = initial.selected;
    state.extra = initial.extra;
  }
  render();
  scheduleScore(0);
})();
