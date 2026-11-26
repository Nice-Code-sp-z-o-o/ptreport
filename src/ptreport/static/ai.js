"use strict";
// Local writing assistant (Ollama, through ptreport's backend).
// Model output is plain text: it is only ever put into a textarea value or textContent, never into HTML.
(function () {
  var csrfInput = document.querySelector("input[name=_csrf]");
  var csrf = csrfInput ? csrfInput.value : "";

  function postJson(url, body, signal) {
    return fetch(url, {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf },
      body: JSON.stringify(body),
      signal: signal
    }).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (data) {
        if (!r.ok) throw new Error(typeof data.error === "string" && data.error ? data.error
          : "The assistant request failed (HTTP " + r.status + ").");
        return data;
      });
    }, function (err) {
      if (err && err.name === "AbortError") throw err;
      throw new Error("Could not reach ptreport. Is it still running?");
    });
  }

  function setIcon(container, name) {
    var use = container.querySelector("svg.icon use");
    if (use) use.setAttribute("href", "#i-" + name);
  }

  // ------------------------------------------------------------ settings --
  var settings = document.querySelector("[data-ai-settings]");
  if (settings && window.fetch) {
    var urlInput = settings.querySelector("[name=url]");
    var modelInput = settings.querySelector("[name=model]");
    var datalist = document.getElementById("ai-model-list");
    var loadBtn = settings.querySelector("[data-ai-load]");
    var testBtn = settings.querySelector("[data-ai-test]");
    var result = settings.querySelector("[data-ai-result]");
    var modelsHint = settings.querySelector("[data-ai-models-hint]");
    loadBtn.hidden = false;
    testBtn.hidden = false;

    var showResult = function (ok, text) {
      result.textContent = "";
      var svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
      svg.setAttribute("class", "icon");
      svg.setAttribute("aria-hidden", "true");
      var use = document.createElementNS("http://www.w3.org/2000/svg", "use");
      use.setAttribute("href", ok ? "#i-check-circle" : "#i-alert");
      svg.appendChild(use);
      var span = document.createElement("span");
      span.textContent = text;
      result.appendChild(svg);
      result.appendChild(span);
      result.classList.toggle("is-error", !ok);
      result.hidden = false;
    };
    var busy = function (btn, on) {
      btn.setAttribute("aria-busy", on ? "true" : "false");
      btn.disabled = on;
    };

    loadBtn.addEventListener("click", function () {
      busy(loadBtn, true);
      postJson(settings.getAttribute("data-models-url"), { url: urlInput.value, model: "" })
        .then(function (data) {
          var models = Array.isArray(data.models) ? data.models.filter(function (m) { return typeof m === "string"; }) : [];
          datalist.textContent = "";
          models.forEach(function (m) {
            var opt = document.createElement("option");
            opt.value = m;
            datalist.appendChild(opt);
          });
          if (!models.length) {
            showResult(false, "Ollama is running but has no models. Install one, e.g. ollama pull qwen2.5:3b.");
            return;
          }
          if (!modelInput.value) modelInput.value = models[0];
          modelsHint.textContent = "Installed: " + models.join(", ");
          showResult(true, models.length + " model(s) found. Pick one in the Model field and save.");
          modelInput.focus();
        })
        .catch(function (err) { showResult(false, err.message); })
        .then(function () { busy(loadBtn, false); });
    });

    testBtn.addEventListener("click", function () {
      busy(testBtn, true);
      postJson(settings.getAttribute("data-test-url"), { url: urlInput.value, model: modelInput.value })
        .then(function (data) { showResult(true, String(data.message || "OK")); })
        .catch(function (err) { showResult(false, err.message); })
        .then(function () { busy(testBtn, false); });
    });
  }

  // ------------------------------------------------------- finding form --
  var dialog = document.getElementById("ai-dialog");
  if (!dialog || typeof dialog.showModal !== "function" || !window.fetch) return;

  var form = document.getElementById("finding-form");
  var status = dialog.querySelector("[data-ai-status]");
  var message = dialog.querySelector("[data-ai-message]");
  var title = dialog.querySelector("[data-ai-title]");
  var suggestion = dialog.querySelector("[data-ai-suggestion]");
  var text = dialog.querySelector("[data-ai-text]");
  var buttons = {
    copy: dialog.querySelector("[data-ai-copy]"),
    insert: dialog.querySelector("[data-ai-insert]"),
    replace: dialog.querySelector("[data-ai-replace]")
  };
  var MAX_FIELD = 20000;
  var FIELD_LABELS = { description: "Description", impact: "Impact", technical_details: "Technical details",
                       remediation: "Remediation" };
  var ACTION_LABELS = { draft: "Draft", improve: "Improved wording", shorten: "Shorter version",
                        translate_en: "English translation", translate_pl: "Polish translation" };
  var current = { field: null, controller: null };

  document.querySelectorAll("[data-ai-menu]").forEach(function (menu) { menu.hidden = false; });

  function value(name) {
    var el = form.querySelector("[name=" + name + "]");
    return el ? el.value : "";
  }

  function setButtons(visible) {
    Object.keys(buttons).forEach(function (k) { buttons[k].hidden = !visible; });
  }

  function reset() {
    if (current.controller) current.controller.abort();
    current.controller = null;
    suggestion.hidden = true;
    text.value = "";
    status.hidden = false;
    status.classList.remove("is-error");
    setIcon(status, "spinner");
    setButtons(false);
  }

  function fail(msg) {
    status.classList.add("is-error");
    setIcon(status, "alert");
    message.textContent = msg;
  }

  function run(field, action) {
    reset();
    current.field = field;
    title.textContent = (ACTION_LABELS[action] || "Suggestion") + " · " + (FIELD_LABELS[field] || field);
    message.textContent = "Asking the local model… The first request can take a while when the model is loading.";
    dialog.showModal();
    if (action === "draft" && !value("title").trim()) {
      fail("Write the vulnerability title first: the draft is based on it.");
      return;
    }
    if (action !== "draft" && !value(field).trim()) {
      fail((FIELD_LABELS[field] || field) + " is empty; there is nothing to work on.");
      return;
    }
    if (action !== "draft" && value(field).length > MAX_FIELD) {
      fail((FIELD_LABELS[field] || field) + " is too long for the assistant (at most " + MAX_FIELD + " characters).");
      return;
    }
    var controller = new AbortController();
    current.controller = controller;
    var body = {
      report_id: parseInt(dialog.getAttribute("data-report-id"), 10),
      field: field,
      action: action,
      title: value("title"),
      cwe: value("cwe"),
      severity: value("severity")
    };
    ["description", "impact", "technical_details", "remediation"].forEach(function (n) {
      body[n] = value(n).slice(0, MAX_FIELD);
    });
    postJson(dialog.getAttribute("data-ai-url"), body, controller.signal)
      .then(function (data) {
        if (typeof data.text !== "string") throw new Error("The assistant returned an unexpected answer.");
        text.value = data.text;          // plain text, never HTML
        status.hidden = true;
        suggestion.hidden = false;
        setButtons(true);
        text.focus();
        text.setSelectionRange(0, 0);
        text.scrollTop = 0;
      })
      .catch(function (err) {
        if (err && err.name === "AbortError") return;
        fail(err.message);
      })
      .then(function () { if (current.controller === controller) current.controller = null; });
  }

  function target() { return form.querySelector("[name=" + current.field + "]"); }

  function changed(el) {
    el.dispatchEvent(new Event("input", { bubbles: true }));
    dialog.close();
    el.focus();
  }

  buttons.replace.addEventListener("click", function () {
    var el = target();
    if (!el) return;
    el.value = text.value;
    changed(el);
  });
  buttons.insert.addEventListener("click", function () {
    var el = target();
    if (!el) return;
    var focused = el.getAttribute("data-ai-caret");
    var at = focused !== null ? Math.min(parseInt(focused, 10) || 0, el.value.length) : el.value.length;
    var before = el.value.slice(0, at);
    var after = el.value.slice(at);
    var sepBefore = before && !/\n\n$/.test(before) ? (/\n$/.test(before) ? "\n" : "\n\n") : "";
    var sepAfter = after && !/^\n/.test(after) ? "\n\n" : "";
    el.value = before + sepBefore + text.value + sepAfter + after;
    var caret = (before + sepBefore + text.value).length;
    changed(el);
    el.setSelectionRange(caret, caret);
  });
  buttons.copy.addEventListener("click", function () {
    var label = buttons.copy.querySelector("span");
    var done = function () {
      label.textContent = "Copied";
      setTimeout(function () { label.textContent = "Copy"; }, 1500);
    };
    if (navigator.clipboard) navigator.clipboard.writeText(text.value).then(done, function () {});
  });

  // Remember where the caret was in each assisted field, for "Insert".
  ["description", "impact", "technical_details", "remediation"].forEach(function (n) {
    var el = form.querySelector("[name=" + n + "]");
    if (!el) return;
    var remember = function () { el.setAttribute("data-ai-caret", String(el.selectionStart)); };
    el.addEventListener("keyup", remember);
    el.addEventListener("click", remember);
    el.addEventListener("blur", remember);
  });

  document.querySelectorAll("[data-ai-action]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var menu = btn.closest("details");
      if (menu) menu.removeAttribute("open");
      run(btn.getAttribute("data-ai-field"), btn.getAttribute("data-ai-action"));
    });
  });
  dialog.querySelector("[data-ai-close]").addEventListener("click", function () { dialog.close(); });
  dialog.querySelector("[data-ai-discard]").addEventListener("click", function () { dialog.close(); });
  dialog.addEventListener("close", reset);
})();
