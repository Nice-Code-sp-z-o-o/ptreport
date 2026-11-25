"use strict";
// Finding editor: add a target in a dialog and link it to the finding without leaving the page,
// so unsaved text in the finding form is kept. Without JS the "separate page" link is used.
(function () {
  var dialog = document.getElementById("target-dialog");
  var openBtn = document.querySelector("[data-open-target-dialog]");
  var list = document.querySelector("[data-target-list]");
  if (!dialog || !openBtn || !list || typeof dialog.showModal !== "function") return;

  var form = dialog.querySelector("form[data-quick-target]");
  var errorBox = dialog.querySelector("[data-quick-target-error]");
  var emptyNote = document.querySelector("[data-target-empty]");
  var fallback = document.querySelector("[data-target-fallback]");
  var csrf = document.querySelector("input[name=_csrf]");

  openBtn.hidden = false;
  if (fallback) fallback.hidden = true;

  function el(tag, attrs, text) {
    var e = document.createElement(tag);
    Object.keys(attrs || {}).forEach(function (k) { e.setAttribute(k, attrs[k]); });
    if (text !== undefined) e.textContent = text;
    return e;
  }

  function clearErrors() {
    errorBox.hidden = true;
    errorBox.textContent = "";
    form.querySelectorAll("[aria-invalid]").forEach(function (i) { i.removeAttribute("aria-invalid"); });
  }

  function addTarget(t) {
    var label = el("label", { "class": "check" });
    var box = el("input", { type: "checkbox", name: "target_ids", value: String(t.id) });
    box.checked = true;
    var text = el("span", { "class": "check-text" });
    text.appendChild(el("strong", {}, t.name));
    if (t.address) text.appendChild(el("span", { "class": "mono" }, t.address));
    label.appendChild(box);
    label.appendChild(text);
    list.appendChild(label);
    if (emptyNote) emptyNote.hidden = true;
    box.focus();
  }

  openBtn.addEventListener("click", function () {
    clearErrors();
    form.reset();
    dialog.showModal();
    var name = form.querySelector("[name=name]");
    if (name) name.focus();
  });
  dialog.querySelector("[data-close-target-dialog]").addEventListener("click", function () { dialog.close(); });
  dialog.addEventListener("click", function (ev) { if (ev.target === dialog) dialog.close(); });

  form.addEventListener("submit", function (ev) {
    ev.preventDefault();
    clearErrors();
    var name = form.querySelector("[name=name]");
    if (!name.value.trim()) {
      name.setAttribute("aria-invalid", "true");
      errorBox.textContent = "Target name is required.";
      errorBox.hidden = false;
      name.focus();
      return;
    }
    var submit = form.querySelector("[type=submit]");
    submit.disabled = true;
    fetch(form.getAttribute("data-quick-target"), {
      method: "POST",
      body: new FormData(form),
      credentials: "same-origin",
      headers: { "Accept": "application/json", "X-CSRF-Token": csrf ? csrf.value : "" }
    })
      .then(function (r) {
        return r.json().catch(function () { return {}; }).then(function (body) { return { status: r.status, body: body }; });
      })
      .then(function (res) {
        if (res.status === 201 && res.body && res.body.target && typeof res.body.target.id === "number") {
          addTarget(res.body.target);
          dialog.close();
          return;
        }
        var errors = (res.body && res.body.errors) || {};
        var messages = [];
        Object.keys(errors).forEach(function (field) {
          var input = form.querySelector("[name=" + field + "]");
          if (input) input.setAttribute("aria-invalid", "true");
          messages.push(String(errors[field]));
        });
        errorBox.textContent = messages.length ? messages.join(" ") : "Could not add the target. Reload the page and try again.";
        errorBox.hidden = false;
      })
      .catch(function () {
        errorBox.textContent = "Could not reach ptreport. Is it still running?";
        errorBox.hidden = false;
      })
      .then(function () { submit.disabled = false; });
  });
})();
