"use strict";
// Small progressive enhancements. Everything works without JS; the server
// re-validates every submission.
(function () {
  var dialog = document.getElementById("confirm-dialog");
  var canDialog = !!(dialog && typeof dialog.showModal === "function");
  var pending = null;     // form waiting for the dialog answer
  var confirmed = null;   // form the user already confirmed

  function openConfirm(form, submitter) {
    pending = { form: form, submitter: submitter || null };
    var button = submitter || form.querySelector("button[type=submit]");
    var label = button ? (button.textContent || "").trim() : "";
    var ok = dialog.querySelector("[data-confirm-ok]");
    ok.textContent = label || "Confirm";
    // Destructive actions get the solid danger button, others the primary one.
    var destructive = !!(button && button.classList.contains("btn-danger"));
    ok.classList.toggle("btn-danger-solid", destructive);
    ok.classList.toggle("btn-primary", !destructive);
    dialog.querySelector("[data-confirm-text]").textContent = form.getAttribute("data-confirm");
    dialog.showModal();
  }

  if (canDialog) {
    dialog.addEventListener("close", function () {
      var p = pending;
      pending = null;
      if (!p || dialog.returnValue !== "confirm") return;
      confirmed = p.form;
      if (p.form.requestSubmit) p.form.requestSubmit(p.submitter || undefined);
      else p.form.submit();
    });
    dialog.addEventListener("click", function (ev) { if (ev.target === dialog) dialog.close("cancel"); });
  }

  document.addEventListener("submit", function (ev) {
    var form = ev.target;
    var msg = form.getAttribute("data-confirm");
    if (msg && confirmed !== form) {
      ev.preventDefault();
      if (canDialog) openConfirm(form, ev.submitter);
      else if (window.confirm(msg)) { confirmed = form; form.submit(); }
      return;
    }
    confirmed = null;
    if (form.hasAttribute("data-validate")) {
      var start = form.querySelector("[name=start_date]");
      var end = form.querySelector("[name=end_date]");
      if (start && end) {
        end.setCustomValidity(start.value && end.value && end.value < start.value
          ? "End date cannot be before the start date." : "");
      }
      if (!form.checkValidity()) {
        ev.preventDefault();
        form.reportValidity();
      }
    }
  }, true);

  // Finding ID prefix: force upper case.
  var prefix = document.querySelector("[name=finding_prefix]");
  if (prefix) {
    prefix.addEventListener("input", function () { prefix.value = prefix.value.toUpperCase(); });
  }

  // Show / copy secret inputs.
  document.querySelectorAll("[data-toggle-secret]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var input = document.getElementById(btn.getAttribute("data-toggle-secret"));
      var hidden = input.type === "password";
      input.type = hidden ? "text" : "password";
      btn.textContent = hidden ? "Hide" : "Show";
    });
  });
  document.querySelectorAll("[data-copy]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var input = document.getElementById(btn.getAttribute("data-copy"));
      if (navigator.clipboard) {
        navigator.clipboard.writeText(input.value).then(function () {
          btn.textContent = "Copied";
          setTimeout(function () { btn.textContent = "Copy"; }, 1500);
        });
      }
    });
  });

  // Toasts: dismiss button; success toasts leave on their own, errors stay.
  document.querySelectorAll("[data-toast]").forEach(function (toast) {
    var close = toast.querySelector("[data-dismiss]");
    if (close) close.addEventListener("click", function () { toast.remove(); });
    if (toast.classList.contains("flash-success")) setTimeout(function () { toast.remove(); }, 6000);
  });

  // Export dropdown: close on outside click or Escape.
  document.addEventListener("click", function (ev) {
    document.querySelectorAll("details.dropdown[open]").forEach(function (d) {
      if (!d.contains(ev.target)) d.removeAttribute("open");
    });
  });
  document.addEventListener("keydown", function (ev) {
    if (ev.key !== "Escape") return;
    document.querySelectorAll("details.dropdown[open]").forEach(function (d) { d.removeAttribute("open"); });
  });
})();

// Settings: keep the colour picker and the hex field in sync.
(function () {
  document.querySelectorAll("[data-color-sync]").forEach(function (picker) {
    var field = document.getElementById(picker.getAttribute("data-color-sync"));
    if (!field) return;
    picker.addEventListener("input", function () { field.value = picker.value.toUpperCase(); });
    field.addEventListener("input", function () {
      var v = field.value.trim();
      if (/^#?[0-9A-Fa-f]{6}$/.test(v)) picker.value = (v[0] === "#" ? v : "#" + v).toLowerCase();
    });
  });
})();
