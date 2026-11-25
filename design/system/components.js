"use strict";
(function () {
  document.querySelectorAll("[data-dialog-open]").forEach(function (b) {
    b.addEventListener("click", function () {
      var d = document.getElementById(b.getAttribute("data-dialog-open"));
      if (d && d.showModal) d.showModal();
    });
  });
  document.querySelectorAll("dialog.modal").forEach(function (d) {
    d.addEventListener("click", function (ev) { if (ev.target === d) d.close(); });
  });

  document.querySelectorAll(".segmented").forEach(function (g) {
    g.addEventListener("click", function (ev) {
      var b = ev.target.closest(".seg-btn");
      if (!b || b.disabled) return;
      g.querySelectorAll(".seg-btn").forEach(function (o) { o.setAttribute("aria-pressed", o === b ? "true" : "false"); });
    });
  });

  document.querySelectorAll("[role=tablist]").forEach(function (list) {
    var tabs = Array.prototype.filter.call(list.querySelectorAll("[role=tab]"), function (t) { return !t.disabled; });
    function select(t) {
      tabs.forEach(function (o) {
        var on = o === t;
        o.setAttribute("aria-selected", on ? "true" : "false");
        o.tabIndex = on ? 0 : -1;
        var p = document.getElementById(o.getAttribute("aria-controls"));
        if (p) p.hidden = !on;
      });
      t.focus();
    }
    list.addEventListener("click", function (ev) { var t = ev.target.closest("[role=tab]"); if (t && !t.disabled) select(t); });
    list.addEventListener("keydown", function (ev) {
      var i = tabs.indexOf(document.activeElement);
      if (i < 0) return;
      if (ev.key === "ArrowRight") select(tabs[(i + 1) % tabs.length]);
      else if (ev.key === "ArrowLeft") select(tabs[(i - 1 + tabs.length) % tabs.length]);
      else return;
      ev.preventDefault();
    });
  });

  document.addEventListener("keydown", function (ev) {
    if (ev.key !== "Escape") return;
    document.querySelectorAll("details.dropdown[open]").forEach(function (d) { d.open = false; });
  });
  document.addEventListener("click", function (ev) {
    document.querySelectorAll("details.dropdown[open]").forEach(function (d) { if (!d.contains(ev.target)) d.open = false; });
  });

  var stack = document.createElement("div");
  stack.className = "toast-stack";
  stack.setAttribute("role", "region");
  stack.setAttribute("aria-label", "Notifications");
  document.body.appendChild(stack);
  var MSG = { success: "Finding saved.", error: "Could not save. Please fix the highlighted fields." };
  document.querySelectorAll("[data-toast]").forEach(function (b) {
    b.addEventListener("click", function () {
      var kind = b.getAttribute("data-toast");
      var t = document.createElement("div");
      t.className = "flash flash-" + kind;
      t.setAttribute("role", kind === "error" ? "alert" : "status");
      var body = document.createElement("div");
      body.className = "flash-body";
      body.textContent = MSG[kind];
      t.appendChild(body);
      stack.appendChild(t);
      setTimeout(function () { t.remove(); }, 4000);
    });
  });
})();
