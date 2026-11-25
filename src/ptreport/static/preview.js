"use strict";
// "Preview PDF": typeset the report in the background and show the PDF in a dialog.
// Without JS (or if the dialog is unsupported) the link simply opens the PDF in a new tab.
(function () {
  var dialog = document.getElementById("pdf-dialog");
  if (!dialog || typeof dialog.showModal !== "function" || !window.fetch) return;

  var frame = dialog.querySelector("[data-pdf-frame]");
  var status = dialog.querySelector("[data-pdf-status]");
  var message = dialog.querySelector("[data-pdf-message]");
  var download = dialog.querySelector("[data-pdf-download]");
  var openTab = dialog.querySelector("[data-pdf-open]");
  var current = { url: null, controller: null };

  function reset() {
    if (current.controller) current.controller.abort();
    if (current.url) URL.revokeObjectURL(current.url);
    current = { url: null, controller: null };
    frame.hidden = true;
    frame.removeAttribute("src");
    download.hidden = true;
    openTab.hidden = true;
    status.hidden = false;
    status.classList.remove("is-error");
  }

  function fail(text, href) {
    status.classList.add("is-error");
    message.textContent = text;
    openTab.href = href;
    openTab.hidden = false;
  }

  function show(href) {
    reset();
    message.textContent = "Generating the PDF from the LaTeX template…";
    dialog.showModal();
    var controller = new AbortController();
    current.controller = controller;
    fetch(href, { credentials: "same-origin", signal: controller.signal })
      .then(function (r) {
        var type = r.headers.get("Content-Type") || "";
        if (!r.ok || type.indexOf("application/pdf") !== 0) {
          throw new Error("PDF generation failed. Open it in a new tab to see the LaTeX log.");
        }
        var name = (/filename="([^"]+)"/.exec(r.headers.get("Content-Disposition") || "") || [])[1] || "report.pdf";
        return r.blob().then(function (blob) { return { blob: blob, name: name }; });
      })
      .then(function (res) {
        current.url = URL.createObjectURL(new Blob([res.blob], { type: "application/pdf" }));
        frame.src = current.url;
        frame.hidden = false;
        status.hidden = true;
        download.href = current.url;
        download.setAttribute("download", res.name);
        download.hidden = false;
        openTab.href = current.url;
        openTab.hidden = false;
      })
      .catch(function (err) {
        if (err && err.name === "AbortError") return;
        fail(err && err.message ? err.message : "Could not reach ptreport. Is it still running?", href);
      });
  }

  document.querySelectorAll("[data-pdf-preview]").forEach(function (link) {
    link.addEventListener("click", function (ev) {
      if (ev.ctrlKey || ev.metaKey || ev.shiftKey || ev.button !== 0) return; // keep "open in new tab"
      ev.preventDefault();
      show(link.getAttribute("href"));
    });
  });
  dialog.querySelector("[data-pdf-close]").addEventListener("click", function () { dialog.close(); });
  dialog.addEventListener("close", reset);
})();
