"use strict";
// Evidence files: drop files anywhere on the upload form to put them into its file input.
// Without JS the plain multi-file input works; the server validates every file.
(function () {
  document.querySelectorAll("[data-file-drop]").forEach(function (form) {
    var input = form.querySelector("input[type=file]");
    if (!input || typeof DataTransfer === "undefined") return;
    var depth = 0;
    function hasFiles(ev) {
      return ev.dataTransfer && Array.prototype.indexOf.call(ev.dataTransfer.types, "Files") !== -1;
    }
    form.addEventListener("dragenter", function (ev) {
      if (!hasFiles(ev)) return;
      ev.preventDefault();
      depth += 1;
      form.classList.add("is-dragover");
    });
    form.addEventListener("dragover", function (ev) {
      if (hasFiles(ev)) ev.preventDefault();
    });
    form.addEventListener("dragleave", function () {
      depth = Math.max(0, depth - 1);
      if (!depth) form.classList.remove("is-dragover");
    });
    form.addEventListener("drop", function (ev) {
      if (!hasFiles(ev)) return;
      ev.preventDefault();
      depth = 0;
      form.classList.remove("is-dragover");
      var transfer = new DataTransfer();
      Array.prototype.forEach.call(ev.dataTransfer.files, function (file) { transfer.items.add(file); });
      input.files = transfer.files;
      input.dispatchEvent(new Event("change", { bubbles: true }));
    });
  });
})();
