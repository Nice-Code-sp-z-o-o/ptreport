// "Select all" toggles on the scanner import review page.
(function () {
  "use strict";
  document.querySelectorAll("[data-check-all]").forEach(function (master) {
    var name = master.getAttribute("data-check-all");
    var boxes = function () { return document.querySelectorAll('input[type="checkbox"][name="' + name + '"]'); };
    master.addEventListener("change", function () {
      boxes().forEach(function (b) { b.checked = master.checked; });
    });
    document.addEventListener("change", function (ev) {
      if (ev.target.name !== name) return;
      var all = Array.prototype.every.call(boxes(), function (b) { return b.checked; });
      var none = Array.prototype.every.call(boxes(), function (b) { return !b.checked; });
      master.checked = all;
      master.indeterminate = !all && !none;
    });
  });
})();
