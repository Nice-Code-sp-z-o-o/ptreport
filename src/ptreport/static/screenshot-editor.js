"use strict";
// Screenshot editor on the finding page: crop, arrows, boxes and pixelated regions drawn on a canvas, then
// uploaded as a PNG that replaces the screenshot (the server keeps the original for "Restore original").
// Without JS the "Edit" buttons stay hidden; everything else on the page keeps working.
(function () {
  var dialog = document.getElementById("shot-editor");
  if (!dialog || typeof dialog.showModal !== "function" || !window.fetch || !window.FormData) return;
  if (!HTMLCanvasElement.prototype.toBlob) return;

  var MAX_BYTES = 10 * 1024 * 1024;     // same limit as uploads (the server checks it again)
  var STROKES = { 1: 2, 2: 4, 3: 7 };    // S/M/L, multiplied by the image's scale unit
  var MIN_DRAG = 4;                      // px in image space; shorter drags are treated as clicks

  var canvas = dialog.querySelector("[data-editor-canvas]");
  var g = canvas.getContext("2d");
  var stage = dialog.querySelector("[data-editor-stage]");
  var status = dialog.querySelector("[data-editor-status]");
  var message = dialog.querySelector("[data-editor-message]");
  var nameEl = dialog.querySelector("[data-editor-name]");
  var errorBox = dialog.querySelector("[data-editor-error]");
  var saveBtn = dialog.querySelector("[data-editor-save]");
  var undoBtn = dialog.querySelector("[data-editor-undo]");
  var redoBtn = dialog.querySelector("[data-editor-redo]");
  var cropActions = dialog.querySelector("[data-crop-actions]");
  var cropApply = dialog.querySelector("[data-crop-apply]");
  var token = dialog.getAttribute("data-csrf") || "";

  var state = null;
  var tool = "arrow";
  var colour = "--c-danger-strong";
  var stroke = 2;

  function cssVar(name) {
    return getComputedStyle(document.documentElement).getPropertyValue(name).trim() || "#ffffff";
  }

  function makeCanvas(w, h) {
    var c = document.createElement("canvas");
    c.width = w;
    c.height = h;
    return c;
  }

  function copyOf(source) {
    var c = makeCanvas(source.width, source.height);
    c.getContext("2d").drawImage(source, 0, 0);
    return c;
  }

  // ------------------------------------------------------------ operations --
  // Every edit is an operation in the coordinate space of the image it was drawn on, so undo/redo simply
  // replays the list on top of the loaded image.

  function unitFor(c) { return Math.max(1, Math.max(c.width, c.height) / 1000); }

  function drawShape(ctx, op) {
    ctx.save();
    ctx.strokeStyle = op.colour;
    ctx.fillStyle = op.colour;
    ctx.lineWidth = op.width;
    ctx.lineCap = "round";
    ctx.lineJoin = "round";
    if (op.type === "rect") {
      ctx.lineJoin = "miter";
      ctx.strokeRect(op.x, op.y, op.w, op.h);
    } else {
      var dx = op.x2 - op.x1, dy = op.y2 - op.y1;
      var len = Math.sqrt(dx * dx + dy * dy);
      var head = Math.min(len * 0.6, Math.max(op.width * 4.5, 12));
      var angle = Math.atan2(dy, dx);
      var bx = op.x2 - Math.cos(angle) * head * 0.8, by = op.y2 - Math.sin(angle) * head * 0.8;
      ctx.beginPath();
      ctx.moveTo(op.x1, op.y1);
      ctx.lineTo(bx, by);
      ctx.stroke();
      ctx.beginPath();
      ctx.moveTo(op.x2, op.y2);
      ctx.lineTo(op.x2 - head * Math.cos(angle - 0.45), op.y2 - head * Math.sin(angle - 0.45));
      ctx.lineTo(op.x2 - head * Math.cos(angle + 0.45), op.y2 - head * Math.sin(angle + 0.45));
      ctx.closePath();
      ctx.fill();
    }
    ctx.restore();
  }

  // Each block becomes one flat colour, written into the pixels themselves: nothing of the original detail
  // survives in the saved PNG (unlike a CSS/canvas blur, which can be partly reversed). The block average is
  // also rounded to a coarse step: exact averages of large-enough blocks are what de-pixelation tools
  // (e.g. Depix) match against rendered candidate text, so they must not be kept.
  var PIXELATE_STEP = 48;
  function quantize(v) {
    return Math.min(255, Math.round(v / PIXELATE_STEP) * PIXELATE_STEP);
  }
  function pixelate(ctx, op) {
    var img = ctx.getImageData(op.x, op.y, op.w, op.h);
    var d = img.data, w = op.w, h = op.h, b = op.block;
    for (var by = 0; by < h; by += b) {
      for (var bx = 0; bx < w; bx += b) {
        var ye = Math.min(by + b, h), xe = Math.min(bx + b, w), r = 0, gr = 0, bl = 0, n = 0, x, y, i;
        for (y = by; y < ye; y++) {
          for (x = bx; x < xe; x++) {
            i = (y * w + x) * 4;
            r += d[i]; gr += d[i + 1]; bl += d[i + 2]; n++;
          }
        }
        r = quantize(r / n); gr = quantize(gr / n); bl = quantize(bl / n);
        for (y = by; y < ye; y++) {
          for (x = bx; x < xe; x++) {
            i = (y * w + x) * 4;
            d[i] = r; d[i + 1] = gr; d[i + 2] = bl; d[i + 3] = 255;
          }
        }
      }
    }
    ctx.putImageData(img, op.x, op.y);
  }

  function applyOp(c, op) {
    if (op.type === "crop") {
      var n = makeCanvas(op.w, op.h);
      n.getContext("2d").drawImage(c, op.x, op.y, op.w, op.h, 0, 0, op.w, op.h);
      return n;
    }
    var ctx = c.getContext("2d");
    if (op.type === "pixelate") pixelate(ctx, op);
    else drawShape(ctx, op);
    return c;
  }

  function replay() {
    var c = copyOf(state.base);
    state.ops.forEach(function (op) { c = applyOp(c, op); });
    state.composite = c;
  }

  function push(op) {
    state.ops.push(op);
    state.redo = [];
    state.composite = applyOp(state.composite, op);
    afterChange();
  }

  function undo() {
    if (!state || !state.ops.length) return;
    state.redo.push(state.ops.pop());
    replay();
    afterChange();
  }

  function redo() {
    if (!state || !state.redo.length) return;
    var op = state.redo.pop();
    state.ops.push(op);
    state.composite = applyOp(state.composite, op);
    afterChange();
  }

  function afterChange() {
    state.selection = null;
    undoBtn.disabled = !state.ops.length;
    redoBtn.disabled = !state.redo.length;
    saveBtn.disabled = !state.ops.length;
    cropApply.disabled = true;
    hideError();
    fit();
    draw();
  }

  // --------------------------------------------------------------- drawing --

  function rectOf(a) {
    var x = Math.round(Math.min(a.x0, a.x1)), y = Math.round(Math.min(a.y0, a.y1));
    return { x: x, y: y, w: Math.round(Math.max(a.x0, a.x1)) - x, h: Math.round(Math.max(a.y0, a.y1)) - y };
  }

  function pendingOp() {
    var d = state.drag;
    if (!d) return null;
    var c = state.composite, unit = unitFor(c);
    if (tool === "arrow") {
      return { type: "arrow", x1: d.x0, y1: d.y0, x2: d.x1, y2: d.y1, colour: cssVar(colour), width: STROKES[stroke] * unit };
    }
    var r = rectOf(d);
    if (tool === "rect") return { type: "rect", x: r.x, y: r.y, w: r.w, h: r.h, colour: cssVar(colour), width: STROKES[stroke] * unit };
    if (tool === "pixelate") {
      return { type: "pixelate", x: r.x, y: r.y, w: r.w, h: r.h, block: Math.max(20, Math.round(Math.max(c.width, c.height) / 50)) };
    }
    return { type: "crop", x: r.x, y: r.y, w: r.w, h: r.h };
  }

  function bigEnough(op) {
    if (!op) return false;
    if (op.type === "arrow") return Math.abs(op.x2 - op.x1) + Math.abs(op.y2 - op.y1) >= MIN_DRAG * 2;
    return op.w >= MIN_DRAG && op.h >= MIN_DRAG;
  }

  function outline(r, dashed) {
    var unit = unitFor(canvas);
    g.save();
    g.lineWidth = Math.max(1, unit * 1.5);
    g.strokeStyle = cssVar("--c-accent");
    if (dashed) g.setLineDash([6 * unit, 4 * unit]);
    g.strokeRect(r.x + 0.5, r.y + 0.5, r.w, r.h);
    g.restore();
  }

  function shade(r) {
    g.save();
    g.fillStyle = cssVar("--c-overlay");
    g.fillRect(0, 0, canvas.width, r.y);
    g.fillRect(0, r.y + r.h, canvas.width, canvas.height - r.y - r.h);
    g.fillRect(0, r.y, r.x, r.h);
    g.fillRect(r.x + r.w, r.y, canvas.width - r.x - r.w, r.h);
    g.restore();
  }

  function draw() {
    if (!state || !state.composite) return;
    var c = state.composite;
    if (canvas.width !== c.width || canvas.height !== c.height) {
      canvas.width = c.width;
      canvas.height = c.height;
    }
    g.clearRect(0, 0, canvas.width, canvas.height);
    g.drawImage(c, 0, 0);
    var op = pendingOp();
    if (op && bigEnough(op)) {
      if (op.type === "crop") { shade(op); outline(op, true); }
      else if (op.type === "pixelate") {
        var tmp = makeCanvas(op.w, op.h);
        tmp.getContext("2d").drawImage(c, op.x, op.y, op.w, op.h, 0, 0, op.w, op.h);
        pixelate(tmp.getContext("2d"), { x: 0, y: 0, w: op.w, h: op.h, block: op.block });
        g.drawImage(tmp, op.x, op.y);
        outline(op, true);
      } else drawShape(g, op);
    } else if (state.selection) {
      shade(state.selection);
      outline(state.selection, true);
    }
  }

  // Scale the canvas (CSS size only, never the pixels) to fit the stage.
  function fit() {
    if (!state || !state.composite) return;
    var c = state.composite;
    var cs = getComputedStyle(stage);
    var w = stage.clientWidth - parseFloat(cs.paddingLeft) - parseFloat(cs.paddingRight);
    var h = stage.clientHeight - parseFloat(cs.paddingTop) - parseFloat(cs.paddingBottom);
    var scale = Math.min(1, w / c.width, h / c.height);
    canvas.style.width = Math.max(1, Math.floor(c.width * scale)) + "px";
    canvas.style.height = Math.max(1, Math.floor(c.height * scale)) + "px";
  }

  function point(ev) {
    var r = canvas.getBoundingClientRect();
    var x = (ev.clientX - r.left) * canvas.width / r.width;
    var y = (ev.clientY - r.top) * canvas.height / r.height;
    return { x: Math.max(0, Math.min(canvas.width, x)), y: Math.max(0, Math.min(canvas.height, y)) };
  }

  canvas.addEventListener("pointerdown", function (ev) {
    if (!state || !state.composite || state.busy || ev.button !== 0) return;
    ev.preventDefault();
    canvas.setPointerCapture(ev.pointerId);
    var p = point(ev);
    state.selection = null;
    cropApply.disabled = true;
    state.drag = { x0: p.x, y0: p.y, x1: p.x, y1: p.y };
    draw();
  });
  canvas.addEventListener("pointermove", function (ev) {
    if (!state || !state.drag) return;
    var p = point(ev);
    state.drag.x1 = p.x;
    state.drag.y1 = p.y;
    draw();
  });
  function endDrag() {
    if (!state || !state.drag) return;
    var op = pendingOp();
    state.drag = null;
    if (!bigEnough(op)) { draw(); return; }
    if (op.type === "crop") {
      state.selection = op;
      cropApply.disabled = false;
      draw();
    } else push(op);
  }
  canvas.addEventListener("pointerup", endDrag);
  canvas.addEventListener("pointercancel", function () { if (state) { state.drag = null; draw(); } });

  function applyCrop() {
    if (!state || !state.selection) return;
    var s = state.selection;
    if (s.w === state.composite.width && s.h === state.composite.height) return;
    push(s);
  }
  cropApply.addEventListener("click", applyCrop);

  // --------------------------------------------------------------- toolbar --

  function press(buttons, active) {
    buttons.forEach(function (b) { b.setAttribute("aria-pressed", b === active ? "true" : "false"); });
  }

  var toolButtons = Array.prototype.slice.call(dialog.querySelectorAll("[data-tool]"));
  var colourButtons = Array.prototype.slice.call(dialog.querySelectorAll("[data-colour]"));
  var strokeButtons = Array.prototype.slice.call(dialog.querySelectorAll("[data-stroke]"));

  function setTool(name) {
    var button = toolButtons.filter(function (b) { return b.getAttribute("data-tool") === name; })[0];
    if (!button) return;
    tool = name;
    press(toolButtons, button);
    cropActions.hidden = name !== "crop";
    var drawsShapes = name === "arrow" || name === "rect";
    colourButtons.concat(strokeButtons).forEach(function (b) { b.disabled = !drawsShapes; });
    if (state) {
      state.selection = null;
      cropApply.disabled = true;
      draw();
    }
  }

  toolButtons.forEach(function (b) {
    b.addEventListener("click", function () { setTool(b.getAttribute("data-tool")); });
  });
  colourButtons.forEach(function (b) {
    b.addEventListener("click", function () { colour = b.getAttribute("data-colour"); press(colourButtons, b); });
  });
  strokeButtons.forEach(function (b) {
    b.addEventListener("click", function () { stroke = Number(b.getAttribute("data-stroke")); press(strokeButtons, b); });
  });
  undoBtn.addEventListener("click", undo);
  redoBtn.addEventListener("click", redo);

  dialog.addEventListener("keydown", function (ev) {
    if (!state) return;
    var key = ev.key.toLowerCase();
    if ((ev.ctrlKey || ev.metaKey) && !ev.altKey) {
      if (key === "z" && !ev.shiftKey) { ev.preventDefault(); undo(); }
      else if ((key === "z" && ev.shiftKey) || key === "y") { ev.preventDefault(); redo(); }
      return;
    }
    if (ev.altKey || ev.target.closest("input, textarea, select")) return;
    if (key === "enter" && state.selection) { ev.preventDefault(); applyCrop(); return; }
    var shortcut = { a: "arrow", b: "rect", p: "pixelate", c: "crop" }[key];
    if (shortcut) { ev.preventDefault(); setTool(shortcut); }
  });

  // ------------------------------------------------------------ open/save --

  function showError(text) {
    errorBox.textContent = text;
    errorBox.hidden = false;
    dialog.querySelector("[data-editor-info]").hidden = true;
  }

  function hideError() {
    errorBox.hidden = true;
    dialog.querySelector("[data-editor-info]").hidden = false;
  }

  function toBlob(type, quality) {
    return new Promise(function (resolve) { canvas.toBlob(resolve, type, quality); });
  }

  function save() {
    if (!state || state.busy || !state.ops.length) return;
    state.busy = true;
    state.drag = null;
    state.selection = null;
    saveBtn.setAttribute("aria-busy", "true");
    hideError();
    // export exactly the edited image (no selection outline)
    g.clearRect(0, 0, canvas.width, canvas.height);
    g.drawImage(state.composite, 0, 0);
    var action = state.action;
    toBlob("image/png")
      .then(function (blob) {
        // a huge photo-like screenshot can exceed the limit as PNG; JPEG keeps it within the upload size
        if (blob && blob.size > MAX_BYTES) return toBlob("image/jpeg", 0.92);
        return blob;
      })
      .then(function (blob) {
        if (!blob) throw new Error("The browser could not encode the image.");
        if (blob.size > MAX_BYTES) throw new Error("The edited image is larger than 10 MB. Crop it and try again.");
        var form = new FormData();
        form.append("_csrf", token);
        form.append("file", blob, blob.type === "image/jpeg" ? "screenshot.jpg" : "screenshot.png");
        return fetch(action, {
          method: "POST", body: form, credentials: "same-origin", headers: { "X-CSRF-Token": token },
        });
      })
      .then(function (r) {
        return r.json().catch(function () { return {}; }).then(function (body) {
          if (!r.ok || !body.ok) {
            throw new Error(body.message || ("Saving failed (HTTP " + r.status + "). Reload the page and try again."));
          }
          return body;
        });
      })
      .then(function (body) {
        state.done = true;
        history.replaceState(null, "", body.redirect);
        window.location.reload();
      })
      .catch(function (err) {
        if (!state) return;
        state.busy = false;
        saveBtn.removeAttribute("aria-busy");
        showError(err && err.message && err.name !== "TypeError" ? err.message : "Could not reach ptreport. Is it still running?");
        draw();
      });
  }
  saveBtn.addEventListener("click", save);

  function open(button) {
    hideError();
    state = { action: button.getAttribute("data-action"), base: null, composite: null, ops: [], redo: [],
              drag: null, selection: null, busy: false };
    nameEl.textContent = button.getAttribute("data-title") || "";
    canvas.hidden = true;
    status.hidden = false;
    status.classList.remove("is-error");
    message.textContent = "Loading the screenshot…";
    saveBtn.disabled = true;
    undoBtn.disabled = true;
    redoBtn.disabled = true;
    setTool("arrow");
    dialog.showModal();
    var current = state;
    var img = new Image();
    img.onload = function () {
      if (state !== current) return;
      var base = makeCanvas(img.naturalWidth, img.naturalHeight);
      base.getContext("2d").drawImage(img, 0, 0);
      state.base = base;
      state.composite = copyOf(base);
      status.hidden = true;
      canvas.hidden = false;
      fit();
      draw();
    };
    img.onerror = function () {
      if (state !== current) return;
      status.classList.add("is-error");
      message.textContent = "The screenshot could not be loaded.";
    };
    img.src = button.getAttribute("data-src");
  }

  function close() { if (dialog.open) dialog.close(); }

  dialog.querySelectorAll("[data-editor-cancel]").forEach(function (b) { b.addEventListener("click", close); });
  dialog.addEventListener("cancel", function (ev) {
    // Esc cancels the editor, except while a save is in flight
    if (state && state.busy) ev.preventDefault();
  });
  dialog.addEventListener("close", function () {
    if (state && state.done) return;
    state = null;
    saveBtn.removeAttribute("aria-busy");
    g.clearRect(0, 0, canvas.width, canvas.height);
  });
  window.addEventListener("resize", function () { if (state && state.composite) fit(); });

  document.querySelectorAll("[data-shot-edit]").forEach(function (button) {
    button.hidden = false;
    button.addEventListener("click", function () { open(button); });
  });
})();
