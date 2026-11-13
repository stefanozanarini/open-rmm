// Tempra RMM remote control: a <canvas> connected to the session over a
// WebSocket. Screen frames arrive as binary messages carrying the
// internal/screensession wire format (decoded here); input events are
// sent as small JSON messages, which the server turns into that same
// wire format before relaying them to the agent.
(function () {
  "use strict";
  var canvas = document.getElementById("screen-canvas");
  var status = document.getElementById("screen-status");
  var ctx = canvas.getContext("2d");
  var img = new Image();
  var buf = new Uint8Array(0);
  var scale = 1; // canvas device pixels per remote virtual-desktop pixel

  function append(chunk) {
    var next = new Uint8Array(buf.length + chunk.length);
    next.set(buf);
    next.set(chunk, buf.length);
    buf = next;
  }

  // Decodes as many complete frames as buf currently holds; mirrors
  // internal/screensession.Decoder.Feed.
  function drain() {
    while (buf.length > 0) {
      var kind = buf[0];
      if (kind === 0x46 /* 'F' */) {
        if (buf.length < 5) return;
        var n = new DataView(buf.buffer, buf.byteOffset + 1, 4).getUint32(0, false);
        if (buf.length < 5 + n) return;
        showImage(buf.slice(5, 5 + n));
        buf = buf.slice(5 + n);
        continue;
      }
      if (kind === 0x53 /* 'S' */) {
        if (buf.length < 9) return;
        var dv = new DataView(buf.buffer, buf.byteOffset + 1, 8);
        resize(dv.getUint32(0, false), dv.getUint32(4, false));
        buf = buf.slice(9);
        continue;
      }
      // Unknown kind: drop everything, the stream cannot be resynchronized.
      buf = new Uint8Array(0);
      return;
    }
  }

  function resize(w, h) {
    canvas.width = w;
    canvas.height = h;
  }

  function showImage(jpegBytes) {
    var blob = new Blob([jpegBytes], { type: "image/jpeg" });
    var url = URL.createObjectURL(blob);
    var im = new Image();
    im.onload = function () {
      if (canvas.width && canvas.height) ctx.drawImage(im, 0, 0, canvas.width, canvas.height);
      URL.revokeObjectURL(url);
    };
    im.src = url;
  }

  var ws = new WebSocket((location.protocol === "https:" ? "wss://" : "ws://") + location.host + canvas.dataset.ws);
  ws.binaryType = "arraybuffer";
  function send(m) {
    if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(m));
  }
  ws.onopen = function () { status.textContent = canvas.dataset.connected; };
  ws.onmessage = function (e) {
    if (typeof e.data === "string") {
      status.textContent = e.data;
      return;
    }
    append(new Uint8Array(e.data));
    drain();
  };
  ws.onclose = function () {
    if (status.textContent === canvas.dataset.connected) status.textContent = canvas.dataset.closed;
  };

  function toRemote(e) {
    var r = canvas.getBoundingClientRect();
    var sx = canvas.width / r.width, sy = canvas.height / r.height;
    return { x: Math.round((e.clientX - r.left) * sx), y: Math.round((e.clientY - r.top) * sy) };
  }
  canvas.addEventListener("contextmenu", function (e) { e.preventDefault(); });
  canvas.addEventListener("mousemove", function (e) {
    var p = toRemote(e);
    send({ t: "move", x: p.x, y: p.y });
  });
  canvas.addEventListener("mousedown", function (e) { canvas.focus(); send({ t: "button", button: e.button, down: true }); });
  canvas.addEventListener("mouseup", function (e) { send({ t: "button", button: e.button, down: false }); });
  canvas.addEventListener("wheel", function (e) {
    e.preventDefault();
    send({ t: "wheel", delta: Math.round(-e.deltaY) });
  }, { passive: false });
  // keyCode is deprecated but, for letters, digits and the common
  // control keys, its values are the same as Windows virtual-key codes
  // (both trace back to the same legacy scheme): good enough to drive
  // SendInput without a full per-layout mapping table.
  canvas.addEventListener("keydown", function (e) { e.preventDefault(); send({ t: "key", key: e.keyCode, down: true }); });
  canvas.addEventListener("keyup", function (e) { e.preventDefault(); send({ t: "key", key: e.keyCode, down: false }); });
  document.getElementById("screen-close").addEventListener("click", function () { send({ t: "close" }); });
})();
