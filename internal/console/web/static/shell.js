// open-rmm interactive shell: xterm.js connected to the session over a
// WebSocket. Output arrives as binary messages, status as text messages.
(function () {
  "use strict";
  var el = document.getElementById("terminal");
  var status = document.getElementById("shell-status");
  var term = new Terminal({ cursorBlink: true, fontSize: 14, scrollback: 5000 });
  var fit = new FitAddon.FitAddon();
  term.loadAddon(fit);
  term.open(el);
  fit.fit();
  term.focus();
  var ws = new WebSocket((location.protocol === "https:" ? "wss://" : "ws://") + location.host + el.dataset.ws);
  ws.binaryType = "arraybuffer";
  function send(m) {
    if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(m));
  }
  function resize() {
    fit.fit();
    send({ t: "r", c: term.cols, r: term.rows });
  }
  ws.onopen = function () {
    status.textContent = el.dataset.connected;
    resize();
  };
  ws.onmessage = function (e) {
    if (typeof e.data === "string") {
      status.textContent = e.data;
      return;
    }
    term.write(new Uint8Array(e.data));
  };
  ws.onclose = function () {
    if (status.textContent === el.dataset.connected) status.textContent = el.dataset.closed;
    term.options.disableStdin = true;
  };
  term.onData(function (d) { send({ t: "i", d: d }); });
  window.addEventListener("resize", resize);
  document.getElementById("shell-close").addEventListener("click", function () { send({ t: "c" }); });
})();
