// Tempra RMM file manager: browses the folder of one session, downloads
// (one file, or the same path from every selected session as a zip),
// uploads to the same folder of the selected sessions, creates folders.
// The server does the work (/files/...); this script only drives it.
(function () {
  "use strict";
  var root = document.getElementById("files");
  if (!root) return;
  var L = root.dataset;
  var browse = document.getElementById("fs-browse");
  var pathIn = document.getElementById("fs-path");
  var status = document.getElementById("fs-status");
  var tbody = document.querySelector("#fs-table tbody");
  var rootsBox = document.getElementById("fs-roots");
  var current = "", sep = "\\", retry = null;

  function targets() {
    return Array.prototype.filter.call(document.querySelectorAll(".fs-target"), function (c) { return c.checked; })
      .map(function (c) { return c.value; });
  }
  function el(tag, text, cls) {
    var e = document.createElement(tag);
    if (text !== undefined) e.textContent = text;
    if (cls) e.className = cls;
    return e;
  }
  function size(n) {
    if (n >= 1073741824) return (n / 1073741824).toFixed(1) + " GB";
    if (n >= 1048576) return (n / 1048576).toFixed(1) + " MB";
    if (n >= 1024) return (n / 1024).toFixed(1) + " KB";
    return n + " B";
  }
  function join(dir, name) {
    return dir.replace(/[\\/]+$/, "") + sep + name;
  }
  function parent(p) {
    var t = p.replace(/[\\/]+$/, "");
    var i = Math.max(t.lastIndexOf("\\"), t.lastIndexOf("/"));
    if (i < 0) return "";
    var up = t.slice(0, i + 1);
    return /^[A-Za-z]:$/.test(t) ? "" : up;
  }
  function api(url, opts) {
    return fetch(url, Object.assign({ credentials: "same-origin" }, opts || {})).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (b) { b._status = r.status; return b; });
    });
  }
  function load(path) {
    clearTimeout(retry);
    status.textContent = L.loading;
    api("/files/" + browse.value + "/list?path=" + encodeURIComponent(path || "")).then(function (b) {
      if (b._status === 409) {
        status.textContent = L.waiting;
        retry = setTimeout(function () { load(path); }, 3000);
        return;
      }
      if (b._status !== 200) { status.textContent = b.error || ("HTTP " + b._status); return; }
      if (b.sep) sep = b.sep;
      if (b.roots) { showRoots(b.roots); if (!path) { load(b.roots[0]); } return; }
      current = b.path;
      pathIn.value = current;
      show(b.entries || []);
      status.textContent = b.truncated ? L.truncated : (b.entries && b.entries.length ? "" : L.empty);
    }).catch(function (e) { status.textContent = String(e); });
  }
  function showRoots(roots) {
    rootsBox.replaceChildren();
    if (roots.length < 2) return;
    roots.forEach(function (r) {
      var b = el("button", r);
      b.type = "button";
      b.addEventListener("click", function () { load(r); });
      rootsBox.appendChild(b);
    });
  }
  function show(entries) {
    tbody.replaceChildren();
    entries.forEach(function (e) {
      var tr = el("tr");
      var name = el("td");
      var full = join(current, e.name);
      if (e.dir) {
        var a = el("a", "📁 " + e.name);
        a.href = "#";
        a.addEventListener("click", function (ev) { ev.preventDefault(); load(full); });
        name.appendChild(a);
      } else {
        name.textContent = "📄 " + e.name;
      }
      tr.appendChild(name);
      tr.appendChild(el("td", e.dir ? L.folder : size(e.size || 0)));
      tr.appendChild(el("td", e.modified ? new Date(e.modified).toLocaleString() : ""));
      var act = el("td");
      if (!e.dir) {
        var d = el("a", L.download);
        d.href = "/files/" + browse.value + "/download?path=" + encodeURIComponent(full);
        act.appendChild(d);
        var all = targets();
        if (all.length > 1) {
          var z = el("a", L.zip);
          z.href = "/files/zip?" + all.map(function (j) { return "job=" + encodeURIComponent(j); }).join("&") +
            "&path=" + encodeURIComponent(full);
          act.appendChild(z);
        }
      }
      tr.appendChild(act);
      tbody.appendChild(tr);
    });
  }

  document.getElementById("fs-go").addEventListener("submit", function (ev) { ev.preventDefault(); load(pathIn.value.trim()); });
  document.getElementById("fs-up").addEventListener("click", function () { var p = parent(current); if (p) load(p); });
  browse.addEventListener("change", function () { current = ""; load(""); });
  document.querySelectorAll(".fs-target").forEach(function (c) { c.addEventListener("change", function () { if (current) load(current); }); });

  document.getElementById("fs-mkdir").addEventListener("submit", function (ev) {
    ev.preventDefault();
    var name = document.getElementById("fs-dirname");
    if (!current || !name.value.trim()) return;
    var body = new URLSearchParams({ csrf: L.csrf, path: join(current, name.value.trim()) });
    api("/files/" + browse.value + "/mkdir", { method: "POST", body: body }).then(function (b) {
      if (b._status !== 200) { status.textContent = b.error || ("HTTP " + b._status); return; }
      name.value = "";
      load(current);
    });
  });

  document.getElementById("fs-upload").addEventListener("submit", function (ev) {
    ev.preventDefault();
    var file = document.getElementById("fs-file").files[0];
    var results = document.getElementById("fs-results");
    var bar = document.getElementById("fs-progress");
    var jobs = targets();
    if (!file || !current) return;
    if (!jobs.length) { status.textContent = L.noTarget; return; }
    if (file.size > Number(L.max)) { status.textContent = L.tooBig; return; }
    // Field order matters: the server reads them before the file.
    var fd = new FormData();
    fd.append("csrf", L.csrf);
    jobs.forEach(function (j) { fd.append("job", j); });
    fd.append("dir", current);
    fd.append("size", String(file.size));
    fd.append("overwrite", document.getElementById("fs-overwrite").checked ? "1" : "0");
    fd.append("file", file, file.name);
    var xhr = new XMLHttpRequest();
    xhr.open("POST", "/files/upload");
    xhr.upload.addEventListener("progress", function (e) { if (e.lengthComputable) bar.value = Math.round(100 * e.loaded / e.total); });
    bar.hidden = false;
    bar.value = 0;
    status.textContent = L.uploading;
    xhr.addEventListener("loadend", function () {
      bar.hidden = true;
      status.textContent = "";
      var b = {};
      try { b = JSON.parse(xhr.responseText); } catch (e) { /* not JSON */ }
      results.replaceChildren();
      if (xhr.status !== 200) { results.appendChild(el("li", b.error || ("HTTP " + xhr.status), "error")); return; }
      (b.results || []).forEach(function (r) {
        var li = el("li");
        li.appendChild(el("strong", r.hostname + ": "));
        li.appendChild(el("span", r.ok ? (r.path + " " + L.done) : (L.failed + ": " + r.error), r.ok ? "" : "error"));
        results.appendChild(li);
      });
      load(current);
    });
    xhr.send(fd);
  });

  load("");
})();
