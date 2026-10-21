// open-rmm console: the agent context menu (right click on an agent row)
// and opening the action named in the address (#act-...). The menu items
// come from a <template> rendered by the server, already translated and
// limited to what the operator may do; this script only shows them.
(function () {
  "use strict";

  // Open the <details> an address points at (e.g. #act-reboot-reboot).
  function openTarget() {
    if (!location.hash) return;
    var el = document.getElementById(location.hash.slice(1));
    if (!el) return;
    if (el.tagName === "DETAILS") el.open = true;
    el.scrollIntoView({ block: "start" });
  }
  window.addEventListener("hashchange", openTarget);
  openTarget();

  var tpl = document.getElementById("agent-menu");
  if (!tpl) return;
  var menu = null;

  function close() {
    if (menu) { menu.remove(); menu = null; }
  }

  // panelURL opens the agent in the bottom panel, keeping the list filters.
  function panelURL(id, tab, hash) {
    var u = new URL(location.href);
    u.searchParams.set("agent", id);
    if (tab) u.searchParams.set("tab", tab); else u.searchParams.delete("tab");
    u.hash = hash || "";
    return u.pathname + u.search + u.hash;
  }

  function post(action, fields) {
    var f = document.createElement("form");
    f.method = "post";
    f.action = action;
    fields.csrf = tpl.dataset.csrf;
    fields["return"] = location.pathname + location.search;
    Object.keys(fields).forEach(function (k) {
      var i = document.createElement("input");
      i.type = "hidden"; i.name = k; i.value = fields[k];
      f.appendChild(i);
    });
    document.body.appendChild(f);
    f.submit();
  }

  document.addEventListener("contextmenu", function (e) {
    var row = e.target.closest("tr[data-agent]");
    if (!row) return;
    e.preventDefault();
    close();
    var id = row.dataset.agent;
    menu = tpl.content.firstElementChild.cloneNode(true);
    menu.querySelector(".ctx-title").textContent = row.dataset.name || "";
    menu.querySelectorAll("[data-only-active]").forEach(function (el) {
      if (row.dataset.status !== "active") el.remove();
    });
    menu.querySelectorAll("a[data-page]").forEach(function (a) {
      a.href = "/agents/" + id;
    });
    menu.querySelectorAll("a[data-tab]").forEach(function (a) {
      a.href = panelURL(id, a.dataset.tab, a.dataset.hash);
    });
    menu.querySelectorAll("a[data-href]").forEach(function (a) {
      a.href = a.dataset.href.replace("{id}", encodeURIComponent(id));
    });
    menu.querySelectorAll("button[data-post]").forEach(function (b) {
      b.addEventListener("click", function () {
        post(b.dataset.post.replace("{id}", encodeURIComponent(id)), { module: b.dataset.module, action: b.dataset.action });
      });
    });
    document.body.appendChild(menu);
    var w = menu.offsetWidth, h = menu.offsetHeight;
    menu.style.left = Math.min(e.pageX, window.scrollX + document.documentElement.clientWidth - w - 8) + "px";
    menu.style.top = Math.min(e.pageY, window.scrollY + document.documentElement.clientHeight - h - 8) + "px";
    var first = menu.querySelector("a, button");
    if (first) first.focus();
  });
  document.addEventListener("click", function (e) {
    if (menu && !menu.contains(e.target)) close();
  });
  document.addEventListener("keydown", function (e) {
    if (e.key === "Escape") close();
  });
  window.addEventListener("scroll", close, { passive: true });
})();
