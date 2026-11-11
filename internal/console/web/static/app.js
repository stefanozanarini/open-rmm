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
    // Open the element and every <details> around it.
    for (var d = el; d; d = d.parentElement) {
      if (d.tagName === "DETAILS") d.open = true;
    }
    el.scrollIntoView({ block: "start" });
  }
  window.addEventListener("hashchange", openTarget);
  openTarget();

  // "Select all" boxes tick every agent box of their form.
  document.querySelectorAll("input[data-check-all]").forEach(function (all) {
    all.addEventListener("change", function () {
      all.form.querySelectorAll('input[type=checkbox][name="agent"]').forEach(function (c) { c.checked = all.checked; });
    });
  });

  // Theme and language apply as soon as they are chosen; the Apply buttons
  // stay for browsers without scripts.
  document.querySelectorAll("header form.theme, header form.lang").forEach(function (f) {
    var sel = f.querySelector("select"), btn = f.querySelector("button");
    if (!sel || !btn) return;
    btn.hidden = true;
    sel.addEventListener("change", function () { f.submit(); });
  });

  // Navigation drop-downs: one open at a time, closed by a click elsewhere.
  var menus = document.querySelectorAll("nav details.menu");
  menus.forEach(function (d) {
    d.addEventListener("toggle", function () {
      if (d.open) menus.forEach(function (o) { if (o !== d) o.open = false; });
    });
  });
  document.addEventListener("click", function (e) {
    menus.forEach(function (d) { if (d.open && !d.contains(e.target)) d.open = false; });
  });

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

// Collapsible groups remember whether they were closed (per browser);
// data-keep-open (a filter of the group is active) keeps one open.
(function () {
  document.querySelectorAll("details[data-remember]").forEach(function (d) {
    var key = "open-rmm." + d.dataset.remember;
    try {
      if (localStorage.getItem(key) === "closed" && !d.hasAttribute("data-keep-open")) d.open = false;
    } catch (e) { /* storage unavailable: the default applies */ }
    d.addEventListener("toggle", function () {
      try { localStorage.setItem(key, d.open ? "open" : "closed"); } catch (e) { /* ignored */ }
    });
  });
})();

// Agents workspace: the scrolling list shows the selected agent.
(function () {
  var list = document.querySelector(".list.scroll");
  var row = list && list.querySelector("tr.current");
  if (row) list.scrollTop = Math.max(0, row.offsetTop - list.clientHeight / 3);
})();

// Job dock: the operator's jobs in progress and just finished, in a corner
// of every page (GET /jobs/active.json).
(function () {
  "use strict";
  // Polls every 4 s while a job runs, every 30 s otherwise, and not while
  // the tab is hidden.
  var dock = document.getElementById("jobdock");
  if (dock && window.fetch) {
    var store = function (k, v) {
      try { if (v === undefined) return sessionStorage.getItem(k); sessionStorage.setItem(k, v); } catch (e) { return null; }
    };
    var closed = {};
    (store("jobdock.closed") || "").split(",").forEach(function (id) { if (id) closed[id] = true; });
    var timer = null;
    var el = function (tag, cls, text) {
      var e = document.createElement(tag);
      if (cls) e.className = cls;
      if (text !== undefined) e.textContent = text;
      return e;
    };
    var render = function (jobs) {
      jobs = jobs.filter(function (j) { return !(j.final && closed[j.id]); });
      dock.replaceChildren();
      if (!jobs.length) { dock.hidden = true; return false; }
      var running = jobs.some(function (j) { return !j.final; });
      var small = store("jobdock.small") === "1";
      var head = el("div", "jobdock-head");
      head.appendChild(el("strong", "", dock.dataset.title + " (" + jobs.length + ")"));
      var all = el("a", "small", dock.dataset.all);
      all.href = "/jobs";
      head.appendChild(all);
      var toggle = el("button", "link", small ? dock.dataset.show : dock.dataset.hide);
      toggle.type = "button";
      toggle.addEventListener("click", function () { store("jobdock.small", small ? "0" : "1"); poll(); });
      head.appendChild(toggle);
      if (!running) {
        var close = el("button", "link", dock.dataset.close);
        close.type = "button";
        close.addEventListener("click", function () {
          jobs.forEach(function (j) { closed[j.id] = true; });
          store("jobdock.closed", Object.keys(closed).slice(-100).join(","));
          dock.hidden = true;
        });
        head.appendChild(close);
      }
      dock.appendChild(head);
      if (!small) {
        var list = el("ul");
        jobs.forEach(function (j) {
          var li = el("li");
          var a = el("a", "", j.host || j.id.slice(0, 8));
          a.href = "/jobs/" + j.id;
          li.appendChild(a);
          li.appendChild(el("span", "muted small", " " + j.action + " "));
          li.appendChild(el("span", "badge " + j.state, j.label));
          if (!j.final && j.progress) {
            var bar = el("progress");
            bar.max = 100;
            bar.value = j.progress;
            li.appendChild(bar);
          }
          if (j.message) li.appendChild(el("div", "muted small", j.message));
          list.appendChild(li);
        });
        dock.appendChild(list);
      }
      dock.hidden = false;
      return running;
    };
    var poll = function () {
      clearTimeout(timer);
      if (document.hidden) return;
      fetch(dock.dataset.src, { credentials: "same-origin", headers: { Accept: "application/json" } })
        .then(function (r) { return r.ok ? r.json() : []; })
        .then(function (jobs) { timer = setTimeout(poll, render(jobs) ? 4000 : 30000); })
        .catch(function () { timer = setTimeout(poll, 30000); });
    };
    document.addEventListener("visibilitychange", function () { if (!document.hidden) poll(); });
    poll();
  }
})();
