"use strict";
(function () {
  var BASE = location.pathname.replace(/[^/]*$/, "");
  function $(id) { return document.getElementById(id); }
  function show(v) {
    ["auth", "account"].forEach(function (x) { $("v-" + x).classList.toggle("active", x === v); });
  }
  function msg(el, t, kind) { el.textContent = t || ""; el.className = "msg " + (kind || "err") + (t ? " show" : ""); }

  async function api(path, opts) {
    opts = opts || {};
    opts.headers = Object.assign({ "Content-Type": "application/json" }, opts.headers || {});
    var r = await fetch(BASE + "api/" + path, opts);
    var d = null; try { d = await r.json(); } catch (e) {}
    if (!r.ok) { var e = new Error((d && d.detail) || ("HTTP " + r.status)); e.status = r.status; throw e; }
    return d;
  }
  var jpost = function (p, b) { return api(p, { method: "POST", body: JSON.stringify(b || {}) }); };

  // ---- tabs ----
  Array.prototype.forEach.call(document.querySelectorAll(".tab"), function (t) {
    t.onclick = function () {
      document.querySelectorAll(".tab").forEach(function (x) { x.classList.remove("active"); });
      t.classList.add("active");
      $("t-login").style.display = t.dataset.tab === "login" ? "block" : "none";
      $("t-register").style.display = t.dataset.tab === "register" ? "block" : "none";
      msg($("auth-msg"), "");
    };
  });

  // ---- auth ----
  $("login-btn").onclick = async function () {
    msg($("auth-msg"), "");
    try { await jpost("login", { email: $("li-email").value.trim(), password: $("li-pw").value }); await enter(); }
    catch (e) { msg($("auth-msg"), e.message); }
  };
  $("register-btn").onclick = async function () {
    msg($("auth-msg"), "");
    try {
      await jpost("register", { email: $("rg-email").value.trim(), password: $("rg-pw").value, display_name: $("rg-name").value.trim() });
      await enter();
    } catch (e) { msg($("auth-msg"), e.message); }
  };
  $("li-pw").addEventListener("keydown", function (e) { if (e.key === "Enter") $("login-btn").click(); });
  $("logout-btn").onclick = async function () { try { await jpost("logout"); } catch (e) {} show("auth"); };

  // ---- account ----
  async function enter() {
    var r = await api("me");
    var u = r.user;
    $("u-name").textContent = u.display_name || u.email;
    $("u-email").textContent = u.email;
    $("avatar").textContent = (u.display_name || u.email || "?").trim().charAt(0).toUpperCase();
    show("account");
    await loadConns();
  }

  async function loadConns() {
    var r = await api("connections");
    var host = $("conns"); host.innerHTML = "";
    if (!r.connections.length) { $("conns-empty").style.display = "block"; return; }
    $("conns-empty").style.display = "none";
    r.connections.forEach(function (c) {
      var el = document.createElement("div"); el.className = "conn";
      var ic = document.createElement("div"); ic.className = "ic"; ic.textContent = "🔗";
      var meta = document.createElement("div"); meta.className = "meta";
      var nm = document.createElement("div"); nm.className = "nm"; nm.textContent = c.name;
      var hosts = (c.hosts && c.hosts.length) ? c.hosts : [c.host];
      var sitesTxt = hosts.length > 2 ? (hosts.length + " sites · " + hosts.slice(0, 2).join(", ") + "…")
                                      : hosts.join(", ");
      var det = document.createElement("div"); det.className = "det"; det.textContent = sitesTxt + " · " + c.email;
      det.title = hosts.join("\n");
      meta.appendChild(nm); meta.appendChild(det);
      var acts = document.createElement("div"); acts.className = "acts";
      var test = mkbtn("Test", "ghost sm", async function () {
        test.disabled = true; test.textContent = "…";
        try {
          var t = await jpost("connections/" + c.id + "/test");
          test.textContent = (t.ok ? "✓ " : "✗ ") + t.ok_count + "/" + t.total + " sites";
          test.title = (t.results || []).map(function (r) {
            return (r.ok ? "✓ " : "✗ ") + r.host + (r.ok ? "" : " — " + (r.detail || "no access"));
          }).join("\n");
        } catch (e) { test.textContent = "✗ failed"; }
        setTimeout(function () { test.disabled = false; test.textContent = "Test"; }, 6000);
      });
      var edit = mkbtn("Edit", "ghost sm", function () { startEdit(c); });
      var del = mkbtn("Remove", "danger sm", async function () {
        if (!confirm("Remove connection \"" + c.name + "\"?")) return;
        try { await api("connections/" + c.id, { method: "DELETE" }); if (editingId === c.id) resetForm(); await loadConns(); } catch (e) { alert(e.message); }
      });
      acts.appendChild(test); acts.appendChild(edit); acts.appendChild(del);
      el.appendChild(ic); el.appendChild(meta); el.appendChild(acts);
      host.appendChild(el);
    });
  }
  function mkbtn(txt, cls, fn) { var b = document.createElement("button"); b.className = "btn " + cls; b.textContent = txt; b.onclick = fn; return b; }

  var editingId = null;

  function resetForm() {
    editingId = null;
    ["c-name", "c-url", "c-email", "c-token"].forEach(function (i) { $(i).value = ""; });
    $("c-token").placeholder = "";
    $("addbox-title").textContent = "+ Add a Jira connection";
    $("add-btn").textContent = "Verify & save";
    $("cancel-edit").style.display = "none";
    msg($("add-msg"), "");
  }

  function startEdit(c) {
    editingId = c.id;
    $("c-name").value = c.name || "";
    $("c-url").value = ((c.sites && c.sites.length) ? c.sites : [c.base_url]).join("\n");
    $("c-email").value = c.email || "";
    $("c-token").value = "";
    $("c-token").placeholder = "leave blank to keep current token";
    $("addbox-title").textContent = "Edit “" + c.name + "”";
    $("add-btn").textContent = "Save changes";
    $("cancel-edit").style.display = "inline-flex";
    msg($("add-msg"), "");
    $("addbox").open = true;
    $("addbox").scrollIntoView({ behavior: "smooth", block: "nearest" });
    $("c-name").focus();
  }

  $("cancel-edit").onclick = function (e) { e.preventDefault(); resetForm(); $("addbox").open = false; };

  $("add-btn").onclick = async function () {
    msg($("add-msg"), "");
    var sites = $("c-url").value.split(/[\n,]+/).map(function (s) { return s.trim(); }).filter(Boolean);
    if (!sites.length || !$("c-email").value.trim()) { msg($("add-msg"), "Fill in at least one site and the account email."); return; }
    var token = $("c-token").value.trim();
    if (!editingId && !token) { msg($("add-msg"), "An API token is required."); return; }
    var body = { name: $("c-name").value.trim(), sites: sites, email: $("c-email").value.trim(), token: token, verify: true };
    var btn = $("add-btn");
    btn.disabled = true; btn.textContent = editingId ? "Saving…" : "Verifying…";
    try {
      if (editingId) await api("connections/" + editingId, { method: "PUT", body: JSON.stringify(body) });
      else await jpost("connections", body);
      resetForm();
      $("addbox").open = false;
      await loadConns();
    } catch (e) { msg($("add-msg"), e.message); }
    finally { btn.disabled = false; btn.textContent = editingId ? "Save changes" : "Verify & save"; }
  };

  // ---- init ----
  (async function () {
    // Show the Google button only if the server has it configured.
    api("auth/config").then(function (c) {
      if (c && c.google) $("google-block").style.display = "block";
    }).catch(function () {});
    if (/[?&]auth_error=exists/.test(location.search)) {
      msg($("auth-msg"), "That email already has a password account — sign in with your password below.");
      history.replaceState({}, "", BASE);
    } else if (/[?&]auth_error=google/.test(location.search)) {
      msg($("auth-msg"), "Google sign-in didn't complete. Try again or use email + password.");
      history.replaceState({}, "", BASE);
    }
    try { await enter(); } catch (e) { show("auth"); $("li-email").focus(); }
  })();
})();
