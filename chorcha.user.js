// ==UserScript==
// @name         Chorcha Answer Bar
// @namespace    chorcha-answers
// @version      16.0
// @description  Auto-clicks correct answer on Chorcha exams — moveable
// @match        *://chorcha.net/*
// @run-at       document-start
// @grant        none
// ==/UserScript==

(function () {
  "use strict";

  let answers = [];
  let current = 0;

  function dcode(t, k) {
    if (!t || typeof t !== "string") return "";
    let r = "";
    for (let i = 0; i < t.length; i++)
      r += String.fromCharCode(t.charCodeAt(i) - k.charCodeAt(i % 16));
    return r;
  }

  const isQ   = u => u.includes("/exam/quick");
  const isB   = u => u.includes("/battle/exam-config");
  const isTgt = u => isQ(u) || isB(u);

  function processResp(url, json, key) {
    try {
      if (!json || json.status !== "success" || !json.data) return;
      let a = [];
      if (isB(url)) {
        if (json.data.questions?.length)
          a = json.data.questions.map((q, i) => ({ n: i + 1, a: (q.answer || "?").toUpperCase().trim() }));
        else if (json.data.exam?.questions)
          a = json.data.exam.questions.map((q, i) => ({ n: i + 1, a: (q.c || "?").toUpperCase().trim() }));
      } else if (isQ(url)) {
        if (!key || !json.data.questions) return;
        a = json.data.questions.map((q, i) => ({ n: i + 1, a: dcode(q.answer, key).toUpperCase().trim() || "?" }));
      }
      if (a.length) { answers = a; current = 0; renderNav(); }
    } catch (e) {}
  }

  const _f = window.fetch;
  window.fetch = async function (...args) {
    const res = await _f.apply(this, args);
    try {
      const u = typeof args[0] === "string" ? args[0] : args[0] instanceof Request ? args[0].url : "";
      if (isTgt(u)) {
        const k = isQ(u) ? (res.headers.get("x-chorcha-id") || "") : "";
        res.clone().json().then(j => processResp(u, j, k)).catch(() => {});
      }
    } catch (e) {}
    return res;
  };

  const _xo = XMLHttpRequest.prototype.open;
  const _xs = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.open = function (m, u) { this._u = String(u || ""); return _xo.apply(this, arguments); };
  XMLHttpRequest.prototype.send = function () {
    if (isTgt(this._u || ""))
      this.addEventListener("load", function () {
        try { processResp(this._u, JSON.parse(this.responseText), isQ(this._u) ? (this.getResponseHeader("x-chorcha-id") || "") : ""); } catch (e) {}
      });
    return _xs.apply(this, arguments);
  };

  function clickAnswer(letter) {
    const idx = { A: 0, B: 1, C: 2, D: 3 }[letter];
    if (idx === undefined) return false;
    const btns = Array.from(document.querySelectorAll('main button.flex.w-full.gap-2.rounded-lg'));
    if (!btns[idx]) return false;
    btns[idx].click();
    return true;
  }

  function makeDraggable(el, skipSel) {
    let active = false, startX, startY, origLeft, origTop;

    function onDown(cx, cy) {
      const r = el.getBoundingClientRect();
      origLeft = r.left; origTop = r.top;
      startX = cx; startY = cy;
      el.style.left = origLeft + "px"; el.style.top = origTop + "px";
      el.style.right = "auto"; el.style.bottom = "auto";
      active = true; el.style.cursor = "grabbing";
    }
    function onMove(cx, cy) {
      if (!active) return;
      el.style.left = Math.max(0, Math.min(origLeft + cx - startX, innerWidth  - el.offsetWidth))  + "px";
      el.style.top  = Math.max(0, Math.min(origTop  + cy - startY, innerHeight - el.offsetHeight)) + "px";
    }
    function onUp() { active = false; el.style.cursor = "grab"; }

    el.addEventListener("mousedown", e => { if (skipSel && e.target.closest(skipSel)) return; onDown(e.clientX, e.clientY); e.preventDefault(); });
    document.addEventListener("mousemove", e => onMove(e.clientX, e.clientY));
    document.addEventListener("mouseup", onUp);
    el.addEventListener("touchstart", e => { if (skipSel && e.target.closest(skipSel)) return; onDown(e.touches[0].clientX, e.touches[0].clientY); e.preventDefault(); }, { passive: false });
    document.addEventListener("touchmove", e => { if (!active) return; onMove(e.touches[0].clientX, e.touches[0].clientY); e.preventDefault(); }, { passive: false });
    document.addEventListener("touchend", onUp);
  }

  function buildUI() {
    const tw = document.createElement("script");
    tw.src = "https://cdn.tailwindcss.com";
    document.head.appendChild(tw);

    const font = document.createElement("link");
    font.rel = "stylesheet";
    font.href = "https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@500;700&display=swap";
    document.head.appendChild(font);

    const style = document.createElement("style");
    style.textContent = `
      #ca-nav, #ca-nav * { font-family: 'IBM Plex Mono', monospace !important; }
      @keyframes ca-pop {
        0%   { transform: scale(0.75); opacity: 0.3; }
        60%  { transform: scale(1.15); opacity: 1; }
        100% { transform: scale(1);   opacity: 1; }
      }
      .ca-pop { animation: ca-pop 0.2s cubic-bezier(.36,.07,.19,.97) both; }
      @keyframes ca-flash {
        0%,100% { opacity: 1; }
        40%     { opacity: 0.3; }
      }
      .ca-flash { animation: ca-flash 0.15s ease; }
    `;
    document.head.appendChild(style);

    const nav = document.createElement("div");
    nav.id = "ca-nav";
    nav.className = [
      "fixed", "z-[2147483647]",
      "inline-flex", "items-stretch",
      "rounded-2xl", "overflow-hidden",
      "cursor-grab", "select-none", "touch-none",
      "shadow-[0_8px_28px_rgba(0,0,0,0.7)]",
      "border", "border-white/10",
    ].join(" ");
    nav.style.cssText = "position:fixed;visibility:hidden;left:0;top:0;";

    /* LEFT — black: Q number + answer letter */
    const info = document.createElement("div");
    info.className = [
      "flex", "flex-col", "items-center", "justify-center",
      "px-4", "py-2", "gap-[1px]",
      "bg-black", "min-w-[52px]",
    ].join(" ");

    const qEl = document.createElement("span");
    qEl.id = "ca-q";
    qEl.className = "text-[9px] font-bold tracking-[0.18em] text-white/50 leading-none uppercase";
    qEl.textContent = "Q—";

    const aEl = document.createElement("span");
    aEl.id = "ca-a";
    aEl.className = "text-[26px] font-bold leading-none text-white tracking-tight";
    aEl.textContent = "?";

    info.appendChild(qEl);
    info.appendChild(aEl);

    /* RIGHT — white tap */
    const tap = document.createElement("div");
    tap.id = "ca-tap";
    tap.className = [
      "flex", "flex-col", "items-center", "justify-center",
      "px-4", "py-3", "gap-[3px]",
      "cursor-pointer", "bg-white",
      "border-l", "border-black/10",
      "active:brightness-90",
      "transition-all", "duration-75",
    ].join(" ");
    tap.innerHTML = `
      <span class="text-[11px] font-bold tracking-[0.2em] text-black/75 uppercase leading-none">TAP</span>
      <span class="text-[7px] font-medium tracking-[0.08em] text-black/35 leading-none">·next  ··prev</span>
    `;

    nav.appendChild(info);
    nav.appendChild(tap);
    document.body.appendChild(nav);

    requestAnimationFrame(() => {
      nav.style.left       = (innerWidth  - nav.offsetWidth  - 14) + "px";
      nav.style.top        = (innerHeight - nav.offsetHeight - 20) + "px";
      nav.style.visibility = "visible";
    });

    makeDraggable(nav, "#ca-tap");

    let tapTimer = null;
    tap.addEventListener("click", () => {
      if (!answers.length) return;

      if (tapTimer) {
        clearTimeout(tapTimer);
        tapTimer = null;
        current = (current - 1 + answers.length) % answers.length;
        renderNav();
      } else {
        tapTimer = setTimeout(() => {
          tapTimer = null;

          tap.classList.remove("ca-flash");
          void tap.offsetWidth;
          tap.classList.add("ca-flash");

          clickAnswer(answers[current].a);
          current = Math.min(current + 1, answers.length - 1);
          renderNav(true);
        }, 270);
      }
    });
  }

  function renderNav(animate = false) {
    const qEl = document.getElementById("ca-q");
    const aEl = document.getElementById("ca-a");
    if (!qEl || !aEl) return;

    if (!answers.length) {
      qEl.textContent = "Q—";
      aEl.textContent = "?";
      return;
    }

    const item = answers[current];
    qEl.textContent = "Q" + item.n;
    aEl.textContent = item.a;

    if (animate) {
      aEl.classList.remove("ca-pop");
      void aEl.offsetWidth;
      aEl.classList.add("ca-pop");
    }
  }

  function boot() { buildUI(); renderNav(); }
  document.body ? boot() : window.addEventListener("DOMContentLoaded", boot);

})();
