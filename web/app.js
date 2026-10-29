// Text from the API is always inserted with textContent (never innerHTML), so no response can inject markup.
(function () {
  "use strict";
  var COLORS = { official: "green", low_risk: "green", suspicious: "yellow", high_risk: "red", dangerous: "red", no_links: "green" };
  var LABELS = { official: "Official site", low_risk: "Low risk", suspicious: "Suspicious", high_risk: "High risk",
                 dangerous: "Known dangerous", no_links: "No links found" };
  var results = document.getElementById("results");
  var language = document.getElementById("language");

  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined) e.textContent = text;
    return e;
  }

  function card(r) {
    var c = el("div", "card " + (COLORS[r.verdict] || "yellow"));
    c.appendChild(el("span", "badge", LABELS[r.verdict] || r.verdict));
    c.appendChild(el("div", "domain", r.domain));
    c.appendChild(el("div", "", "Risk score " + r.score + " / 100"));
    if (r.note) c.appendChild(el("div", "note", r.note));
    if (r.explanation) {
      c.appendChild(el("p", "", r.explanation.summary));
      var ul = el("ul");
      (r.explanation.reasons || []).forEach(function (x) { ul.appendChild(el("li", "", x)); });
      c.appendChild(ul);
      c.appendChild(el("p", "", r.explanation.advice));
    }
    c.appendChild(el("div", "meta", r.basis === "name_only_analysis"
      ? "Based on the name only (not yet seen in our certificate feed)."
      : "Seen in our certificate feed."));
    return c;
  }

  function show(nodes) { results.replaceChildren.apply(results, nodes); }
  function fail(msg) { show([el("div", "error", msg)]); }

  function post(path, body) {
    body.language = language.value;
    return fetch(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) })
      .then(function (res) {
        return res.json().then(function (data) {
          if (!res.ok) {
            throw new Error(res.status === 429 ? "Too many requests. Please wait a minute."
              : (typeof data.detail === "string" ? data.detail : "That input was not accepted."));
          }
          return data;
        });
      });
  }

  document.getElementById("form-check").addEventListener("submit", function (ev) {
    ev.preventDefault();
    post("/check", { input: document.getElementById("input").value })
      .then(function (r) { show([card(r)]); }).catch(function (e) { fail(e.message); });
  });

  document.getElementById("form-scan").addEventListener("submit", function (ev) {
    ev.preventDefault();
    post("/scan-message", { text: document.getElementById("text").value }).then(function (r) {
      var head = el("div", "card " + (COLORS[r.worst_verdict] || "yellow"));
      head.appendChild(el("span", "badge", LABELS[r.worst_verdict] || r.worst_verdict));
      head.appendChild(el("p", "", r.links_found + " link(s) found in the message."));
      if (r.message_analysis.tactics.length) {
        head.appendChild(el("p", "", "Pressure tactics noticed: " + r.message_analysis.tactics.join(", ") + "."));
      }
      show([head].concat(r.links.map(card)));
    }).catch(function (e) { fail(e.message); });
  });

  function tab(which) {
    ["check", "scan"].forEach(function (n) {
      document.getElementById("panel-" + n).hidden = n !== which;
      document.getElementById("tab-" + n).setAttribute("aria-selected", String(n === which));
    });
    results.replaceChildren();
  }
  document.getElementById("tab-check").addEventListener("click", function () { tab("check"); });
  document.getElementById("tab-scan").addEventListener("click", function () { tab("scan"); });

  fetch("/config").then(function (r) { return r.json(); }).then(function (cfg) {
    cfg.languages.forEach(function (l) { var o = el("option", "", l); o.value = l; language.appendChild(o); });
    var d = document.getElementById("dispute");
    if (cfg.dispute_url) {
      var a = el("a", "", "Dispute a result");
      a.href = cfg.dispute_url; a.rel = "noopener noreferrer";
      d.appendChild(a);
    }
  }).catch(function () { language.appendChild(el("option", "", "English")); });
})();
