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

  function loadAwareness() {
    fetch("/safety/feed").then(function (res) {
      if (!res.ok) throw new Error("Live updates are temporarily unavailable.");
      return res.json();
    }).then(function (data) {
      var threatBox = document.getElementById("threats");
      threatBox.replaceChildren();
      if (!data.threats.length) threatBox.appendChild(el("p", "meta", "No recent high-risk watched-brand domains."));
      data.threats.forEach(function (item) {
        var row = el("div", "threat-row");
        row.appendChild(el("div", "domain", item.domain));
        row.appendChild(el("div", "meta", item.verdict.replace("_", " ") + " · score " + item.score + "/100"));
        threatBox.appendChild(row);
      });
      var checklist = document.getElementById("precautions");
      checklist.replaceChildren.apply(checklist, data.precautions.map(function (item) { return el("li", "", item); }));
      var articleBox = document.getElementById("articles");
      articleBox.replaceChildren();
      if (!data.articles.length) articleBox.appendChild(el("p", "meta", "No new advisories are available right now."));
      data.articles.forEach(function (item) {
        var a = document.createElement("a");
        a.className = "article-link"; a.href = item.url; a.target = "_blank"; a.rel = "noopener noreferrer";
        a.appendChild(el("strong", "", item.title)); a.appendChild(el("span", "meta", item.source + (item.published_at ? " · " + item.published_at : "")));
        articleBox.appendChild(a);
      });
      document.getElementById("news-updated").textContent = "Updated " + new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
    }).catch(function () {
      document.getElementById("threats").replaceChildren(el("p", "meta", "Live threat updates are temporarily unavailable. The checker and safety guidance are still available."));
      document.getElementById("articles").replaceChildren(el("p", "meta", "Trusted advisories are temporarily unavailable. Please check back soon."));
      document.getElementById("news-updated").textContent = "Refresh unavailable";
    });
  }

  function post(path, body) {
    body.language = language.value;
    return fetch(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) })
      .then(function (res) {
        return res.text().then(function (text) {
          var data;
          try {
            data = text ? JSON.parse(text) : {};
          } catch (_) {
            data = {};
          }
          if (!res.ok) {
            throw new Error(res.status === 429 ? "Too many requests. Please wait a minute."
              : (typeof data.detail === "string" ? data.detail
                : res.status >= 500 ? "The service is temporarily unavailable. Please try again."
                : "That input was not accepted."));
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
  loadAwareness();
  window.setInterval(loadAwareness, 300000);

  fetch("/config").then(function (r) {
    return r.text().then(function (text) {
      if (!r.ok) throw new Error("Configuration is temporarily unavailable.");
      try { return text ? JSON.parse(text) : {}; } catch (_) { throw new Error("Configuration is invalid."); }
    });
  }).then(function (cfg) {
    cfg.languages.forEach(function (l) { var o = el("option", "", l); o.value = l; language.appendChild(o); });
    var d = document.getElementById("dispute");
    if (cfg.dispute_url) {
      var a = el("a", "", "Dispute a result");
      a.href = cfg.dispute_url; a.rel = "noopener noreferrer";
      d.appendChild(a);
    }
    var params = new URLSearchParams(window.location.search);
    var checkParam = params.get("check") || params.get("domain") || params.get("input");
    if (checkParam) {
      document.getElementById("input").value = checkParam;
      post("/check", { input: checkParam })
        .then(function (r) { show([card(r)]); })
        .catch(function (e) { fail(e.message); });
    }
  }).catch(function () { language.appendChild(el("option", "", "English")); });
})();
