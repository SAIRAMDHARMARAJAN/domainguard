(function () {
  "use strict";
  var threats = document.getElementById("threats");
  var precautions = document.getElementById("precautions");
  var articles = document.getElementById("articles");
  function text(tag, value) {
    var node = document.createElement(tag);
    node.textContent = value;
    return node;
  }
  fetch("/safety/feed").then(function (r) {
    if (!r.ok) throw new Error("Safety feed is temporarily unavailable.");
    return r.json();
  }).then(function (data) {
    threats.replaceChildren();
    if (!data.threats.length) threats.appendChild(text("p", "No recent high-risk watched-brand domains."));
    data.threats.forEach(function (item) {
      var row = document.createElement("div");
      row.className = "card";
      row.appendChild(text("div", item.domain));
      row.appendChild(text("div", item.verdict.replace("_", " ") + " · score " + item.score + "/100"));
      threats.appendChild(row);
    });
    precautions.replaceChildren.apply(precautions, data.precautions.map(function (item) { return text("li", item); }));
    articles.replaceChildren();
    if (!data.articles.length) articles.appendChild(text("p", "Trusted news is temporarily unavailable."));
    data.articles.forEach(function (item) {
      var p = document.createElement("p");
      var a = document.createElement("a");
      a.href = item.url; a.target = "_blank"; a.rel = "noopener noreferrer"; a.textContent = item.title;
      p.appendChild(a); p.appendChild(text("div", item.source));
      articles.appendChild(p);
    });
  }).catch(function (error) {
    threats.textContent = error.message;
    precautions.textContent = "Review the checklist: avoid unexpected links, verify domains, use MFA, and never share one-time passwords.";
    articles.textContent = "Trusted news is temporarily unavailable.";
  });
}());
