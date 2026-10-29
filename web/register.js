// Registration form. Errors and messages are inserted as text only.
(function () {
  "use strict";
  var results = document.getElementById("results");
  function msg(text, cls) {
    var d = document.createElement("div");
    d.className = cls || "card";
    d.textContent = text;
    results.replaceChildren(d);
  }
  document.getElementById("form-register").addEventListener("submit", function (ev) {
    ev.preventDefault();
    var body = {
      company_name: document.getElementById("company_name").value.trim(),
      email: document.getElementById("email").value.trim(),
      contact_person: document.getElementById("contact_person").value.trim() || null,
      domains: document.getElementById("domains").value.split(/\s+/).filter(Boolean),
      aliases: document.getElementById("aliases").value.split(",").map(function (s) { return s.trim(); }).filter(Boolean)
    };
    fetch("/register", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) })
      .then(function (res) {
        return res.json().then(function (data) {
          if (!res.ok) throw new Error(typeof data.detail === "string" ? data.detail : "Registration was not accepted.");
          return data;
        });
      })
      .then(function (data) { msg(data.message, "card green"); })
      .catch(function (e) { msg(e.message, "error"); });
  });
})();
