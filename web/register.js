// Registration form. Errors and messages are inserted as text only.
(function () {
  "use strict";
  var results = document.getElementById("results");
  var otpForm = document.getElementById("form-otp");
  var registeredEmail = "";
  var registrationCaptcha = "";
  var otpCaptcha = "";
  window.onRegistrationCaptcha = function (token) { registrationCaptcha = token; };
  window.onOtpCaptcha = function (token) { otpCaptcha = token; };
  function captchaToken(id) {
    return id === "turnstile-widget" ? registrationCaptcha : otpCaptcha;
  }
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
      aliases: document.getElementById("aliases").value.split(",").map(function (s) { return s.trim(); }).filter(Boolean),
      captcha_token: captchaToken("turnstile-widget")
    };
    fetch("/register", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) })
      .then(function (res) {
        return res.text().then(function (text) {
          var data;
          try {
            data = text ? JSON.parse(text) : {};
          } catch (_) {
            data = {};
          }
          if (!res.ok) {
            throw new Error(typeof data.detail === "string" ? data.detail
              : res.status >= 500 ? "The service is temporarily unavailable. Please try again."
              : "Registration was not accepted.");
          }
          return data;
        });
      })
      .then(function (data) {
        registeredEmail = body.email;
        var sent = data.verification_email_sent !== false;
        msg(data.message, sent ? "card green" : "error");
        otpForm.hidden = !sent;
        if (sent) document.getElementById("otp").focus();
      })
      .catch(function (e) { msg(e.message, "error"); });
  });
  otpForm.addEventListener("submit", function (ev) {
    ev.preventDefault();
    fetch("/verify-otp", { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: registeredEmail, otp: document.getElementById("otp").value.trim(),
        captcha_token: captchaToken("otp-turnstile-widget") }) })
      .then(function (res) {
        return res.json().then(function (data) {
          if (!res.ok) throw new Error(typeof data.detail === "string" ? data.detail : "Verification failed.");
          return data;
        });
      })
      .then(function (data) {
        var key = document.getElementById("key-result");
        key.className = "card green";
        key.textContent = data.message + " API key: " + data.api_key;
        otpForm.hidden = true;
      })
      .catch(function (e) {
        var key = document.getElementById("key-result");
        key.className = "error";
        key.textContent = e.message;
      });
  });
})();
