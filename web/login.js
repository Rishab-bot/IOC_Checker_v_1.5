/* Sign-in page for IOC Checker. Sends the login to the server, then reloads so the server can show the app. */
"use strict";

const form = document.getElementById("login-form");
const errorBox = document.getElementById("login-error");
const button = document.getElementById("login-submit");

/** Show a message under the fields, or hide the box when the message is empty. */
function showError(message) {
  errorBox.textContent = message;
  errorBox.hidden = !message;
}

/** Send the username and password; on success reload the page, which the server now answers with the app. */
async function signIn(event) {
  event.preventDefault();
  showError("");
  button.disabled = true;
  button.setAttribute("aria-busy", "true");
  try {
    const response = await fetch("/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: form.elements.username.value.trim(),
        password: form.elements.password.value,
      }),
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || `HTTP ${response.status}`);
    location.reload();
  } catch (err) {
    form.elements.password.value = "";
    showError(err instanceof TypeError ? "Could not reach the server. Try again." : `Could not sign in: ${err.message}.`);
    button.disabled = false;
    button.removeAttribute("aria-busy");
    form.elements.password.focus();
  }
}

form.addEventListener("submit", signIn);
