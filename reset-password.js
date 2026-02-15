const statusEl = document.getElementById("status");
const form = document.getElementById("reset-form");
const newPasswordInput = document.getElementById("new-password");
const confirmPasswordInput = document.getElementById("confirm-password");
const token = new URLSearchParams(window.location.search).get("token") || "";

function setStatus(message, isError = false) {
  statusEl.textContent = message;
  statusEl.style.color = isError ? "#b00020" : "#5f6870";
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    method: options.method || "GET",
    headers: {
      "Content-Type": "application/json",
      ...(options.headers || {}),
    },
    body: options.body ? JSON.stringify(options.body) : undefined,
  });

  const contentType = response.headers.get("content-type") || "";
  const data = contentType.includes("application/json")
    ? await response.json()
    : null;

  if (!response.ok) {
    throw new Error(data?.error || "Request failed");
  }

  return data;
}

if (!token) {
  form.classList.add("hidden");
  setStatus("Invalid or missing reset token.", true);
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const password = newPasswordInput.value;
  const confirmPassword = confirmPasswordInput.value;

  if (password !== confirmPassword) {
    setStatus("Passwords do not match.", true);
    return;
  }

  try {
    await api("/api/reset-password", {
      method: "POST",
      body: { token, password },
    });

    setStatus("Password reset successful. You can now sign in.");
    form.reset();
    setTimeout(() => {
      window.location.href = "/";
    }, 1200);
  } catch (error) {
    setStatus(error.message, true);
  }
});
