const authSection = document.getElementById("auth");
const paintSection = document.getElementById("paint");
const statusEl = document.getElementById("status");

const loginForm = document.getElementById("login-form");
const signupForm = document.getElementById("signup-form");

const canvas = document.getElementById("canvas");
const ctx = canvas.getContext("2d");
const colorInput = document.getElementById("color");
const sizeInput = document.getElementById("size");
const clearBtn = document.getElementById("clear");
const savePngBtn = document.getElementById("save-png");
const saveCloudBtn = document.getElementById("save-cloud");
const signOutBtn = document.getElementById("signout");

let drawing = false;
let lastX = 0;
let lastY = 0;

ctx.lineCap = "round";
ctx.lineJoin = "round";
ctx.strokeStyle = colorInput.value;
ctx.lineWidth = Number(sizeInput.value);

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

function showAuth() {
  authSection.classList.remove("hidden");
  paintSection.classList.add("hidden");
}

function showPaint() {
  authSection.classList.add("hidden");
  paintSection.classList.remove("hidden");
}

function pointFromEvent(event) {
  const rect = canvas.getBoundingClientRect();
  const scaleX = canvas.width / rect.width;
  const scaleY = canvas.height / rect.height;

  if (event.touches && event.touches[0]) {
    return {
      x: (event.touches[0].clientX - rect.left) * scaleX,
      y: (event.touches[0].clientY - rect.top) * scaleY,
    };
  }

  return {
    x: (event.clientX - rect.left) * scaleX,
    y: (event.clientY - rect.top) * scaleY,
  };
}

function start(event) {
  drawing = true;
  const p = pointFromEvent(event);
  lastX = p.x;
  lastY = p.y;
}

function draw(event) {
  if (!drawing) return;
  event.preventDefault();
  const p = pointFromEvent(event);
  ctx.beginPath();
  ctx.moveTo(lastX, lastY);
  ctx.lineTo(p.x, p.y);
  ctx.stroke();
  lastX = p.x;
  lastY = p.y;
}

function end() {
  drawing = false;
}

async function loadPainting() {
  const result = await api("/api/painting");
  ctx.clearRect(0, 0, canvas.width, canvas.height);

  if (!result.imageData) {
    return;
  }

  await new Promise((resolve, reject) => {
    const image = new Image();
    image.onload = () => {
      ctx.drawImage(image, 0, 0, canvas.width, canvas.height);
      resolve();
    };
    image.onerror = reject;
    image.src = result.imageData;
  });
}

async function handleAuthSuccess(email) {
  showPaint();
  await loadPainting();
  setStatus(`Signed in as ${email}`);
}

canvas.addEventListener("mousedown", start);
canvas.addEventListener("mousemove", draw);
window.addEventListener("mouseup", end);
canvas.addEventListener("mouseleave", end);
canvas.addEventListener("touchstart", start, { passive: false });
canvas.addEventListener("touchmove", draw, { passive: false });
window.addEventListener("touchend", end);
window.addEventListener("touchcancel", end);

colorInput.addEventListener("input", () => {
  ctx.strokeStyle = colorInput.value;
});

sizeInput.addEventListener("input", () => {
  ctx.lineWidth = Number(sizeInput.value);
});

clearBtn.addEventListener("click", () => {
  ctx.clearRect(0, 0, canvas.width, canvas.height);
  setStatus("Canvas cleared locally. Click Save Painting to keep it.");
});

savePngBtn.addEventListener("click", () => {
  const a = document.createElement("a");
  a.download = "painting.png";
  a.href = canvas.toDataURL("image/png");
  a.click();
});

saveCloudBtn.addEventListener("click", async () => {
  try {
    await api("/api/painting", {
      method: "POST",
      body: { imageData: canvas.toDataURL("image/png") },
    });
    setStatus("Painting saved.");
  } catch (error) {
    setStatus(error.message, true);
  }
});

signOutBtn.addEventListener("click", async () => {
  try {
    await api("/api/logout", { method: "POST" });
    showAuth();
    setStatus("Signed out.");
  } catch (error) {
    setStatus(error.message, true);
  }
});

signupForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const email = document.getElementById("signup-email").value.trim();
  const password = document.getElementById("signup-password").value;

  try {
    await api("/api/signup", { method: "POST", body: { email, password } });
    await handleAuthSuccess(email);
    signupForm.reset();
  } catch (error) {
    setStatus(error.message, true);
  }
});

loginForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const email = document.getElementById("login-email").value.trim();
  const password = document.getElementById("login-password").value;

  try {
    await api("/api/login", { method: "POST", body: { email, password } });
    await handleAuthSuccess(email);
    loginForm.reset();
  } catch (error) {
    setStatus(error.message, true);
  }
});

(async function init() {
  try {
    const me = await api("/api/me");
    await handleAuthSuccess(me.email);
  } catch {
    showAuth();
    setStatus("Sign in or create an account.");
  }
})();
