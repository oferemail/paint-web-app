const authSection = document.getElementById("auth");
const paintSection = document.getElementById("paint");
const statusEl = document.getElementById("status");

const authForm = document.getElementById("auth-form");
const authTitle = document.getElementById("auth-title");
const authSubtitle = document.getElementById("auth-subtitle");
const authSubmit = document.getElementById("auth-submit");
const authToggle = document.getElementById("auth-toggle");
const authEmail = document.getElementById("auth-email");
const authPassword = document.getElementById("auth-password");
const forgotPasswordBtn = document.getElementById("forgot-password");
const googleLoginBtn = document.getElementById("google-login");

const canvas = document.getElementById("canvas");
const ctx = canvas.getContext("2d");
const colorInput = document.getElementById("color");
const sizeInput = document.getElementById("size");
const clearBtn = document.getElementById("clear");
const undoBtn = document.getElementById("undo");
const magicBtn = document.getElementById("magic");
const savePngBtn = document.getElementById("save-png");
const saveCloudBtn = document.getElementById("save-cloud");
const signOutBtn = document.getElementById("signout");
const magicModal = document.getElementById("magic-modal");
const magicForm = document.getElementById("magic-form");
const magicCancelBtn = document.getElementById("magic-cancel");
const magicRunBtn = document.getElementById("magic-run");
const magicDownloadBtn = document.getElementById("magic-download");
const magicErrorEl = document.getElementById("magic-error");
const magicProgressEl = document.getElementById("magic-progress");
const magicPreviewWrap = document.getElementById("magic-preview-wrap");
const magicPreview = document.getElementById("magic-preview");

let drawing = false;
let lastX = 0;
let lastY = 0;
let authMode = "signup";
let strokeMoved = false;
let history = [];
let historyIndex = -1;
const HISTORY_LIMIT = 30;
let lastMagicImageData = "";

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

function setAuthMode(mode) {
  authMode = mode;

  if (mode === "signup") {
    authTitle.textContent = "Create Account";
    authSubtitle.textContent = "Start drawing and save your progress.";
    authSubmit.textContent = "Sign Up";
    authToggle.textContent = "Already have an account? Sign in";
    authPassword.autocomplete = "new-password";
    forgotPasswordBtn.classList.add("hidden");
  } else {
    authTitle.textContent = "Sign In";
    authSubtitle.textContent = "Welcome back. Continue your latest painting.";
    authSubmit.textContent = "Sign In";
    authToggle.textContent = "Need an account? Sign up";
    authPassword.autocomplete = "current-password";
    forgotPasswordBtn.classList.remove("hidden");
  }
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
  strokeMoved = false;
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
  strokeMoved = true;
  lastX = p.x;
  lastY = p.y;
}

function end() {
  if (drawing && strokeMoved) {
    pushHistoryState();
  }
  drawing = false;
}

function currentCanvasData() {
  return canvas.toDataURL("image/png");
}

function buildMagicInputImageData() {
  const magicCanvas = document.createElement("canvas");
  // Keep input compact and square for reliable API requests.
  magicCanvas.width = 512;
  magicCanvas.height = 512;
  const magicCtx = magicCanvas.getContext("2d");

  magicCtx.fillStyle = "#ffffff";
  magicCtx.fillRect(0, 0, magicCanvas.width, magicCanvas.height);

  const scale = Math.min(magicCanvas.width / canvas.width, magicCanvas.height / canvas.height);
  const drawWidth = canvas.width * scale;
  const drawHeight = canvas.height * scale;
  const offsetX = (magicCanvas.width - drawWidth) / 2;
  const offsetY = (magicCanvas.height - drawHeight) / 2;

  magicCtx.drawImage(canvas, offsetX, offsetY, drawWidth, drawHeight);
  return magicCanvas.toDataURL("image/png");
}

function buildMagicMaskData() {
  const maskCanvas = document.createElement("canvas");
  maskCanvas.width = 512;
  maskCanvas.height = 512;
  const maskCtx = maskCanvas.getContext("2d");

  // Fully transparent mask means the whole image can be regenerated.
  maskCtx.clearRect(0, 0, maskCanvas.width, maskCanvas.height);
  return maskCanvas.toDataURL("image/png");
}

function resetHistoryFromCanvas() {
  history = [currentCanvasData()];
  historyIndex = 0;
  refreshUndoButton();
}

function pushHistoryState() {
  const snapshot = currentCanvasData();
  if (historyIndex >= 0 && history[historyIndex] === snapshot) {
    return;
  }

  history = history.slice(0, historyIndex + 1);
  history.push(snapshot);
  if (history.length > HISTORY_LIMIT) {
    history.shift();
  }
  historyIndex = history.length - 1;
  refreshUndoButton();
}

function refreshUndoButton() {
  undoBtn.disabled = historyIndex <= 0;
}

async function drawSnapshot(dataUrl) {
  await new Promise((resolve, reject) => {
    const image = new Image();
    image.onload = () => {
      // Preserve image aspect ratio to avoid stretch artifacts.
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      ctx.fillStyle = "#ffffff";
      ctx.fillRect(0, 0, canvas.width, canvas.height);

      const scale = Math.max(canvas.width / image.width, canvas.height / image.height);
      const drawWidth = image.width * scale;
      const drawHeight = image.height * scale;
      const offsetX = (canvas.width - drawWidth) / 2;
      const offsetY = (canvas.height - drawHeight) / 2;

      ctx.drawImage(image, offsetX, offsetY, drawWidth, drawHeight);
      resolve();
    };
    image.onerror = () => reject(new Error("Unable to render generated image in browser."));
    image.src = dataUrl;
  });
}

async function loadPainting() {
  const result = await api("/api/painting");
  ctx.clearRect(0, 0, canvas.width, canvas.height);

  if (!result.imageData) {
    resetHistoryFromCanvas();
    return;
  }

  await drawSnapshot(result.imageData);
  resetHistoryFromCanvas();
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
  pushHistoryState();
  setStatus("Canvas cleared locally. Click Save Painting to keep it.");
});

undoBtn.addEventListener("click", async () => {
  if (historyIndex <= 0) {
    return;
  }

  historyIndex -= 1;
  refreshUndoButton();
  try {
    await drawSnapshot(history[historyIndex]);
    setStatus("Undid last change.");
  } catch {
    setStatus("Unable to restore previous state.", true);
  }
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

function openMagicModal() {
  magicCancelBtn.textContent = "Cancel";
  magicDownloadBtn.classList.add("hidden");
  magicErrorEl.textContent = "";
  magicErrorEl.classList.add("hidden");
  magicProgressEl.textContent = "";
  magicProgressEl.classList.add("hidden");
  magicPreview.removeAttribute("src");
  magicPreviewWrap.classList.add("hidden");
  magicModal.classList.remove("hidden");
}

function closeMagicModal() {
  magicModal.classList.add("hidden");
}

magicBtn.addEventListener("click", () => {
  openMagicModal();
});

magicCancelBtn.addEventListener("click", () => {
  closeMagicModal();
});

magicDownloadBtn.addEventListener("click", () => {
  if (!lastMagicImageData) {
    return;
  }

  const a = document.createElement("a");
  a.download = "magic-result.png";
  a.href = lastMagicImageData;
  a.click();
});

magicModal.addEventListener("click", (event) => {
  if (event.target === magicModal) {
    closeMagicModal();
  }
});

magicForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const style = new FormData(magicForm).get("magic-style");
  if (!style) {
    setStatus("Choose a style first.", true);
    return;
  }

  magicRunBtn.disabled = true;
  magicCancelBtn.disabled = true;
  magicErrorEl.textContent = "";
  magicErrorEl.classList.add("hidden");
  magicProgressEl.textContent = "Sending sketch to AI...";
  magicProgressEl.classList.remove("hidden");
  setStatus("Generating magic image...");

  try {
    const result = await api("/api/magic-transform", {
      method: "POST",
      body: {
        imageData: buildMagicInputImageData(),
        maskData: buildMagicMaskData(),
        style,
      },
    });
    if (!result?.imageData || typeof result.imageData !== "string") {
      throw new Error("Magic API returned an invalid image payload.");
    }

    lastMagicImageData = result.imageData;
    magicPreview.src = result.imageData;
    magicPreviewWrap.classList.remove("hidden");
    magicDownloadBtn.classList.remove("hidden");
    magicProgressEl.textContent = "Image generated. Applying to canvas...";

    await drawSnapshot(result.imageData);
    pushHistoryState();
    magicProgressEl.textContent = "Done. Applied to canvas.";
    magicCancelBtn.textContent = "Close";
    const providerNote = result.provider ? ` via ${result.provider}` : "";
    setStatus(`Magic transform complete${providerNote}. Save Painting to store it.`);
  } catch (error) {
    magicErrorEl.textContent = error.message || "Magic generation failed.";
    magicErrorEl.classList.remove("hidden");
    setStatus(error.message, true);
  } finally {
    magicRunBtn.disabled = false;
    magicCancelBtn.disabled = false;
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

authToggle.addEventListener("click", () => {
  setAuthMode(authMode === "signup" ? "login" : "signup");
  setStatus("");
});

googleLoginBtn.addEventListener("click", () => {
  window.location.href = "/api/oauth/google/start";
});

forgotPasswordBtn.addEventListener("click", async () => {
  const email = authEmail.value.trim();
  if (!email) {
    setStatus("Enter your email first, then click Forgot my password.", true);
    return;
  }

  try {
    await api("/api/forgot-password", { method: "POST", body: { email } });
    setStatus("If that email exists, we sent a reset link. Check your inbox and spam folder, then follow the link to set a new password.");
  } catch (error) {
    setStatus(error.message, true);
  }
});

authForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const email = authEmail.value.trim();
  const password = authPassword.value;
  const genericAuthError = "Unable to authenticate with those credentials.";

  if (!email || !password) return;

  if (authMode === "signup") {
    try {
      await api("/api/signup", { method: "POST", body: { email, password } });
      await handleAuthSuccess(email);
      authForm.reset();
      return;
    } catch (error) {
      if (error.message.includes("Too many attempts")) {
        setStatus(error.message, true);
        return;
      }
      setStatus(genericAuthError, true);
      return;
    }
  }

  try {
    await api("/api/login", { method: "POST", body: { email, password } });
    await handleAuthSuccess(email);
    authForm.reset();
  } catch (error) {
    if (error.message.includes("Too many attempts")) {
      setStatus(error.message, true);
      return;
    }
    setStatus(genericAuthError, true);
  }
});

(async function init() {
  const oauthError = new URLSearchParams(window.location.search).get("oauth_error");
  if (oauthError) {
    setStatus("Social sign-in was not completed. Please try again.", true);
    window.history.replaceState({}, "", "/");
  }

  try {
    const me = await api("/api/me");
    await handleAuthSuccess(me.email);
  } catch {
    showAuth();
    setStatus("Sign in or create an account.");
    setAuthMode("signup");
    resetHistoryFromCanvas();
  }
})();
