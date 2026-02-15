const canvas = document.getElementById("canvas");
const ctx = canvas.getContext("2d");
const colorInput = document.getElementById("color");
const sizeInput = document.getElementById("size");
const clearBtn = document.getElementById("clear");
const saveBtn = document.getElementById("save");

let drawing = false;
let lastX = 0;
let lastY = 0;

ctx.lineCap = "round";
ctx.lineJoin = "round";
ctx.strokeStyle = colorInput.value;
ctx.lineWidth = Number(sizeInput.value);

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
});

saveBtn.addEventListener("click", () => {
  const a = document.createElement("a");
  a.download = "painting.png";
  a.href = canvas.toDataURL("image/png");
  a.click();
});
