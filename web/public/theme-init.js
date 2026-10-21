// Apply the stored theme before first paint to avoid a flash. Kept outside
// index.html because the server's CSP allows no inline scripts.
try {
  var t = localStorage.getItem("fireid-theme") || "system"
  if (t === "system")
    t = matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light"
  document.documentElement.classList.add(t)
} catch (e) {}
