/* Standalone report controls: no network, no persistence, no external scripts. */
(() => {
  const sections = [...document.querySelectorAll("details[data-print-expand]")];
  document.querySelector("#expand-all").addEventListener("click", () => {
    sections.forEach((section) => {
      section.open = true;
    });
  });
  document.querySelector("#collapse-all").addEventListener("click", () => {
    document.querySelectorAll("details").forEach((section) => {
      section.open = false;
    });
  });
  document
    .querySelector("#print-report")
    .addEventListener("click", () => window.print());
  let previous = null;
  window.addEventListener("beforeprint", () => {
    if (previous) return;
    previous = sections.map((section) => section.open);
    sections.forEach((section) => {
      section.open = true;
    });
  });
  window.addEventListener("afterprint", () => {
    if (!previous) return;
    sections.forEach((section, index) => {
      section.open = previous[index];
    });
    previous = null;
  });
  function revealAnchor() {
    const target = document.getElementById(location.hash.slice(1));
    if (!target || !target.classList.contains("finding-card")) return;
    target.querySelector("details").open = true;
  }
  window.addEventListener("hashchange", revealAnchor);
  revealAnchor();
})();
