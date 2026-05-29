document.addEventListener("DOMContentLoaded", () => {
  const searchInput = document.getElementById("findingSearch");
  const severityFilter = document.getElementById("severityFilter");
  const liveText = document.getElementById("liveEvaluationText");

  const messages = [
    "Checking dependency vulnerabilities...",
    "Reviewing package trust signals...",
    "Analyzing CI/CD workflow risks...",
    "Ranking findings by exploit likelihood...",
    "Preparing fix recommendations..."
  ];

  let index = 0;

  setInterval(() => {
    if (!liveText) return;
    liveText.textContent = messages[index];
    index = (index + 1) % messages.length;
  }, 2200);

  function filterText() {
    const searchValue = searchInput?.value.toLowerCase() || "";
    const severityValue = severityFilter?.value || "all";

    const pageItems = document.querySelectorAll(".finding-card, .result-card, .package-card, tr");

    pageItems.forEach((item) => {
      const text = item.innerText.toLowerCase();

      const matchesSearch = text.includes(searchValue);
      const matchesSeverity =
        severityValue === "all" || text.includes(severityValue);

      if (matchesSearch && matchesSeverity) {
        item.classList.remove("hidden");
      } else {
        item.classList.add("hidden");
      }
    });
  }

  searchInput?.addEventListener("input", filterText);
  severityFilter?.addEventListener("change", filterText);
});
