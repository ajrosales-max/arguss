document.addEventListener("DOMContentLoaded", () => {
  const searchInput = document.getElementById("findingSearch");
  const severityFilter = document.getElementById("severityFilter");
  const riskCards = document.querySelectorAll(".risk-card[data-filter]");
  let activeRiskFilter = "all";

  function findingItems() {
    return document.querySelectorAll(".finding-entry");
  }

  function applyFilters() {
    const searchValue = searchInput?.value.toLowerCase() || "";
    const severityValue = severityFilter?.value || "all";

    findingItems().forEach((item) => {
      const text = item.innerText.toLowerCase();
      const severity = item.dataset.severity || "";
      const isKev = item.dataset.kev === "true";
      const tier = item.dataset.tier || "";
      const epss = Number.parseFloat(item.dataset.epss || "0");

      const matchesSearch = searchValue === "" || text.includes(searchValue);
      const matchesSeverity = severityValue === "all" || severity === severityValue;

      let matchesRisk = true;
      if (activeRiskFilter === "kev") {
        matchesRisk = isKev;
      } else if (activeRiskFilter === "auto") {
        matchesRisk = tier === "auto_merge";
      } else if (activeRiskFilter === "high-epss") {
        matchesRisk = epss > 0.1;
      }

      item.classList.toggle("hidden", !(matchesSearch && matchesSeverity && matchesRisk));
    });
  }

  riskCards.forEach((card) => {
    card.addEventListener("click", () => {
      activeRiskFilter = card.dataset.filter || "all";
      riskCards.forEach((other) => {
        other.classList.toggle("active", other === card);
      });
      applyFilters();
    });
  });

  if (riskCards.length > 0) {
    riskCards[0].classList.add("active");
  }

  searchInput?.addEventListener("input", applyFilters);
  severityFilter?.addEventListener("change", applyFilters);

  const shareBtn = document.getElementById("share-button");
  if (shareBtn) {
    const label = shareBtn.querySelector(".btn-share-label");
    const originalText = label?.textContent || "Copy link";
    let resetTimer = null;

    shareBtn.addEventListener("click", async () => {
      if (!label) return;
      try {
        await navigator.clipboard.writeText(window.location.href);
        label.textContent = "Copied!";
        shareBtn.classList.add("btn-share-success");
        clearTimeout(resetTimer);
        resetTimer = setTimeout(() => {
          label.textContent = originalText;
          shareBtn.classList.remove("btn-share-success");
        }, 2000);
      } catch (_err) {
        label.textContent = "Press Cmd+C";
      }
    });
  }

  const backToTop = document.getElementById("back-to-top");
  if (backToTop) {
    function checkScroll() {
      backToTop.hidden = window.scrollY < 600;
    }
    window.addEventListener("scroll", checkScroll, { passive: true });
    backToTop.addEventListener("click", () => {
      window.scrollTo({ top: 0, behavior: "smooth" });
    });
    checkScroll();
  }
});
