// Phase 8 - Educational Mode toggle on source-code finding cards.
//
// Lazy-loads per-finding remediation content via XHR the first time the
// expand button is clicked, caches it on the button's parent card so the
// second click (collapse) and any subsequent re-expand reuse the same
// DOM without refetching.
(function () {
  function escapeHtml(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;");
  }

  function renderContent(target, data) {
    target.innerHTML =
      '<section class="educational-block educational-vulnerable">' +
      '<h5>Vulnerable</h5><pre class="mono">' +
      escapeHtml(data.vulnerable_snippet) + "</pre></section>" +
      '<section class="educational-block educational-fixed">' +
      '<h5>Fixed</h5><pre class="mono">' +
      escapeHtml(data.fixed_snippet) + "</pre></section>" +
      '<section class="educational-block educational-explanation">' +
      "<h5>Why this matters</h5><p>" +
      escapeHtml(data.explanation) + "</p></section>";
  }

  function onToggle(btn) {
    const card = btn.closest(".finding-card");
    if (!card) return;
    const target = card.querySelector(".educational-content");
    if (!target) return;

    const expanded = btn.getAttribute("aria-expanded") === "true";
    if (expanded) {
      target.hidden = true;
      btn.setAttribute("aria-expanded", "false");
      btn.innerHTML = "▾ Show Educational Detail";
      return;
    }

    btn.setAttribute("aria-expanded", "true");
    btn.innerHTML = "▴ Hide Educational Detail";

    // Cached? Just reveal.
    if (card.dataset.educationalLoaded === "1") {
      target.hidden = false;
      return;
    }

    const findingId = btn.dataset.findingId;
    target.innerHTML = '<p class="muted">Loading...</p>';
    target.hidden = false;

    fetch("/api/finding/" + encodeURIComponent(findingId) + "/educational")
      .then(function (resp) {
        if (!resp.ok) {
          return resp.json().then(function (e) { throw new Error(e.error || "lookup failed"); });
        }
        return resp.json();
      })
      .then(function (data) {
        renderContent(target, data);
        card.dataset.educationalLoaded = "1";
      })
      .catch(function (err) {
        target.innerHTML = '<p class="muted">Could not load educational content: ' +
          escapeHtml(err.message) + "</p>";
      });
  }

  document.addEventListener("click", function (e) {
    const btn = e.target.closest(".educational-toggle");
    if (btn) {
      e.preventDefault();
      onToggle(btn);
    }
  });
})();
