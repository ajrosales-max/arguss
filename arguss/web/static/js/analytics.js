/**
 * Arguss funnel analytics → GTM dataLayer → GA4.
 *
 * In GTM: add a Custom Event trigger for each event name below, then a GA4 Event
 * tag that sends the event name and event parameters (repo, ref, source, status,
 * has_workflows, has_package_json, scan_hash, from_path).
 *
 * Events: scan_url, scan_url_result, scan_upload, scan_upload_result,
 * remediation_start, wizard_select, wizard_authorize, github_install.
 */
(function () {
  "use strict";

  window.dataLayer = window.dataLayer || [];

  function argussTrack(eventName, params) {
    if (!eventName || typeof eventName !== "string") return;
    var payload = Object.assign({ event: eventName }, params || {});
    window.dataLayer.push(payload);
  }

  window.argussTrack = argussTrack;

  /**
   * Parse https GitHub URL to "owner/repo", or null.
   * Never returns the raw URL (avoid sending full typed strings to GA).
   */
  function argussParseGithubRepo(url) {
    if (!url || typeof url !== "string") return null;
    var trimmed = url.trim();
    var match = trimmed.match(
      /^https?:\/\/(?:www\.)?github\.com\/([^/?#]+)\/([^/?#]+?)(?:\.git)?\/?(?:[?#].*)?$/i
    );
    if (!match) return null;
    var owner = match[1];
    var repo = match[2];
    if (!owner || !repo || owner === "." || repo === ".") return null;
    return owner + "/" + repo;
  }

  window.argussParseGithubRepo = argussParseGithubRepo;

  function htmxStatus(detail) {
    if (detail && detail.successful === true) return "success";
    if (detail && detail.successful === false) return "error";
    var xhr = detail && detail.xhr;
    if (!xhr) return "error";
    return xhr.status >= 200 && xhr.status < 400 ? "success" : "error";
  }

  function scanFormContext(form) {
    var urlInput = form.querySelector("#scan-url, input[name='url']");
    var refInput = form.querySelector("#scan-ref, input[name='ref']");
    var url = urlInput && urlInput.value ? urlInput.value : "";
    var ref = refInput && refInput.value ? String(refInput.value).trim() : "";
    var repo = argussParseGithubRepo(url);
    var source = form.dataset.argussDemo === "1" ? "demo" : "form";
    var params = { source: source };
    if (repo) params.repo = repo;
    if (ref) params.ref = ref;
    return params;
  }

  function uploadFormContext(form) {
    var workflows = form.querySelector("input[name='workflows_zip']");
    var packageJson = form.querySelector("input[name='package_json']");
    return {
      has_workflows: workflows && workflows.files && workflows.files.length > 0 ? "true" : "false",
      has_package_json:
        packageJson && packageJson.files && packageJson.files.length > 0 ? "true" : "false",
    };
  }

  function onHtmxBeforeRequest(event) {
    var elt = event.detail && event.detail.elt;
    if (!elt) return;
    var form = elt.id === "scan-form" || elt.id === "upload-form" ? elt : elt.closest(".scan-form");
    if (!form) return;

    if (form.id === "scan-form") {
      argussTrack("scan_url", scanFormContext(form));
      return;
    }
    if (form.id === "upload-form") {
      argussTrack("scan_upload", uploadFormContext(form));
    }
  }

  function onHtmxAfterRequest(event) {
    var elt = event.detail && event.detail.elt;
    if (!elt) return;
    var form = elt.id === "scan-form" || elt.id === "upload-form" ? elt : elt.closest(".scan-form");
    if (!form) return;

    var status = htmxStatus(event.detail);
    if (form.id === "scan-form") {
      var scanParams = scanFormContext(form);
      scanParams.status = status;
      argussTrack("scan_url_result", scanParams);
      delete form.dataset.argussDemo;
      return;
    }
    if (form.id === "upload-form") {
      var uploadParams = uploadFormContext(form);
      uploadParams.status = status;
      argussTrack("scan_upload_result", uploadParams);
    }
  }

  function onSubmit(event) {
    var form = event.target;
    if (!form || form.tagName !== "FORM") return;

    if (form.classList.contains("remediation-cta-form")) {
      var action = form.getAttribute("action") || "";
      var hashMatch = action.match(/\/assessment\/([0-9a-fA-F]+)\//);
      var params = {};
      if (hashMatch && hashMatch[1]) {
        params.scan_hash = hashMatch[1].slice(0, 8);
      }
      argussTrack("remediation_start", params);
      return;
    }

    if (form.id === "wizard-plan-form") {
      argussTrack("wizard_select");
      return;
    }

    if (form.classList.contains("wizard-authorize-form")) {
      argussTrack("wizard_authorize");
    }
  }

  function onClick(event) {
    var anchor = event.target && event.target.closest
      ? event.target.closest('a[href^="/github/install"]')
      : null;
    if (!anchor) return;
    argussTrack("github_install", {
      from_path: window.location.pathname || "/",
    });
  }

  function bind() {
    document.body.addEventListener("htmx:beforeRequest", onHtmxBeforeRequest);
    document.body.addEventListener("htmx:afterRequest", onHtmxAfterRequest);
    document.body.addEventListener("submit", onSubmit, true);
    document.body.addEventListener("click", onClick, true);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", bind);
  } else {
    bind();
  }
})();
