/**
 * Lazy-init full-project dependency graph (Cytoscape).
 * Expects #dependency-graph-data JSON and window.ArgussCytoscapeHelpers from results.html.
 */
(function () {
  "use strict";

  var MAX_FILTERED_NODES = 100;
  var ROOT_ID = "root";

  function helpers() {
    return window.ArgussCytoscapeHelpers || {};
  }

  function nodeLabel(ele) {
    var fn = helpers().nodeLabel;
    if (typeof fn === "function") {
      return fn(ele);
    }
    var name = ele.data("label") || ele.data("id") || "";
    var version = ele.data("version");
    var count = ele.data("vuln_count");
    var text = name;
    if (version) {
      text += "@" + version;
    }
    if (count && count > 0) {
      text += " (" + count + ")";
    }
    return text;
  }

  function severityColor(severity) {
    var fn = helpers().severityColor;
    if (typeof fn === "function") {
      return fn(severity);
    }
    switch (severity) {
      case "critical":
        return "#A32D2D";
      case "high":
        return "#D85A30";
      case "medium":
        return "#BA7517";
      case "low":
        return "#185FA5";
      default:
        return "#C9C1D5";
    }
  }

  function trustBorderWidth(ele) {
    var score = ele.data("trust_score");
    if (typeof score !== "number" || Number.isNaN(score)) {
      return 2;
    }
    return 2 + Math.round((Math.max(0, Math.min(100, score)) / 100) * 5);
  }

  function parseGraphElements() {
    var dataEl = document.getElementById("dependency-graph-data");
    if (!dataEl) {
      return [];
    }
    try {
      var parsed = JSON.parse(dataEl.textContent || "[]");
      return Array.isArray(parsed) ? parsed : [];
    } catch (err) {
      console.debug("dependency-graph: failed to parse elements", err);
      return [];
    }
  }

  function partitionElements(allElements) {
    var nodes = [];
    var edges = [];
    allElements.forEach(function (el) {
      if (!el || !el.data) {
        return;
      }
      if (el.data.source && el.data.target) {
        edges.push(el);
      } else if (el.data.id) {
        nodes.push(el);
      }
    });
    return { nodes: nodes, edges: edges };
  }

  function buildParentMap(edges) {
    var parentsOf = Object.create(null);
    edges.forEach(function (edge) {
      var child = edge.data.target;
      var parent = edge.data.source;
      if (!child || !parent) {
        return;
      }
      if (!parentsOf[child]) {
        parentsOf[child] = [];
      }
      if (parentsOf[child].indexOf(parent) === -1) {
        parentsOf[child].push(parent);
      }
    });
    return parentsOf;
  }

  function nodeHasVuln(node) {
    return node.data.has_vuln === true || (node.data.vuln_count && node.data.vuln_count > 0);
  }

  function collectVulnerablePathNodes(nodes, edges) {
    var parentsOf = buildParentMap(edges);
    var keep = Object.create(null);
    var seeds = nodes.filter(nodeHasVuln);

    if (!seeds.length) {
      return keep;
    }

    function markAncestors(nodeId) {
      if (keep[nodeId]) {
        return;
      }
      keep[nodeId] = true;
      (parentsOf[nodeId] || []).forEach(markAncestors);
    }

    seeds.forEach(function (node) {
      markAncestors(node.data.id);
    });
    keep[ROOT_ID] = true;
    return keep;
  }

  function capNodeSet(keep, nodes, edges) {
    var ids = Object.keys(keep);
    if (ids.length <= MAX_FILTERED_NODES) {
      return keep;
    }

    var nodeMeta = Object.create(null);
    nodes.forEach(function (node) {
      var id = node.data.id;
      if (keep[id]) {
        nodeMeta[id] = node.data;
      }
    });

    var parentsOf = buildParentMap(edges);
    var ranked = ids.slice().sort(function (a, b) {
      var aVuln = nodeHasVuln({ data: nodeMeta[a] }) ? 1 : 0;
      var bVuln = nodeHasVuln({ data: nodeMeta[b] }) ? 1 : 0;
      if (aVuln !== bVuln) {
        return bVuln - aVuln;
      }
      var aDepth = typeof nodeMeta[a].depth === "number" ? nodeMeta[a].depth : 0;
      var bDepth = typeof nodeMeta[b].depth === "number" ? nodeMeta[b].depth : 0;
      return bDepth - aDepth;
    });

    var capped = Object.create(null);
    ranked.slice(0, MAX_FILTERED_NODES).forEach(function (id) {
      capped[id] = true;
    });
    capped[ROOT_ID] = true;

    var changed = true;
    while (changed) {
      changed = false;
      Object.keys(capped).forEach(function (id) {
        (parentsOf[id] || []).forEach(function (parent) {
          if (keep[parent] && !capped[parent]) {
            capped[parent] = true;
            changed = true;
          }
        });
      });
    }

    return capped;
  }

  function filterElements(allElements, showAll) {
    var parts = partitionElements(allElements);
    if (showAll) {
      return allElements;
    }

    var keep = collectVulnerablePathNodes(parts.nodes, parts.edges);
    if (!Object.keys(keep).length) {
      return [];
    }
    keep = capNodeSet(keep, parts.nodes, parts.edges);

    var filteredNodes = parts.nodes.filter(function (node) {
      return keep[node.data.id];
    });
    var filteredEdges = parts.edges.filter(function (edge) {
      return keep[edge.data.source] && keep[edge.data.target];
    });
    return filteredNodes.concat(filteredEdges);
  }

  function graphStylesheet() {
    return [
      {
        selector: "node",
        style: {
          label: "",
          width: 28,
          height: 28,
          "background-color": "#D8D4CE",
          "border-width": 2,
          "border-color": "#C9C1D5",
          opacity: 1,
        },
      },
      {
        selector: "node[has_vuln = true]",
        style: {
          width: 52,
          height: 52,
          "background-color": "#FFFFFF",
          "border-width": 3,
          "border-color": function (ele) {
            return severityColor(ele.data("max_severity"));
          },
        },
      },
      {
        selector: "node[node_class = 'root']",
        style: {
          "background-color": "#0B0B11",
          "border-color": "#0B0B11",
          width: 36,
          height: 36,
        },
      },
      {
        selector: "node[node_class = 'direct']",
        style: {
          "border-color": "#7C3AED",
        },
      },
      {
        selector: "node[trust_score]",
        style: {
          "border-width": trustBorderWidth,
          "border-color": "#9F5BFF",
        },
      },
      {
        selector: "node[max_severity]",
        style: {
          "border-color": function (ele) {
            return severityColor(ele.data("max_severity"));
          },
          "border-width": 3,
        },
      },
      {
        selector: "node.dimmed",
        style: {
          opacity: 0.25,
        },
      },
      {
        selector: "node.ancestor-highlight",
        style: {
          "background-color": "#F3EBFF",
          "border-width": 4,
          opacity: 1,
        },
      },
      {
        selector: "edge",
        style: {
          width: 1.5,
          "line-color": "#C9C1D5",
          "target-arrow-color": "#C9C1D5",
          "target-arrow-shape": "triangle",
          "curve-style": "bezier",
          "arrow-scale": 0.75,
          opacity: 1,
        },
      },
      {
        selector: "edge.dimmed",
        style: {
          opacity: 0.15,
        },
      },
      {
        selector: "edge.ancestor-highlight",
        style: {
          width: 2.5,
          "line-color": "#9F5BFF",
          "target-arrow-color": "#9F5BFF",
          opacity: 1,
        },
      },
    ];
  }

  function fitGraph(cy) {
    requestAnimationFrame(function () {
      requestAnimationFrame(function () {
        cy.resize();
        cy.fit(undefined, 32);
      });
  function formatNodeHoverTooltip(node) {
    var name = node.data("label") || node.data("id") || "";
    var version = node.data("version");
    var pkg = name;
    if (version) {
      pkg += "@" + version;
    }
    var lines = [pkg];
    var count = node.data("vuln_count");
    if (count && count > 0) {
      lines.push(
        "Findings: " + count + ", max severity: " + (node.data("max_severity") || "unknown")
      );
    }
    var score = node.data("trust_score");
    if (typeof score === "number" && !Number.isNaN(score)) {
      lines.push("Trust ring: thicker border = higher risk (score " + score + ")");
      var concern = node.data("trust_concern");
      if (concern) {
        lines.push(String(concern));
      }
    }
    return lines.join("\n");
  }

  function hideTooltip(tooltipEl) {
    if (!tooltipEl) {
      return;
    }
    tooltipEl.hidden = true;
    tooltipEl.textContent = "";
  }

  function showTooltipAtNode(cy, tooltipEl, node, text) {
    if (!tooltipEl || !text) {
      hideTooltip(tooltipEl);
      return;
    }
    var pos = node.renderedPosition();
    tooltipEl.style.left = pos.x + "px";
    tooltipEl.style.top = pos.y + "px";
    tooltipEl.textContent = text;
    tooltipEl.hidden = false;
  }

  function clearHighlight(cy, state) {
    cy.elements().removeClass("ancestor-highlight dimmed");
    state.activeHighlightId = null;
    hideTooltip(state.tooltipEl);
  }

  function highlightAncestors(cy, node, state) {
    var trail = node.predecessors().union(node);
    cy.elements().removeClass("ancestor-highlight dimmed");
    trail.addClass("ancestor-highlight");
    cy.elements().difference(trail).addClass("dimmed");
    state.activeHighlightId = node.id();
  }

  function createGraph(container, elements, state) {
    if (typeof cytoscape === "undefined") {
      return null;
    }
    state.activeHighlightId = null;
    var cy = cytoscape({
      container: container,
      elements: elements,
      layout: {
        name: "concentric",
        fit: true,
        padding: 24,
        startAngle: (3 / 2) * Math.PI,
        clockwise: true,
        equidistant: false,
        minNodeSpacing: 28,
        concentric: function (node) {
          var depth = node.data("depth");
          if (typeof depth !== "number" || Number.isNaN(depth)) {
            return 0;
          }
          return depth;
        },
        levelWidth: function () {
          return 1;
        },
      },
      style: graphStylesheet(),
      minZoom: 0.15,
      maxZoom: 3,
    });

    cy.on("tap", "node", function (evt) {
      var node = evt.target;
      if (state.activeHighlightId === node.id()) {
        clearHighlight(cy, state);
        return;
      }
      highlightAncestors(cy, node, state);
    });

    cy.on("tap", function (evt) {
      if (evt.target === cy) {
        clearHighlight(cy, state);
      }
    });

    cy.on("mouseover", "node", function (evt) {
      showTooltipAtNode(
        cy,
        state.tooltipEl,
        evt.target,
        formatNodeHoverTooltip(evt.target)
      );
    });

    cy.on("mouseout", "node", function () {
      hideTooltip(state.tooltipEl);
    });

    cy.on("pan zoom", function () {
      hideTooltip(state.tooltipEl);
    });

    fitGraph(cy);
    return cy;
  }

    return cy;
  }

  function DependencyGraphController() {
    this.allElements = [];
    this.cy = null;
    this.container = null;
    this.tooltipEl = null;
    this.wrapEl = null;
    this.loadBtn = null;
    this.showAllInput = null;
    this.graphState = { tooltipEl: null, activeHighlightId: null };
    this.expandBtn = null;
    this.fullscreenEl = null;
    this.fullscreenCloseBtn = null;
    this.fullscreenSlot = null;
    this.inlineHost = null;
    this.panelShell = null;
    this.fullscreenOpen = false;
  }

  DependencyGraphController.prototype.initDom = function () {
    this.container = document.getElementById("dependency-graph-cy");
    this.tooltipEl = document.getElementById("dependency-graph-tooltip");
    this.wrapEl = document.getElementById("dependency-graph-wrap");
    this.loadBtn = document.getElementById("dependency-graph-load");
    this.showAllInput = document.getElementById("dependency-graph-show-all");
    this.inlineHost = document.getElementById("dependency-graph-inline-host");
    this.panelShell = document.getElementById("dependency-graph-panel-shell");
    this.expandBtn = document.getElementById("dependency-graph-expand");
    this.fullscreenEl = document.getElementById("dependency-graph-fullscreen");
    this.fullscreenCloseBtn = document.getElementById("dependency-graph-fullscreen-close");
    this.fullscreenSlot = document.getElementById("dependency-graph-fullscreen-slot");
    var section = document.querySelector(".dependency-graph-section");
    this.defaultShowAll =
      section && section.getAttribute("data-default-show-all") === "true";
    this.graphState.tooltipEl = this.tooltipEl;
    return Boolean(this.container && this.loadBtn && this.wrapEl);
  };

  DependencyGraphController.prototype.isShowAll = function () {
    if (this.showAllInput) {
      return Boolean(this.showAllInput.checked);
    }
    return this.defaultShowAll;
  };

  DependencyGraphController.prototype.render = function () {
    var showAll = this.isShowAll();
    var elements = filterElements(this.allElements, showAll);

    if (this.cy) {
      this.cy.destroy();
      this.cy = null;
    }

    if (!elements.length) {
      if (this.tooltipEl) {
        this.tooltipEl.textContent = "No vulnerable dependency paths to display.";
        this.tooltipEl.hidden = false;
      }
      return;
    }

    this.cy = createGraph(this.container, elements, this.graphState);
    if (this.cy) {
      this.container._cy = this.cy;
    }
  };

  DependencyGraphController.prototype.onLoad = function () {
    if (typeof cytoscape === "undefined") {
      if (this.tooltipEl) {
        this.tooltipEl.textContent =
          "Graph library still loading — try again in a moment.";
        this.tooltipEl.hidden = false;
      }
      return;
    }

    this.allElements = parseGraphElements();
    if (!this.allElements.length) {
      return;
    }

    this.wrapEl.hidden = false;
    this.loadBtn.disabled = true;
    this.loadBtn.textContent = "Graph loaded";
    if (this.expandBtn) {
      this.expandBtn.disabled = false;
    }
    this.render();
  };


  DependencyGraphController.prototype.openFullscreen = function () {
    if (this.fullscreenOpen || !this.panelShell || !this.fullscreenSlot || !this.fullscreenEl) {
      return;
    }
    this.fullscreenSlot.appendChild(this.panelShell);
    this.fullscreenEl.hidden = false;
    this.fullscreenEl.setAttribute("aria-hidden", "false");
    document.body.classList.add("dependency-graph-fullscreen-active");
    this.fullscreenOpen = true;
    if (this.cy) {
      fitGraph(this.cy);
    }
  };

  DependencyGraphController.prototype.closeFullscreen = function () {
    if (!this.fullscreenOpen || !this.panelShell || !this.inlineHost || !this.fullscreenEl) {
      return;
    }
    this.inlineHost.appendChild(this.panelShell);
    this.fullscreenEl.hidden = true;
    this.fullscreenEl.setAttribute("aria-hidden", "true");
    document.body.classList.remove("dependency-graph-fullscreen-active");
    this.fullscreenOpen = false;
    hideTooltip(this.graphState.tooltipEl);
    if (this.cy) {
      fitGraph(this.cy);
    }
  };

  DependencyGraphController.prototype.bind = function () {
    var self = this;
    this.loadBtn.addEventListener("click", function () {
      self.onLoad();
    });
    if (this.showAllInput) {
      this.showAllInput.addEventListener("change", function () {
        if (!self.cy) {
          return;
        }
        self.render();
      });
    }
    if (this.expandBtn) {
      this.expandBtn.addEventListener("click", function () {
        self.openFullscreen();
      });
    }
    if (this.fullscreenCloseBtn) {
      this.fullscreenCloseBtn.addEventListener("click", function () {
        self.closeFullscreen();
      });
    }
    document.addEventListener("keydown", function (evt) {
      if (evt.key === "Escape" && self.fullscreenOpen) {
        self.closeFullscreen();
      }
    });
  };

  function boot() {
    var controller = new DependencyGraphController();
    if (!controller.initDom()) {
      return;
    }
    controller.bind();
    window.ArgussDependencyGraph = controller;
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
})();
