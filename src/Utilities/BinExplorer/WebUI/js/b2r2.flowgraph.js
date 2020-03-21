/*
  B2R2 - the Next-Generation Reversing Platform

  Copyright (c) SoftSec Lab. @ KAIST, since 2016

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in all
  copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
  SOFTWARE.
 */

"use strict";

class FlowGraph extends Graph {
  constructor(div, id, kind) {
    super(div, kind);
    this.refreshIcon = d3.select("#js-icon-refresh").classed("rotating", true);
    // The json data.
    this.json = null;
    // The main svg.
    this.svg = div.append("svg").style("width", "100%").style("height", "100%");
    // The top layer of the flow graph.
    this.stage = this.svg.append("g").attr("transform", "scale (1)");
    // The main group for a flow graph.
    this.cfg = this.stage.append("g");
    // The minimap for this graph.
    this.minimap = new Minimap(div, this);
    // The mapping from address to stmt in the graph.
    this.linemap = {};
    // The last activated line.
    this.lastActiveLine = null;
    // The last activated terms.
    this.lastActiveTerms = [];
    this.initializeLineFunc();
    this.fetchAndDraw(id, kind);
  }

  initializeLineFunc() {
    this.linefunc = d3.line()
      .x(function (d) { return d.X; })
      .y(function (d) { return d.Y; })
      .curve(d3.curveMonotoneY);
  }

  queryDataflow(addr, term) {
    return this.linemap[addr].Tokens[term];
  }

  deactivateHighlights() {
    if (this.lastActiveLine !== null)
      this.lastActiveLine.classed("active", false);
    for (let i = 0; i < this.lastActiveTerms.length; i++) {
      this.lastActiveTerms[i].classed("active", false);
    }
    this.lastActiveTerms = [];
  }

  appendTerm(idx, txt, tag, term, addr) {
    const cls = "c-graph__stmt--" + tag;
    const tspan = txt.append("tspan").text(term).classed(cls, true);
    if (idx == 0) tspan.attr("x", 2).attr("dy", "14px");
    else tspan.attr("dx", "0px");
    if (tag == "variable" || tag == "value") {
      const myself = this;
      tspan.on("click", function () {
        myself.deactivateHighlights();
        d3.event.stopPropagation();
        const nodes = myself.queryDataflow(addr, term);
        for (let i = 0; i < nodes.length; i++) {
          nodes[i].classed("active", true);
          myself.lastActiveTerms.push(nodes[i]);
        }
      });
    }
    if (term in this.linemap[addr].Tokens)
      this.linemap[addr].Tokens[term].push(tspan);
    else
      this.linemap[addr].Tokens[term] = [tspan];
  }

  drawLinesOfNode(v, g) {
    const f = "js-filter-stmt-background";
    for (let i = 0; i < v.Terms.length; i++) {
      const line = v.Terms[i];
      const addr = parseInt(line[0], 16);
      const y = i * 14 + stmtPaddingTop;
      const txt = g.append("text").attr("transform", "translate(0," + y + ")")
        .classed("c-graph__stmt", true)
        .attr("xml:space", "preserve");
      txt
        .on("mouseover", function () { txt.attr("filter", "url(#" + f + ")"); })
        .on("mouseout", function () { txt.attr("filter", null); });
      this.linemap[addr] = { DOM: txt, Tokens: {} };
      for (let j = 0; j < line.length; j++) {
        const term = line[j][0];
        const tag = line[j][1];
        this.appendTerm(j, txt, tag, term, addr);
      }
    }
  }

  addContextMenu(g) {
    $(g.node()).contextMenu({
      selector: "text",
      callback: function (k, _opts) {
        switch (k) {
          case "copy-addr":
            copyToClipboard($(this).find(".c-graph__stmt--address").text());
            break;
          case "copy-stmt":
            copyToClipboard($(this).text());
            break;
          default: break;
        }
      },
      items: {
        "copy-addr": { name: "Copy address", icon: "edit" },
        "copy-stmt": { name: "Copy stmt", icon: "copy" }
      }
    });
  }

  drawNode(v) {
    this.minimap.drawNode(v);
    const x = v.Coordinate.X;
    const y = v.Coordinate.Y;
    const g = this.cfg.append("g")
      .attr("transform", "translate(" + x + "," + y + ")");
    g.append("rect")
      .classed("c-graph__node", true)
      .attr("width", v.Width)
      .attr("height", v.Height);
    this.addContextMenu(g);
    this.drawLinesOfNode(v, g);
  }

  drawNodes(json) {
    for (let i = 0; i < json.Nodes.length; i++) {
      this.drawNode(json.Nodes[i]);
    }
  }

  drawEdge(e) {
    this.minimap.drawEdge(e);
    const path = this.cfg.append("path")
      .classed("c-graph__edge", true)
      .classed("c-graph__" + e.Type.toLowerCase(), true)
      .datum(e.Points)
      .attr("d", this.linefunc)
      .attr("marker-end", "url(#" + "js-" + e.Type.toLowerCase() + ")");
    if (e.IsBackEdge) path.attr("stroke-dasharray", "4, 4");
  }

  drawEdges(json) {
    for (let i = 0; i < json.Edges.length; i++) {
      this.drawEdge(json.Edges[i]);
    }
  }

  computeReductionRate(graphDims) {
    const widthReduction = this.vpDims.cfgVPDim.width / graphDims.width;
    const heightReduction = this.vpDims.cfgVPDim.height / graphDims.height;
    let reductionRate = Math.min(widthReduction, heightReduction);
    // If the entire CFG is smaller than the cfgVP, then simply use the rate 1.
    // In other words, the maximum reductionRate is one.
    if (reductionRate >= 1) reductionRate = 1;
    return reductionRate;
  }

  centerAlign(reductionRate) {
    const xshiftAmount = this.vpDims.cfgVPDim.width / 2 / reductionRate;
    this.cfg.attr("transform", "translate(" + xshiftAmount + ",0)");
    this.minimap.centerAlign(this.vpDims.minimapVPDim, reductionRate);
  }

  static onZoom(g) {
    return function () {
      g.transK = d3.event.transform.k;
      const ratio = g.reductionRate * minimapRatio / g.transK;
      const x = (- d3.event.transform.x) * ratio;
      const y = (- d3.event.transform.y) * ratio;
      const k = g.reductionRate / g.transK;
      const trans = "translate(" + x + "," + y + ") scale(" + k + ")";
      g.ratio = ratio;
      g.stage.attr("transform", d3.event.transform);
      g.minimap.viewbox.attr("transform", trans);
    };
  }

  computeTranslate(xPos, yPos) {
    const cfgDim = this.vpDims.cfgVPDim;
    const s = this.transK / this.reductionRate;
    const k = this.transK;
    const x = - xPos * k - (s - 1) * cfgDim.width / 2;
    const y = - yPos * k + cfgDim.height / 2;
    return { x: x, y: y, k: k };
  }

  registerPathDblClickEvents() {
    const myself = this;
    this.cfg.selectAll(".c-graph__edge").on("dblclick", function (pts) {
      const bounds = d3.event.target.getBoundingClientRect();
      const clickY = d3.event.clientY;
      const bottomDist = Math.abs(bounds.bottom - clickY);
      const topDist = Math.abs(bounds.top - clickY);
      const goingUp = topDist > bottomDist;
      const firstpt = pts[0];
      const lastpt = pts[pts.length - 1];
      const pt =
           (goingUp && firstpt.Y > lastpt.Y)
        || (!goingUp && firstpt.Y < lastpt.Y)
        ? lastpt : firstpt;
      const r = myself.computeTranslate(pt.X, pt.Y);
      const x = r.x, y = r.y, k = r.k;
      myself.svg.transition().duration(700)
        .call(myself.zoom.transform, d3.zoomIdentity.translate(x, y).scale(k));
    });
  }

  registerEvents(reductionRate) {
    const myself = this;
    this.transK = 1 / reductionRate;
    this.zoom = d3.zoom()
      .scaleExtent([reductionRate, 5])
      .on("zoom", FlowGraph.onZoom(myself));
    const transform = d3.zoomIdentity.translate(0, 0).scale(reductionRate);
    this.svg
      .call(this.zoom)
      .call(this.zoom.transform, transform)
      .on("dblclick.zoom", null);
    this.minimap.registerViewboxEvents(this.vpDims.minimapVPDim, this);
    this.registerPathDblClickEvents();
    $(document).on("click", function () { myself.deactivateHighlights(); });
  }

  draw(json) {
    this.vpDims = computeVPDimensions(this.container);
    this.minimap.resize(this.vpDims.minimapVPDim);
    this.minimap.registerViewbox(this.vpDims.minimapVPDim);
    this.drawNodes(json);
    this.drawEdges(json);
    // Compute the actual bbox after drawing the graph.
    const graphDims = this.cfg.node().getBBox();
    this.reductionRate = this.computeReductionRate(graphDims);
    this.centerAlign(this.reductionRate);
    this.registerEvents(this.reductionRate);
    this.refreshIcon.classed("rotating", false);
  }

  fetchAndDraw(id, kind) {
    const myself = this;
    query({ "q": kind, "args": id }, function (_status, json) {
      myself.json = json;
      myself.draw(json);
    });
  }

  moveToInitialPos() {
    this.svg.call(this.zoom.transform,
      d3.zoomIdentity.translate(0, 0).scale(this.reductionRate));
  }

  createResultValue(patternIdx, patternLen, str) {
    const maxCnt = 8;
    const startIdx = patternIdx < maxCnt ? 0 : patternIdx - maxCnt;
    const myLastIdx = patternIdx + patternLen + maxCnt;
    const endIdx = myLastIdx > str.length - 1 ? str.length - 1 : myLastIdx;
    return (startIdx > 0 ? "... " : "")
      + str.substr(startIdx, patternIdx - startIdx)
      + "<strong>" + str.substr(patternIdx, patternLen) + "</strong>"
      + str.substr(patternIdx + patternLen, maxCnt)
      + (endIdx < myLastIdx ? "" : " ...");
  }

  search(q) {
    const myself = this;
    let results = [];
    for (let i = 0; i < this.json.Nodes.length; i++) {
      const v = this.json.Nodes[i];
      for (let j = 0; j < v.Terms.length; j++) {
        const term = v.Terms[j];
        let str = "";
        for (let k = 0; k < term.length; k++) {
          const elm = term[k];
          str += elm[0];
        }
        const patternIdx = str.toLowerCase().indexOf(q);
        if (patternIdx >= 0) {
          const addr = parseInt(term[0], 16);
          results.push({
            addr: addr,
            val: this.createResultValue(patternIdx, q.length, str),
            onclick: function () {
              const coord = v.Coordinate;
              const r = myself.computeTranslate(coord.X + v.Width / 2, coord.Y);
              const x = r.x, y = r.y, k = r.k;
              myself.deactivateHighlights();
              myself.svg.transition().duration(500)
                .call(myself.zoom.transform,
                  d3.zoomIdentity.translate(x, y).scale(k));
              myself.linemap[addr].DOM.classed("active", true);
              myself.lastActiveLine = myself.linemap[addr].DOM;
              d3.event.stopPropagation();
              $("#js-search-dialog").dialog("close");
            },
            onhover: null
          });
        }
      }
    }
    return results.sort(function (a, b) { return a.addr - b.addr; });
  }
}

