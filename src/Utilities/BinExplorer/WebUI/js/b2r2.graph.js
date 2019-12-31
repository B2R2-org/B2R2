/*
  B2R2 - the Next-Generation Reversing Platform

  Author: Subin Jeong <cyclon2@kaist.ac.kr>
          Soomin Kim <soomink@kaist.ac.kr>
          Sang Kil Cha <sangkilc@kaist.ac.kr>

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

class FlowGraph {
  constructor(div, name, kind) {
    this.refreshIcon = d3.select("#js-icon-refresh").classed("rotating", true);
    // The json data.
    this.json = null;
    // The type of the graph.
    this.kind = kind;
    // The c-graph container.
    this.container = div;
    // The main svg.
    this.svg = div.append("svg").style("width", "100%").style("height", "100%");
    // The top layer of the flow graph.
    this.stage = this.svg.append("g").attr("transform", "scale (1)");
    // The main group for a flow graph.
    this.cfg = this.stage.append("g");
    // The minimap for this graph.
    this.minimap = new Minimap(div, this);
    // The predefined arrows and filters.
    this.predefs = this.cfg.append("defs");
    this.initializePredefs(name);
    this.fetchAndDraw(name, kind);
  }

  generateArrowID(name, tag) {
    return "js-" + name + "-" + tag.toLowerCase();
  }

  generateArrowClass(tag) {
    return "c-graph__arrow-" + tag.toLowerCase();
  }

  generateEdgeClass(tag) {
    return "c-graph__" + tag.toLowerCase();
  }

  generateFilterID(name, filter) {
    return "js-filter-" + filter + "-" + name;
  }

  setMarkerArrow(name, tag) {
    this.predefs.append("marker")
      .classed(this.generateArrowClass(tag), true)
      .attr("id", this.generateArrowID(name, tag))
      .attr("markerWidth", 3)
      .attr("markerHeight", 3)
      .attr("markerUnits", "strokeWidth")
      .attr("viewBox", "-5 -5 10 10")
      .attr("refX", 5)
      .attr("refY", 0)
      .attr("orient", "auto")
      .append("path")
        .attr("d", "M 0,0 m -5,-5 L 5,0 L -5,5 Z");
  }

  setFilter(name) {
    this.predefs.append("filter")
      .attr("id", this.generateFilterID(name, "blur"))
      .attr("filterUnits", "userSpaceOnUse")
      .append("feGaussianBlur")
        .attr("stdDeviation", 2);
  }

  initializePredefs(name) {
    this.setMarkerArrow(name, "InterJmpEdge");
    this.setMarkerArrow(name, "InterCJmpTrueEdge");
    this.setMarkerArrow(name, "InterCJmpFalseEdge");
    this.setMarkerArrow(name, "IntraJmpEdge");
    this.setMarkerArrow(name, "IntraCJmpTrueEdge");
    this.setMarkerArrow(name, "IntraCJmpFalseEdge");
    this.setMarkerArrow(name, "FallThroughEdge");
    this.setMarkerArrow(name, "CallEdge");
    this.setMarkerArrow(name, "RetEdge");
    this.setFilter(name);
    this.linefunc = d3.line()
      .x(function (d) { return d.X; })
      .y(function (d) { return d.Y; })
      .curve(d3.curveMonotoneY);
  }

  appendTerm(idx, txt, tag, term) {
    const cls = "c-graph__stmt--" + tag;
    const tspan = txt.append("tspan").text(term).classed(cls, true);
    if (idx == 0) tspan.attr("x", padding / 2).attr("dy", "14px");
    else tspan.attr("dx", "0px");
  }

  drawLinesOfNode(v, g) {
    for (let i = 0; i < v.Terms.length; i++) {
      const line = v.Terms[i];
      const y = i * 14 + stmtPaddingTop;
      const gstmt = g.append("g").attr("transform", "translate(0," + y + ")");
      const txt = gstmt.append("text")
        .classed("c-graph__stmt", true)
        .attr("xml:space", "preserve");
      for (let j = 0; j < line.length; j++) {
        const term = line[j][0];
        const tag = line[j][1];
        this.appendTerm(j, txt, tag, term);
      }
    }
  }

  drawNode(name, v) {
    this.minimap.drawNode(v);
    const x = v.Coordinate.X;
    const y = v.Coordinate.Y;
    const g = this.cfg.append("g")
      .attr("addr", v.PPoint[0])
      .attr("transform", "translate(" + x + "," + y + ")");
    g.append("rect")
      .classed("c-graph__node", true)
      .attr("width", v.Width)
      .attr("height", v.Height);
    const rect = g.append("rect")
      .classed("c-graph__node--blur", true)
      .attr("width", v.Width)
      .attr("height", v.Height);
    const f = this.generateFilterID(name, "blur");
    rect
      .on("mouseover", function () { rect.attr("filter", "url(#" + f + ")"); })
      .on("mouseout", function () { rect.attr("filter", null); });
    this.drawLinesOfNode(v, g);
  }

  drawNodes(name, json) {
    for (let i = 0; i < json.Nodes.length; i++) {
      this.drawNode(name, json.Nodes[i]);
    }
  }

  drawEdge(name, e) {
    this.minimap.drawEdge(e);
    const path = this.cfg.append("path")
      .classed("c-graph__edge", true)
      .classed(this.generateEdgeClass(e.Type), true)
      .datum(e.Points)
      .attr("d", this.linefunc)
      .attr("marker-end", "url(#" + this.generateArrowID(name, e.Type) + ")");
    if (e.IsBackEdge) path.attr("stroke-dasharray", "4, 4");
  }

  drawEdges(name, json) {
    for (let i = 0; i < json.Edges.length; i++) {
      this.drawEdge(name, json.Edges[i]);
    }
  }

  computeReductionRate(vpDims, graphDims) {
    const widthReduction = vpDims.cfgVPDim.width / graphDims.width;
    const heightReduction = vpDims.cfgVPDim.height / graphDims.height;
    let reductionRate = Math.min(widthReduction, heightReduction);
    // If the entire CFG is smaller than the cfgVP, then simply use the rate 1.
    // In other words, the maximum reductionRate is one.
    if (reductionRate >= 1) reductionRate = 1;
    return reductionRate;
  }

  centerAlign(reductionRate, vpDims) {
    const xshiftAmount = vpDims.cfgVPDim.width / 2 / reductionRate;
    this.cfg.attr("transform", "translate(" + xshiftAmount + ",0)");
    this.minimap.centerAlign(vpDims.minimapVPDim, reductionRate);
  }

  static onZoom(g) {
    const minimapWidth = g.minimap.stage.node().getBoundingClientRect().width;
    return function () {
      g.transK = d3.event.transform.k;
      const cfgWidth = g.stage.node().getBoundingClientRect().width;
      const ratio = minimapWidth / cfgWidth;
      const x = (- d3.event.transform.x) * ratio;
      const y = (- d3.event.transform.y) * ratio;
      const k = g.reductionRate / g.transK;
      const trans = "translate(" + x + "," + y + ") scale(" + k + ")";
      g.ratio = ratio;
      g.stage.attr("transform", d3.event.transform);
      g.minimap.viewbox.attr("transform", trans);
    };
  }

  registerPathDblClickEvents(cfgDim) {
    const myself = this;
    this.cfg.selectAll(".c-graph__edge").on("dblclick", function (pts) {
      const s = myself.transK / myself.reductionRate;
      const k = myself.transK;
      const x = - pts[pts.length - 1].X * k - (s - 1) * cfgDim.width / 2;
      const y = - pts[pts.length - 1].Y * k + cfgDim.height / 2;
      myself.svg.transition().duration(700)
        .call(myself.zoom.transform, d3.zoomIdentity.translate(x, y).scale(k));
    });
  }

  registerEvents(reductionRate, vpDims) {
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
    this.minimap.registerViewboxEvents(vpDims.minimapVPDim, this);
    this.registerPathDblClickEvents(vpDims.cfgVPDim);
  }

  draw(name, json) {
    const vpDims = computeVPDimensions(this.container);
    this.minimap.resize(vpDims.minimapVPDim);
    this.minimap.registerViewbox(vpDims.minimapVPDim);
    this.drawNodes(name, json);
    this.drawEdges(name, json);
    // Compute the actual bbox after drawing the graph.
    const graphDims = this.cfg.node().getBBox();
    this.reductionRate = this.computeReductionRate(vpDims, graphDims);
    this.centerAlign(this.reductionRate, vpDims);
    this.registerEvents(this.reductionRate, vpDims);
    this.refreshIcon.classed("rotating", false);
  }

  fetchAndDraw(name, kind) {
    const myself = this;
    query({ "q": kind, "args": name }, function (_status, json) {
      myself.json = json;
      myself.draw(name, json);
    });
  }

  moveToInitialPos() {
    this.svg.call(this.zoom.transform,
      d3.zoomIdentity.translate(0, 0).scale(this.reductionRate));
  }
}

