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

class Minimap {
  constructor(div, parent) {
    this.parent = parent;
    this.dim = null; // Dimensional information will be updated by resize.
    this.div = div.append("div").classed("c-minimap", true);
    this.topper = this.div.append("div").classed("l-minimap-topper", true);
    this.makeIcons();
    this.registerDragHandle();
    this.graph = this.div.append("div").classed("l-minimap-graph", true);
    this.svg = this.graph.append("svg");
    this.stage = this.svg.append("g");
    this.linefunc = d3.line()
      .x(function (d) { return d.X * minimapRatio; })
      .y(function (d) { return d.Y * minimapRatio; })
      .curve(d3.curveLinear);
  }

  minimize() {
    this.div.style("width", "76px").style("height", "22px");
    this.graph.style("display", "none");
  }

  maximize() {
    this.div.style("width", null).style("height", null);
    this.graph.style("display", "block");
  }

  initpos() {
    this.parent.moveToInitialPos();
  }

  makeIcon(name, icon, desc) {
    return this.topper.append("span")
      .classed("c-minimap__" + name, true)
      .classed("glyphicon", true)
      .classed(icon, true)
      .attr("title", desc);
  }

  makeIcons() {
    const myself = this;
    this.makeIcon("min", "glyphicon-triangle-bottom", "Minimize")
      .on("click", function () { myself.minimize(); });
    this.makeIcon("recover", "glyphicon-triangle-top", "Maximize")
      .on("click", function () { myself.maximize(); });
    this.makeIcon("init", "glyphicon-record", "Move to the init position")
      .on("click", function () { myself.initpos(); });
    this.makeIcon("move", "glyphicon-move", "Move minimap")
      .attr("id", "js-minimap-movehandle");
  }

  drawNode(v) {
    const x = v.Coordinate.X * minimapRatio;
    const y = v.Coordinate.Y * minimapRatio;
    this.stage.append("rect")
      .classed("c-minimap__node", true)
      .attr("rx", "1").attr("ry", "1")
      .attr("width", v.Width * minimapRatio)
      .attr("height", v.Height * minimapRatio)
      .attr("transform", "translate(" + x + "," + y + ")");
  }

  drawEdge(e) {
    const path = this.stage.append("path")
      .classed("c-minimap__edge", true)
      .datum(e.Points)
      .attr("d", this.linefunc);
    if (e.IsBackEdge) path.attr("stroke-dasharray", "2, 2");
  }

  registerViewbox(vpDim) {
    this.viewbox = this.svg.append("rect")
      .classed("c-minimap__viewbox", true)
      .attr("width", vpDim.width + "px")
      .attr("height", vpDim.height + "px");
  }

  computeMousePoint(event) {
    const svg = this.svg.node();
    let point = svg.createSVGPoint();
    point.x = event.clientX;
    point.y = event.clientY;
    return point.matrixTransform(svg.getScreenCTM().inverse());
  }

  registerViewboxEvents(vpDim, srcgraph) {
    let offsetX = 0, offsetY = 0;
    const myself = this;
    const viewbox = this.viewbox;
    const mydrag = function () {
      const point = myself.computeMousePoint(d3.event.sourceEvent);
      const mx = point.x - offsetX;
      const my = point.y - offsetY;
      const mk = srcgraph.reductionRate / srcgraph.transK;
      const mtrans = "translate(" + mx + "," + my + ") scale(" + mk + ")";
      const x = - mx / srcgraph.ratio;
      const y = - my / srcgraph.ratio;
      const k = srcgraph.transK;
      const trans = "translate(" + x + "," + y + ") scale(" + k + ")";
      viewbox.attr("transform", mtrans);
      srcgraph.stage.attr("transform", trans);
      srcgraph.zoom.transform(srcgraph.svg,
        d3.zoomIdentity.translate(x, y).scale(k));
    };
    const dragOnViewbox = d3.drag()
      .on("start", function () {
        const evt = d3.event.sourceEvent;
        const box = viewbox.node().getBoundingClientRect();
        offsetX = evt.clientX - box.left;
        offsetY = evt.clientY - box.top;
      })
      .on("drag", mydrag)
      .on("end", function () {});
    viewbox.call(dragOnViewbox);
    const dragOutsideViewbox = d3.drag()
      .on("start", function () {
        const mk = srcgraph.reductionRate / srcgraph.transK;
        mydrag();
        offsetX = vpDim.width * mk / 2;
        offsetY = vpDim.height * mk / 2;
      })
      .on("drag", mydrag)
      .on("end", function () {});
    this.svg.call(dragOutsideViewbox);
  }

  resize(vpDim) {
    this.svg
      .attr("width", vpDim.width + "px")
      .attr("height", vpDim.height + "px");
    this.dim = this.div.node().getBoundingClientRect();
  }

  centerAlign(vpDim, reductionRate) {
    const xshiftAmount = vpDim.width / 2;
    this.stage
      .attr("transform",
            "translate(" + xshiftAmount + ",0) scale(" + reductionRate + ")");
  }

  registerDragHandle() {
    const myself = this;
    $(this.div.node()).draggable({
      handle: "#js-minimap-movehandle",
      drag: function (_e) {
        const div = d3.select(this);
        const box = myself.parent.svg.node().getBoundingClientRect();
        const topper = div.select(".l-minimap-topper");
        const topperHeight = topper.node().getBoundingClientRect().height;
        const bottom = box.height * (1 - minimapRatio)
          - parseFloat(div.style("top")) + topperHeight;
        const right = myself.dim.left - parseFloat(div.style("left"));
        d3.select(this)
          .style("right", right + "px")
          .style("bottom", bottom + "px");
      }
    });
  }
}

