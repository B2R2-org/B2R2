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

class SVGDefs {
  static register(container) {
    const div = container.append("div") // Hide the SVG.
      .style("position", "absolute").style("width", 0).style("height", 0);
    const svg = div.append("svg").attr("width", 0).attr("height", 0);
    const defs = svg.append("defs");
    SVGDefs.setMarkerArrow(defs, "InterJmpEdge");
    SVGDefs.setMarkerArrow(defs, "InterCJmpTrueEdge");
    SVGDefs.setMarkerArrow(defs, "InterCJmpFalseEdge");
    SVGDefs.setMarkerArrow(defs, "IntraJmpEdge");
    SVGDefs.setMarkerArrow(defs, "IntraCJmpTrueEdge");
    SVGDefs.setMarkerArrow(defs, "IntraCJmpFalseEdge");
    SVGDefs.setMarkerArrow(defs, "FallThroughEdge");
    SVGDefs.setMarkerArrow(defs, "CallFallThroughEdge");
    SVGDefs.setMarkerArrow(defs, "RecursiveCallEdge");
    SVGDefs.setMarkerArrow(defs, "CallEdge");
    SVGDefs.setMarkerArrow(defs, "RetEdge");
    SVGDefs.setFilter(defs);
  }

  static setMarkerArrow(defs, tag) {
    defs.append("marker")
      .classed("c-arrow-" + tag.toLowerCase(), true)
      .attr("id", "js-" + tag.toLowerCase())
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

  static setFilter(defs) {
    defs.append("filter")
      .attr("id", "js-filter-blur")
      .attr("filterUnits", "userSpaceOnUse")
      .append("feGaussianBlur")
      .attr("stdDeviation", 2);
  }
}

