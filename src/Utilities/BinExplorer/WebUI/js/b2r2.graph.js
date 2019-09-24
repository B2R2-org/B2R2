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

// Set the bottom margin of the entire UI
const bottomMargin = 10;

// Set the right margin of the entire UI
const rightMargin = 20;

// Set the ratio between the CFG VP and the minimap VP.
const minimapRatio = 0.4;

// Set the padding size for each CFG node.
const padding = 4;

// Node border thickness.
const nodeBorderThickness = 1.5;

// Edge thickness.
const edgeThickness = 3;

// The duration time for zooming when both nodes and edges are double clicked.
const focusMovementDuration = 750;

const nodePaddingTop = 3;

const minimapMarginRight = 20;

// Each line (statement) in a node.
class LineOfNode {
  constructor(d) {
    this.graphinfo = d.graphinfo;
    this.text = d.text;
    this.class = d.class;
    this.id = d.id;
    this.idx = d.idx;
    this.node = d.node;
    this.terms = d.terms;
    this.y = d.y;
    this.idNum = d.idNum;
    this.comment = d.comment;
    this.width = d.width;
  }

  init() {

  }

  add() {
    let rectid = "id_" + this.graphinfo.tab + "_rect-" + this.idNum;
    let textid = "id_" + this.graphinfo.tab + "_text-" + this.idNum;

    let gtext = this.node.append("g")
      .attr("id", "id_" + this.graphinfo.tab + "_g-" + this.idNum)
      .attr("class", "gstmt")
      .attr("idx", this.idx)
      .attr("transform", "translate(0," + this.y + ")");

    let text = gtext.append("text").attr("class", "stmt").attr("id", textid);
    let contextMenuRect = gtext.insert("rect")
      .attr("id", rectid)
      .attr("class", "nodestmtbox")
      .attr("width", this.width)
      .attr("y", 4)
      .attr("height", 14)
      .attr("fill", "transparent");

    this.setContextMenuEventOnStmt(contextMenuRect);

    for (let i = 0; i < this.terms.length; i++) {
      let s = this.terms[i][0];
      let tag = this.terms[i][1];

      this.appendDisasmFragment(i, text, "cfgDisasmText " + tag, s);
    }
  }

  appendDisasmFragment(i, txt, cls, fragment) {
    let t = txt.append("tspan")
      .text(fragment).attr("class", cls).attr("xml:space", "preserve");

    if (i == 0) t.attr("x", padding / 2).attr("dy", "14px");
    else t.attr("dx", "1px");
  }

  setContextMenuEventOnStmt(rect) {
    let contextmenu = this.graphinfo.contextmenu;
    rect.on("contextmenu", function () {
      let self = this;
      function showContextMemu() {
        const e = d3.event;
        e.preventDefault();
        contextmenu.show(self, e.clientX, e.clientY);
      }
      showContextMemu();
    })
  }
}

class Node {
  constructor(d) {
    this.graphinfo = d.graphinfo;
    this.terms = d.terms;
    this.idx = d.idx;
    this.x = d.x;
    this.y = d.y;
    this.width = d.width;
    this.height = d.height;
    this.addr = d.addr;
  }

  getNodeindex() {

  }

  addAux(g) {
    // Additional layer for bluring.
    let rectBlur = g.append("rect")
      .attr("class", "cfgNodeBlur")
      .attr("fill", "transparent")
      .attr("stroke", "black")
      .attr("stroke-width", nodeBorderThickness);

    rectBlur.attr("width", this.width).attr("height", this.height);
  }

  add() {
    let g = this.graphinfo.document.select(this.graphinfo.group).append("g")
      .attr("nodeid", this.idx)
      .attr("addr", this.addr)
      .attr("class", "gNode")
      .attr("transform", "translate (" + this.x + "," + this.y + ")");

    let rect = g.append("rect")
      .attr("class", "cfgNode")
      .attr("fill", "white")
      .attr("stroke", "black")
      .attr("stroke-width", nodeBorderThickness)
      .attr("width", this.width)
      .attr("height", this.height);

    this.addAux(g);

    for (let i = 0; i < this.terms.length; i++) {
      new LineOfNode({
        graphinfo: this.graphinfo,
        node: g,
        idx: i,
        text: "",
        terms: this.terms[i],
        idNum: "[NODEID]-[LINEID]".replace("[NODEID]", this.idx).replace("[LINEID]", i),
        y: i * 14 + nodePaddingTop,
        width: this.width
      }).add();
    }
  }
}

class Edge {
  constructor(d) {
    this.graphinfo = d.graphinfo;
    this.type = d.type;
    this.points = d.points;
    this.isBackEdge = d.IsBackEdge;
  }

  add() {
    let lineFunction = d3.line()
      .x(function (d) { return d.X; })
      .y(function (d) { return d.Y; })
      .curve(d3.curveMonotoneY);

    // Additional line for bluring.
    this.graphinfo.document.select(this.graphinfo.group).insert("path", ":first-child")
      .attr("class", "cfg" + this.type + "Blur cfgEdgeBlur")
      .attr("d", lineFunction(this.points))
      .attr("stroke", "transparent")
      .attr("stroke-width", edgeThickness)
      .attr("fill", "none");

    let p = this.graphinfo.document.select(this.graphinfo.group).insert("path", ":first-child")
      .attr("class", "cfg" + this.type)
      .attr("d", lineFunction(this.points))
      .attr("stroke-width", edgeThickness)
      .attr("fill", "none");

    if (this.isBackEdge) p.attr("stroke-dasharray", "4, 4");

    p.attr("marker-end", "url(#cfg" + this.type + "Arrow-" + this.graphinfo.tab + ")");

    if (this.isBackEdge) m.attr("stroke-dasharray", "2, 2");
  }
}

class MiniNode {
  constructor(d) {
    this.graphinfo = d.graphinfo;
    this.idx = d.idx;
    this.x = d.x;
    this.y = d.y;
    this.width = d.width;
    this.height = d.height;
    this.class = "minimapRects";
  }

  add() {
    this.graphinfo.document.select(this.graphinfo.minimapStage)
      .append("g")
      .attr("miniid", this.idx)
      .attr("transform",
        "translate(" + this.x +
        ", " + this.y + ")")
      .append("rect")
      .attr("class", this.class)
      .attr("rx", "1").attr("ry", "1")
      .attr("fill", "rgb(45, 53, 70)")
      .attr("stroke", "rgb(255, 255,255)")
      .attr("style", "outline: 1px solid black;")
      .attr("width", this.width)
      .attr("height", this.height);
  }
}

class MiniEdge {
  constructor(d) {
    this.graphinfo = d.graphinfo;
    this.type = d.type;
    this.points = d.points;
  }

  add() {
    let miniLineFunction = d3.line()
      .x(function (d) { return d.X * minimapRatio; })
      .y(function (d) { return d.Y * minimapRatio; })
      .curve(d3.curveLinear);

    let m = this.graphinfo.document.select(this.graphinfo.minimapStage).insert("path", ":first-child")
      .attr("class", "cfg" + this.type)
      .attr("d", miniLineFunction(this.points))
      .attr("stroke-width", 0.7)
      .attr("fill", "none");
  }
}

class MiniFlowGraph {
  constructor(d) {
    this.graphinfo = d.graphinfo;
  }

  draw() {
    const miniBox = this.graphinfo.document.node().querySelector(this.graphinfo.minimapStage).getBoundingClientRect();

    let minimapWidth = miniBox.width * this.graphinfo.reductionRate;
    let minimapHeight = miniBox.height * this.graphinfo.reductionRate;

    let minimapDim = {
      width: minimapWidth < 200 ? 200 : minimapWidth,
      height: minimapHeight < 300 ? 300 : minimapHeight,
    };


    this.graphinfo.dims.minimapDim = minimapDim;

    let newWidth = this.graphinfo.dims.minimapDim.width;
    let newHeight = this.graphinfo.dims.minimapDim.height;

    // set minimap size based on the graph size.
    this.graphinfo.document.select(this.graphinfo.minimap)
      .attr("width", newWidth + "px").attr("height", newHeight + "px");

    // set size of the minimap nodes.
    let nodeSize = Math.ceil(Math.log(newWidth / 1000) / Math.log(2));
    if (nodeSize <= 0) nodeSize = 1;

    let nodes = this.graphinfo.document.select(this.graphinfo.minimapStage).selectAll(".minimapRects");
    nodes.attr("style", "outline: " + nodeSize + "px" + " solid black;");

    $(this.graphinfo.minimapContainer).css("margin-right", minimapMarginRight + "px");
    $(this.graphinfo.minimapContainer).css("margin-bottom", bottomMargin + "px");
    $(this.graphinfo.minimapContainer).css("padding-top", "20px");

    return this.graphinfo.dims;
  }
}

class FlowGraph {
  constructor(d) {
    if (!isDict(d, "flowgraph")) return;

    if (d.document === undefined)
      this.document = d3.select(document);
    else
      this.document = d3.select(d.document);

    if (d.graphContainer === undefined)
      this.graphContainer = "#id_graphContainer";
    else
      this.graphContainer = d.graphContainer;

    if (d.minimapContainer === undefined)
      this.minimapContainer = "#minimapDiv";
    else
      this.minimapContainer = d.minimapContainer;

    this.tab = d.tab;
    this.cfg = d.cfg;
    this.stage = d.stage;
    this.group = d.group;
    this.minimap = d.minimap;
    this.minimapStage = d.minimapStage;
    this.minimapViewPort = d.minimapViewPort;
    this.reductionRate = 0;
    this.dims = d.dims;
    this.json = d.json;

    if (d.contextmenu === undefined)
      this.contextmenu = Root.ContextMenu;
    else
      this.contextmenu = d.contextmenu;

    if (d.newWindow === undefined)
      this.newWindow = false;
    else
      this.newWindow = d.newWindow;
  }

  setMarkerArrow(group, name) {
    const id = name + "-" + this.tab;
    group.append("marker")
      .attr("id", id).attr("class", name)
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

  setFilter(group) {
    group.append("filter").attr("id", "cfgBlur")
      .append("feGaussianBlur").attr("stdDeviation", 2);
  }

  setDefs(defs) {
    // Several definitions to use to draw a CFG.
    this.setMarkerArrow(defs, "cfgInterJmpEdgeArrow");
    this.setMarkerArrow(defs, "cfgInterCJmpTrueEdgeArrow");
    this.setMarkerArrow(defs, "cfgInterCJmpFalseEdgeArrow");
    this.setMarkerArrow(defs, "cfgIntraJmpEdgeArrow");
    this.setMarkerArrow(defs, "cfgIntraCJmpTrueEdgeArrow");
    this.setMarkerArrow(defs, "cfgIntraCJmpFalseEdgeArrow");
    this.setMarkerArrow(defs, "cfgFallThroughEdgeArrow");
    this.setMarkerArrow(defs, "cfgCallEdgeArrow");
    this.setMarkerArrow(defs, "cfgRetEdgeArrow");

    // Add filters.
    this.setFilter(defs);
  }

  init() {
    // Clear up the existing elements.
    $(this.cfg).empty();
    $(this.minimap).empty();

    // Create a top layer for drawing a CFG on the main window.
    this.document.select(this.cfg)
      .append("g").attr("id", "cfgStage-" + this.tab)
      .attr("transform", "scale (1)");

    // Create the main group for a CFG. This is to easily maintain the
    // coordinates of the main graph.
    this.document.select(this.stage)
      .append("g").attr("id", "cfgGrp-" + this.tab);

    let defs = this.document.select(this.group).append("defs");
    this.setDefs(defs);

    // First draw an empty background for minimap.
    this.document.select(this.minimap)
      .append("rect")
      .attr("width", "100%")
      .attr("height", "100%")
      .attr("fill", "#282a36");

    // Create a top layer for drawing a CFG on the minimap.
    this.document.select(this.minimap)
      .append("g").attr("id", "minimapStage-" + this.tab);
  }

  drawNode(idx, v) {
    new MiniNode({
      graphinfo: this,
      idx: idx,
      x: v.Coordinate.X * minimapRatio,
      y: v.Coordinate.Y * minimapRatio,
      width: v.Width * minimapRatio,
      height: v.Height * minimapRatio,
      class: "minimapRects"
    }).add();

    new Node({
      graphinfo: this,
      idx: idx,
      terms: v.Terms,
      x: v.Coordinate.X,
      y: v.Coordinate.Y,
      width: v.Width,
      height: v.Height,
      addr: v.PPoint[0],
    }).add();
  }

  drawNodes() {
    for (let i = 0; i < this.json.Nodes.length; i++) {
      this.drawNode(i, this.json.Nodes[i]);
    }

    let r = this.document.node().querySelector(this.group).getBBox(),
      obj = {
        width: r.width,
        height: r.height
      };

    return obj;
  }

  drawEdge(e) {
    new Edge({
      graphinfo: this,
      type: e.Type,
      points: e.Points,
      isBackEdge: e.IsBackEdge
    }).add();

    new MiniEdge({
      graphinfo: this,
      type: e.Type,
      points: e.Points
    }).add();
  }

  drawEdges() {
    for (let i = 0; i < this.json.Edges.length; i++) {
      this.drawEdge(this.json.Edges[i]);
    }
  }
  centerAlign(self, shiftX) {
    let leftPadding = (self.dims.cfgVPDim.width) / 2 / self.reductionRate;

    self.document.select(self.group).attr("transform",
      "translate(" + leftPadding + ", 0)");

    self.document.select(self.minimapStage)
      .attr("transform",
        "translate (" + shiftX + ", 0) scale (" + self.reductionRate + ")");
  }

  drawGraphAux() {

    function drawMinimapViewPort(self) {
      self.document.select(self.minimap)
        .append("rect")
        .attr("id", "minimapVP-" + self.tab)
        .attr("width", (self.dims.minimapVPDim.width - 2) + "px")
        .attr("height", (self.dims.minimapVPDim.height - 2) + "px")
        .attr("fill", "transparent")
        .attr("stroke-width", "0.5")
        .attr("stroke", "white");
    }

    let extraRatio = 0.9, // Give a little bit more space.
      stageDim = null;

    this.init();
    stageDim = this.drawNodes();
    this.drawEdges();

    this.reductionRate =
      Math.min(this.dims.cfgVPDim.width / stageDim.width,
        this.dims.cfgVPDim.height / stageDim.height) * extraRatio;

    // If the entire CFG is smaller than the cfgVP, then simply use the rate 1.
    // In other words, the maximum reductionRate is one.
    if (this.reductionRate >= 1) this.reductionRate = 1;

    this.dims = new MiniFlowGraph({
      graphinfo: this,
    }).draw();

    this.centerAlign(this, this.dims.minimapDim.width / 2);
    drawMinimapViewPort(this);
    this.registerEvents();
    $("#icon-refresh").removeClass("rotating"); // Stop the animation.
  }

  resize(dims) {
    this.dims = dims;
    this.dims = new MiniFlowGraph({
      graphinfo: this,
    }).draw();

    this.centerAlign(this, this.dims.minimapDim.width / 2);
    d3.select(this.cfg)
      .attr("width", this.dims.cfgVPDim.width)
      .attr("height", this.dims.cfgVPDim.height);
    d3.select(this.minimapViewPort)
      .attr("width", this.dims.minimapVPDim.width)
      .attr("height", this.dims.minimapVPDim.height);
    Root.AutoComplete.reload(this);
  }

  drawGraph() {
    $("#icon-refresh").addClass("rotating"); // Start the animation.
    // This is to make sure that the rotation animation is running first.
    //setTimeout(function () { this.drawGraphAux(dims, cfg); }, 5);
    this.drawGraphAux();
  }

  registerEvents() {
    let self = this;
    let translateWidthRatio = null;
    let translateHeightRatio = null;
    let offsetX = null;
    let offsetY = null;
    let inverseK = this.reductionRate;
    let transX = 0;
    let transY = 0;
    let transK = 1 / this.reductionRate;

    let cfg = this.document.select(this.cfg);
    let cfgStage = this.document.select(this.stage);
    let minimap = this.document.select(this.minimap);
    let minimapVP = this.document.select(this.minimapViewPort);

    let edges = cfgStage.selectAll(".cfgEdgeBlur");
    let zoom = null;


    function getEdgePts(edge) {
      return edge.split(/M|L/)
        .filter(function (el) { return el.length != 0; });
    }

    function getPointFromEdgePts(edgePts, index) {
      let lastPts = edgePts[index].split(",");
      let lastX = parseFloat(lastPts[lastPts.length - 2]) * self.reductionRate;
      let lastY = parseFloat(lastPts[lastPts.length - 1]) * self.reductionRate;

      return { x: lastX, y: lastY };
    }

    function getMousePos() {
      let mouse = d3.mouse(self.document.node().querySelector(self.stage));

      return { x: mouse[0] * self.reductionRate, y: mouse[1] * self.reductionRate }
    }

    // Returns an integer from 1.0 to 2.0 depending on the length.
    function getAccelerationRate(lastPt, mousePt) {
      let xpow = Math.pow(lastPt.x - mousePt.x, 2);
      let ypow = Math.pow(lastPt.y - mousePt.y, 2);
      let currentLength = Math.sqrt(xpow + ypow);
      let r = currentLength / (100 + currentLength) + 1.0;
      return r;
    }

    edges.each(function (d, i) {
      d3.select(this).on("dblclick", function () {
        let edge = d3.select(this).attr("d");
        let edgePts = getEdgePts(edge);
        let lastPt = getPointFromEdgePts(edgePts, edgePts.length - 1);
        let vMapLastPt = convertvMapPtToVPCoordinate({
          tab: self.tab,
          document: self.document.node()
        }, lastPt.x, lastPt.y);
        let mousePt = getMousePos();

        let acceleration = getAccelerationRate(vMapLastPt, mousePt);

        // As b2r2.css has .glyphicon { padding-right: 5px; }, which is used
        // when dims are generated at reloadUI(), 5px plus to vMapPt.x
        // has to be considered as long as the padding has been maintained.
        toCenter({
          tab: self.tab,
          document: self.document.node()
        }, vMapLastPt.x + 5, vMapLastPt.y, zoom, transK, focusMovementDuration * acceleration);
      });
    });

    $(self.document.node()).on("click", ".cfgNodeBlur", function () {
      let $rect = $(this).prev();
      $rect.toggleClass("nodeHighlight");
    });

    function getEventPointFromMinimap(event) {
      let svgSource = self.document.node().querySelector(self.minimap);
      let viewerPoint = svgSource.createSVGPoint();

      viewerPoint.x = event.clientX;
      viewerPoint.y = event.clientY;

      return viewerPoint.matrixTransform(svgSource.getScreenCTM().inverse());
    }

    function jumpToCursor() {
      let centerPoint = getEventPointFromMinimap(d3.event.sourceEvent);
      let minimapX = centerPoint.x - offsetX - (self.dims.minimapDim.width - self.dims.minimapVPDim.width) / 2;
      let minimapY = centerPoint.y - offsetY;
      let minimapK = self.reductionRate * inverseK;

      offsetX = (self.dims.minimapVPDim.width * minimapK) / 2;
      offsetY = (self.dims.minimapVPDim.height * minimapK) / 2;
      minimapVP.attr("transform",
        "translate(" + minimapX + ","
        + minimapY + ") scale(" + minimapK + ")");

      transX = - minimapX / translateWidthRatio;
      transY = - minimapY / translateHeightRatio;
      cfgStage.attr("transform",
        "translate(" + transX + ","
        + transY + ") scale(" + transK + ")");

      zoom.transform(cfg,
        d3.zoomIdentity.translate(transX, transY).scale(transK));
    }

    function dragStart() {
      let evt = d3.event.sourceEvent;
      let vp = self.document.node().querySelector(self.minimapViewPort).getBoundingClientRect();

      offsetX = evt.clientX - vp.left;
      offsetY = evt.clientY - vp.top;
    }

    function dragMove() {
      let mouseSVGPoint = getEventPointFromMinimap(d3.event.sourceEvent);
      let minimapX = mouseSVGPoint.x - offsetX - (self.dims.minimapDim.width - self.dims.minimapVPDim.width) / 2;
      let minimapY = mouseSVGPoint.y - offsetY;
      let minimapK = self.reductionRate * inverseK;

      transX = - minimapX / translateWidthRatio;
      transY = - minimapY / translateHeightRatio;
      minimapVP.attr("transform",
        "translate(" + minimapX + ","
        + minimapY + ") scale(" + minimapK + ")");
      cfgStage.attr("transform",
        "translate(" + transX + ","
        + transY + ") scale(" + transK + ")");
      zoom.transform(cfg,
        d3.zoomIdentity.translate(transX, transY).scale(transK));
    }

    function dragEnd() {
      self.document.node().querySelector(self.minimap).style.cursor = "default";
    }

    let dragBehavior = d3.drag()
      .on("start", dragStart)
      .on("drag", dragMove)
      .on("end", dragEnd);

    minimapVP.call(dragBehavior);

    let clickAndDrag = d3.drag()
      .on("start", jumpToCursor)
      .on("drag", dragMove)
      .on("end", dragEnd);

    minimap.call(clickAndDrag);

    function zoomed() {
      let minimapBound = self.document.node().querySelector(self.minimapStage).getBoundingClientRect();
      let viewportBound = self.document.node().querySelector(self.stage).getBoundingClientRect();

      cfgStage.attr("transform", d3.event.transform);

      transX = d3.event.transform.x;
      transY = d3.event.transform.y;
      transK = d3.event.transform.k;

      inverseK = 1 / transK;
      let minimapK = self.reductionRate * inverseK;

      translateWidthRatio = minimapBound.width / viewportBound.width;
      translateHeightRatio = minimapBound.height / viewportBound.height;

      transX = (- transX) * translateWidthRatio + (self.dims.minimapDim.width - self.dims.minimapVPDim.width) / 2;
      transY = (- transY) * translateHeightRatio;

      minimapVP.attr("transform",
        "translate(" + transX + ","
        + transY + ") scale(" + minimapK + ")")
        .attr("style", "stroke-width:" + (1.5 / (minimapK)) + "px");
    }
    $(self.document.node()).on("click", ".autocomplete-item", function () {
      if (self.newWindow || self.tab === parseInt($(Root.TabList.id + " li.tab.active").attr("counter"))) {
        let target = $(this).attr("target");
        let rect = self.document.select(target);
        let width = rect.attr("width");
        let gNode = d3.select(rect.node().parentNode.parentNode);
        let idx = parseInt($(this).attr("idx"));
        let pos = getGroupPos(gNode.attr("transform"));
        let x = (pos[0] + width / 2) * self.reductionRate;;
        let y = (pos[1] + idx * 14) * self.reductionRate;
        let vMapPt = convertvMapPtToVPCoordinate({
          tab: self.tab,
          document: self.document.node()
        }, x, y);
        toCenter({
          tab: self.tab,
          document: self.document.node()
        }, parseFloat(vMapPt.x), parseFloat(vMapPt.y), zoom, transK, focusMovementDuration);
      }
    });

    zoom = d3.zoom().scaleExtent([this.reductionRate, 5]).on("zoom", zoomed);
    let transform = d3.zoomIdentity.translate(0, 0).scale(self.reductionRate);
    cfg.call(zoom).call(zoom.transform, transform).on("dblclick.zoom", null);
  }
}
