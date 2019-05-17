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
var bottomMargin = 10;

// Set the right margin of the entire UI
var rightMargin = 10;

// Set the ratio between the CFG VP and the minimap VP.
var minimapRatio = 0.4;

// Set the padding size for each CFG node.
var padding = 4;

// Node border thickness.
var nodeBorderThickness = 1.5;

// Edge thickness.
var edgeThickness = 3;

// The duration time for zooming when both nodes and edges are double clicked.
var focusMovementDuration = 750;

function initMarker(defs, name) {
  let currentTabNumber = $("#id_tabContainer li.tab.active").attr("counter");
  defs.append("marker")
    .attr("id", name + "-" + currentTabNumber).attr("class", name)
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

function initSVG() {
  let currentTabNumber = $("#id_tabContainer li.tab.active").attr("counter");
  // Clear up the existing elements.
  $("#cfg-" + currentTabNumber).empty();
  $("#minimap-" + currentTabNumber).empty();
  // Create a top layer for drawing a CFG on the main window.
  d3.select("svg#cfg-" + currentTabNumber).append("g").attr("id", "cfgStage-" + currentTabNumber)
    .attr("transform", "scale (1)");

  // Create the main group for a CFG. This is to easily maintain the
  // coordinates of the main graph.
  d3.select("g#cfgStage-" + currentTabNumber).append("g").attr("id", "cfgGrp" + currentTabNumber);

  // Several definitions to use to draw a CFG.
  let defs = d3.select("g#cfgGrp" + currentTabNumber).append("defs");
  initMarker(defs, "cfgJmpEdgeArrow");
  initMarker(defs, "cfgCJmpTrueEdgeArrow");
  initMarker(defs, "cfgCJmpFalseEdgeArrow");
  initMarker(defs, "cfgFallThroughEdgeArrow");

  // Add filters.
  defs.append("filter").attr("id", "cfgBlur")
    .append("feGaussianBlur").attr("stdDeviation", 2);

  // First draw an empty background for minimap.
  d3.select("svg#minimap-" + currentTabNumber)
    .append("rect").attr("width", "100%").attr("height", "100%")
    .attr("fill", "#282a36");

  // Create a top layer for drawing a CFG on the minimap.
  d3.select("svg#minimap-" + currentTabNumber).append("g").attr("id", "minimapStage-" + currentTabNumber);
}

function initEvents(cfg) {
  $(function () {
    $("#menuCopyCFG").click(function (e) {
      e.preventDefault();
      let mymodal = $("#codeCopyCFG");
      mymodal.text(JSON.stringify(cfg, null, " "));
    });
  })

  $(function () {
    $("#btnCopyCFG").click(function (e) {
      copyToClipboard($("#codeCopyCFG").text());
    });
  })
}

function appendDisasmFragment(txt, cls, fragment, isOpcode) {
  let t = txt.append("tspan")
    .text(fragment).attr("class", cls).attr("xml:space", "preserve");

  if (isOpcode) t.attr("x", padding / 2).attr("dy", "14px");
  else t.attr("dx", "0px");
}

function strRepeat(str, num) {
  if (num < 0) return "";
  else if (num === 1) return str;
  else return str + strRepeat(str, num - 1);
}

function drawNode(idx, v) {
  const nodePaddingTop = 3;
  let currentTabNumber = $("#id_tabContainer li.tab.active").attr("counter");
  let g = d3.select("g#cfgGrp" + currentTabNumber).append("g")
    .attr("nodeid", idx)
    .attr("class", "gNode")
    .on("click", function () {
      let gcfg = $(this).parent();
      gcfg.append($(this));
    })
  let rect = g.append("rect")
    .attr("class", "cfgNode")
    .attr("fill", "white")
    .attr("stroke", "black")
    .attr("stroke-width", nodeBorderThickness)

  // Additional layer for bluring.
  let rectBlur = g.append("rect")
    .attr("class", "cfgNodeBlur")
    .attr("id", v.NodeID)
    .attr("fill", "transparent")
    .attr("stroke", "black")
    .attr("stroke-width", nodeBorderThickness);

  let i, j;
  for (i = 0; i < v.Terms.length; i++) {
    let y = i * 14 + nodePaddingTop;
    let idNum = "[NODEID]-[STMTID]".replace("[NODEID]", idx).replace("[STMTID]", i);
    let rectid = "id_" + currentTabNumber + "_rect-" + idNum;
    let textid = "id_" + currentTabNumber + "_text-" + idNum;
    let gtext = g.append("g")
      .attr("id", "id_" + currentTabNumber + "_g-" + idNum)
      .attr("class", "gstmt")
      .attr("idx", i)
      .attr("transform", "translate(0," + y + ")")

    let terms = v.Terms[i];
    let s = terms[0][0];
    let tag = terms[0][1];
    let text = gtext.append("text").attr("class", "stmt").attr("id", textid);
    let mnemonic = s + strRepeat(" ", (s.length > 8 ? 0 : 8 - s.length));
    gtext.insert("rect")
      .attr("id", rectid)
      .attr("class", "nodestmtbox")
      .attr("width", v.Width)
      .attr("y", 4)
      .attr("height", 14)
      .attr("fill", "transparent")
      .on("contextmenu", function () {
        let self = this;
        function showContextMemu() {
          const e = d3.event;
          e.preventDefault();
          $("#id_node-contextmenu")
            .css("display", "block")
            .css("top", e.clientY)
            .css("left", e.clientX)
            .attr("target", "#" + $(self).attr("id"));
        }
        showContextMemu();
      })

    appendDisasmFragment(text, "cfgDisasmText " + tag, mnemonic, true);
    if (terms.length > 2) {
      for (j = 1; j < terms.length; j++) {
        let s = terms[j][0];
        let tag = terms[j][1];
        if (j == terms.length - 2) {
          appendDisasmFragment(text, "cfgDisasmText " + tag, s, false);
        } else if (j == terms.length - 1) {
          if (s.length > 0) {
            let comment = " # " + s;
            setComment(currentTabNumber, "#" + rectid, comment, true);
          }
        } else {
          appendDisasmFragment(text, "cfgDisasmText " + tag, s, false);
          appendDisasmFragment(text, "cfgDisasmText", ",", false);
        }
      }
    }
  }

  rect.attr("width", v.Width).attr("height", v.Height);
  rectBlur.attr("width", v.Width).attr("height", v.Height);

  g.attr("transform", "translate (" + v.Pos.X + "," + v.Pos.Y + ")");

  d3.select("g#minimapStage-" + currentTabNumber).append("rect")
    .attr("miniid", idx)
    .attr("class", "minimapRects")
    .attr("rx", "1").attr("ry", "1")
    .attr("fill", "rgb(45, 53, 70)")
    .attr("stroke", "rgb(255, 255,255)")
    .attr("style", "outline: 1px solid black;")
    .attr("width", v.Width * minimapRatio)
    .attr("height", v.Height * minimapRatio)
    .attr("transform",
      "translate(" + v.Pos.X * minimapRatio +
      ", " + v.Pos.Y * minimapRatio + ")");
}

function drawNodes(g) {
  let currentTabNumber = $("#id_tabContainer li.tab.active").attr("counter");

  for (let i = 0; i < g.Nodes.length; i++) {
    drawNode(i, g.Nodes[i]);
  }

  let r = document.getElementById("cfgGrp" + currentTabNumber).getBBox(),
    obj = {
      width: r.width,
      height: r.height
    };

  return obj;
}

function drawEdge(e) {
  let currentTabNumber = $("#id_tabContainer li.tab.active").attr("counter");

  let lineFunction = d3.line()
    .x(function (d) { return d.X; })
    .y(function (d) { return d.Y; });

  lineFunction.curve(d3.curveMonotoneY);

  // Additional line for bluring.
  d3.select("g#cfgGrp" + currentTabNumber).insert("path", ":first-child")
    .attr("class", "cfg" + e.Type + "Blur" + " cfgEdgeBlur")
    .attr("d", lineFunction(e.Points))
    .attr("stroke", "transparent")
    .attr("stroke-width", edgeThickness)
    .attr("fill", "none");

  let p = d3.select("g#cfgGrp" + currentTabNumber).insert("path", ":first-child")
    .attr("class", "cfg" + e.Type)
    .attr("d", lineFunction(e.Points))
    .attr("stroke-width", edgeThickness)
    .attr("fill", "none");

  if (e.IsBackEdge) p.attr("stroke-dasharray", "4, 4");

  p.attr("marker-end", "url(#cfg" + e.Type + "Arrow-" + currentTabNumber + ")");

  let miniLineFunction = d3.line()
    .x(function (d) { return d.X * minimapRatio; })
    .y(function (d) { return d.Y * minimapRatio; })
    .curve(d3.curveLinear);

  let m = d3.select("g#minimapStage-" + currentTabNumber).insert("path", ":first-child")
    .attr("class", "cfg" + e.Type)
    .attr("d", miniLineFunction(e.Points))
    .attr("stroke-width", 0.7)
    .attr("fill", "none");

  if (e.IsBackEdge) m.attr("stroke-dasharray", "2, 2");
}

function drawEdges(g) {
  for (let i = 0; i < g.Edges.length; i++) {
    drawEdge(g.Edges[i]);
  }
}

function centerAlign(dims, shiftX, reductionRate) {
  let currentTabNumber = $("#id_tabContainer li.tab.active").attr("counter");

  let leftPadding = (dims.cfgVPDim.width) / 2 / reductionRate;

  d3.select("g#cfgGrp" + currentTabNumber).attr("transform",
    "translate(" + leftPadding + ", 0)");

  d3.select("g#minimapStage-" + currentTabNumber)
    .attr("transform",
      "translate (" + shiftX + ", 0) scale (" + reductionRate + ")");
}

function setMinimap(dims, reductionRate) {
  let currentTabNumber = $("#id_tabContainer li.tab.active").attr("counter");
  let minimapMarginRight = 20;

  let minimapWidth = document.getElementById("minimapStage-" + currentTabNumber).getBoundingClientRect().width * reductionRate;
  let minimapHeight = document.getElementById("minimapStage-" + currentTabNumber).getBoundingClientRect().height * reductionRate;

  let minimapDim = {
    width: minimapWidth < 200 ? 200 : minimapWidth,
    height: minimapHeight < 300 ? 300 : minimapHeight,
  };

  dims.minimapDim = minimapDim;

  let newWidth = dims.minimapDim.width;
  let newHeight = dims.minimapDim.height;

  // set minimap size based on the graph size.
  d3.select("svg#minimap-" + currentTabNumber)
    .attr("width", newWidth + "px").attr("height", newHeight + "px");

  // set size of the minimap nodes.
  let nodeSize = Math.ceil(Math.log(newWidth / 1000) / Math.log(2));
  if (nodeSize <= 0) nodeSize = 1;

  let nodes = d3.select("g#minimapStage-" + currentTabNumber).selectAll(".minimapRects");
  nodes.attr("style", "outline: " + nodeSize + "px" + " solid black;");

  $("#minimapDiv").css("margin-right", minimapMarginRight + "px");
  $("#minimapDiv").css("margin-bottom", bottomMargin + "px");
  $("#minimapDiv").css("padding-top", "20px");

  return dims
}

function drawMinimapViewPort(dims) {
  let currentTabNumber = $("#id_tabContainer li.tab.active").attr("counter");

  d3.select("svg#minimap-" + currentTabNumber)
    .append("rect")
    .attr("id", "minimapVP-" + currentTabNumber)
    .attr("width", (dims.minimapVPDim.width - 2) + "px")
    .attr("height", (dims.minimapVPDim.height - 2) + "px")
    .attr("fill", "transparent")
    .attr("stroke-width", "0.5")
    .attr("stroke", "white");
}

function drawCFG(dims, cfg) {
  $("#icon-refresh").addClass("rotating"); // Start the animation.
  // This is to make sure that the rotation animation is running first.
  setTimeout(function () { drawCFGAux(dims, cfg); }, 5);
  autocomplete(cfg);
}

function drawCFGAux(dims, cfg) {
  let extraRatio = 0.9, // Give a little bit more space.
    stageDim = null,
    reductionRate;

  initSVG();
  initEvents(cfg);

  stageDim = drawNodes(cfg);
  drawEdges(cfg);

  reductionRate =
    Math.min(dims.cfgVPDim.width / stageDim.width,
      dims.cfgVPDim.height / stageDim.height) * extraRatio;

  // If the entire CFG is smaller than the cfgVP, then simply use the rate 1.
  // In other words, the maximum reductionRate is one.
  if (reductionRate >= 1) reductionRate = 1;

  dims = setMinimap(dims, reductionRate);
  centerAlign(dims, dims.minimapDim.width / 2, reductionRate);
  drawMinimapViewPort(dims);
  registerEvents(reductionRate, dims, cfg);
  $("#icon-refresh").removeClass("rotating"); // Stop the animation.
}

function registerEvents(reductionRate, dims, g) {
  let currentTabNumber = $("#id_tabContainer li.tab.active").attr("counter");
  let zoom = null;
  let translateWidthRatio = null;
  let translateHeightRatio = null;
  let offsetX = null;
  let offsetY = null;
  let inverseK = reductionRate;
  let transX = 0;
  let transY = 0;
  let transK = 1 / reductionRate;

  let cfg = d3.select("svg#cfg-" + currentTabNumber);
  let cfgStage = d3.select("g#cfgStage-" + currentTabNumber);
  let minimap = d3.select("svg#minimap-" + currentTabNumber);
  let minimapVP = d3.select("rect#minimapVP-" + currentTabNumber);
  let nodes = cfgStage.selectAll(".cfgNodeBlur");
  let edges = cfgStage.selectAll(".cfgEdgeBlur");
  let texts = cfgStage.selectAll(".cfgDisasmText");

  function getEdgePts(edge) {
    return edge.split(/M|L/)
      .filter(function (el) { return el.length != 0; });
  }

  function convertvMapPtToVPCoordinate(dx, dy) {
    let currentTabNumber = $("#id_tabContainer li.tab.active").attr("counter");
    let miniVPBound =
      document.getElementById("minimapVP-" + currentTabNumber).getBoundingClientRect();
    let viewportBound =
      document.getElementById("cfgStage-" + currentTabNumber).getBoundingClientRect();
    let minimapBound =
      document.getElementById("minimapStage-" + currentTabNumber).getBoundingClientRect();

    translateWidthRatio = minimapBound.width / viewportBound.width;
    translateHeightRatio = minimapBound.height / viewportBound.height;

    let widthRatio = minimapRatio / translateWidthRatio;
    let halfWidth = miniVPBound.width / minimapRatio / 2;

    return { x: dx + halfWidth * widthRatio, y: dy };
  }


  function getPointFromEdgePts(edgePts, index) {
    let lastPts = edgePts[index].split(",");
    let lastX = parseFloat(lastPts[lastPts.length - 2]) * reductionRate;
    let lastY = parseFloat(lastPts[lastPts.length - 1]) * reductionRate;

    return { x: lastX, y: lastY };
  }

  function toCenter(dx, dy, accelerationRate) {
    let currentTabNumber = $("#id_tabContainer li.tab.active").attr("counter");
    let miniVPBound =
      document.getElementById("minimapVP-" + currentTabNumber).getBoundingClientRect();
    let viewportBound =
      document.getElementById("cfgStage-" + currentTabNumber).getBoundingClientRect();
    let minimapBound =
      document.getElementById("minimapStage-" + currentTabNumber).getBoundingClientRect();

    translateWidthRatio = minimapBound.width / viewportBound.width;
    translateHeightRatio = minimapBound.height / viewportBound.height;

    let widthRatio = minimapRatio / translateWidthRatio;
    let heightRatio = minimapRatio / translateHeightRatio;

    let halfWidth = miniVPBound.width / minimapRatio / 2;
    let halfHeight = miniVPBound.height / minimapRatio / 2;
    let newX = (halfWidth - dx) * widthRatio;
    let newY = (halfHeight - dy) * heightRatio;

    cfg.transition()
      .duration(focusMovementDuration * accelerationRate)
      .call(zoom.transform,
        d3.zoomIdentity.translate(newX, newY).scale(transK));
  }

  function getMousePos() {
    let mouse = d3.mouse(document.getElementById("cfgStage-" + currentTabNumber));

    return { x: mouse[0] * reductionRate, y: mouse[1] * reductionRate }
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
      let vMapLastPt = convertvMapPtToVPCoordinate(lastPt.x, lastPt.y);
      let mousePt = getMousePos();

      let acceleration = getAccelerationRate(vMapLastPt, mousePt);

      // As b2r2.css has .glyphicon { padding-right: 5px; }, which is used
      // when dims are generated at reloadUI(), 5px plus to vMapPt.x
      // has to be considered as long as the padding has been maintained.
      toCenter(vMapLastPt.x + 5, vMapLastPt.y, acceleration);
    });
  });

  nodes.each(function (d, i) {
    d3.select(this).on("click", function () {
      let rect = $(".cfgNode")[i];
      if (rect.classList.contains("nodeHighlight")) {
        d3.select(rect).classed("nodeHighlight", false);
      } else {
        $(".cfgNode").removeClass("nodeHighlight");
        d3.select(rect).classed("nodeHighlight", true);
      }
    });
  });

  nodes.each(function (d, i) {
    d3.select(this).on("dblclick", function () {
      let id = d3.select(this).attr("id");
      let x = g.Nodes[Number(id)].Pos.X * reductionRate;
      let y = g.Nodes[Number(id)].Pos.Y * reductionRate;
      let vMapPt = convertvMapPtToVPCoordinate(x, y);
      let halfHeight = d3.select(this).attr("height") / 2 * reductionRate;

      toCenter(vMapPt.x + 5, vMapPt.y + halfHeight, 100);
    });

  });

  texts.on("click", function () {
    // Remove all highlights for cfgDisasmText
    $(".cfgDisasmText").removeClass("wordHighlight");
    let clsName = d3.select(this).attr("class").split(" ")[1];
    // Only highlights with "clsName"
    // XXX: later we should change false to true
    texts.filter("." + clsName).classed("wordHighlight", false);
  });

  function getEventPointFromMinimap(event) {
    let svgSource = document.getElementById("minimap-" + currentTabNumber);
    let viewerPoint = svgSource.createSVGPoint();

    viewerPoint.x = event.clientX;
    viewerPoint.y = event.clientY;

    return viewerPoint.matrixTransform(svgSource.getScreenCTM().inverse());
  }

  function jumpToCursor() {
    let centerPoint = getEventPointFromMinimap(d3.event.sourceEvent);
    let minimapX = centerPoint.x - offsetX - (dims.minimapDim.width - dims.minimapVPDim.width) / 2;
    let minimapY = centerPoint.y - offsetY;
    let minimapK = reductionRate * inverseK;

    offsetX = (dims.minimapVPDim.width * minimapK) / 2;
    offsetY = (dims.minimapVPDim.height * minimapK) / 2;
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
    let currentTabNumber = $("#id_tabContainer li.tab.active").attr("counter");
    let evt = d3.event.sourceEvent;
    let vp = document.getElementById("minimapVP-" + currentTabNumber).getBoundingClientRect();

    offsetX = evt.clientX - vp.left;
    offsetY = evt.clientY - vp.top;
  }

  function dragMove() {
    let mouseSVGPoint = getEventPointFromMinimap(d3.event.sourceEvent);
    let minimapX = mouseSVGPoint.x - offsetX - (dims.minimapDim.width - dims.minimapVPDim.width) / 2;
    let minimapY = mouseSVGPoint.y - offsetY;
    let minimapK = reductionRate * inverseK;

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
    document.getElementById("minimap-" + currentTabNumber).style.cursor = "default";
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

  document.getElementById("cfg-" + currentTabNumber)
    .addEventListener("mousemove", (function () { /*empty*/ }).bind(this));

  function zoomed() {
    let currentTabNumber = $("#id_tabContainer li.tab.active").attr("counter");
    let minimapBound =
      document.getElementById("minimapStage-" + currentTabNumber).getBoundingClientRect();
    let viewportBound =
      document.getElementById("cfgStage-" + currentTabNumber).getBoundingClientRect();

    cfgStage.attr("transform", d3.event.transform);

    transX = d3.event.transform.x;
    transY = d3.event.transform.y;
    transK = d3.event.transform.k;

    inverseK = 1 / transK;
    let minimapK = reductionRate * inverseK;

    translateWidthRatio = minimapBound.width / viewportBound.width;
    translateHeightRatio = minimapBound.height / viewportBound.height;

    transX = (- transX) * translateWidthRatio + (dims.minimapDim.width - dims.minimapVPDim.width) / 2;
    transY = (- transY) * translateHeightRatio;

    minimapVP.attr("transform",
      "translate(" + transX + ","
      + transY + ") scale(" + minimapK + ")")
      .attr("style", "stroke-width:" + (1.5 / (minimapK)) + "px");
  }

  $(document).on("click", ".autocomplete-item", function () {
    if (currentTabNumber === $("#id_tabContainer li.tab.active").attr("counter")) {
      let target = $(this).attr("target");
      let rect = d3.select(target);
      let width = rect.attr("width");
      let gNode = d3.select(rect.node().parentNode.parentNode);
      let idx = parseInt($(this).attr("idx"));
      let pos = gNode.attr("transform")
        .split("translate")[1].split("(")[1].split(")")[0].split(",");
      let x = (parseFloat(pos[0]) + width / 2) * reductionRate;;
      let y = (parseFloat(pos[1]) + idx * 14) * reductionRate;
      let vMapPt = convertvMapPtToVPCoordinate(x, y);
      toCenter(parseFloat(vMapPt.x), parseFloat(vMapPt.y), 1);
    }
  });

  $(document).on("click", ".comment-content", function () {
    if (currentTabNumber === $("#id_tabContainer li.tab.active").attr("counter")) {
      // #id_tabid_[element-type]_nodeidx_idx
      let $self = $(this);
      let tabid = $self.attr("target").split("_")[1];
      let tab = $("#id_tabContainer li[counter=" + tabid + "]");
      if (tab.length > 0) {
        function getData() {
          return new Promise(function (resolve, reject) {
            activateTab(tab, resolve);
          });
        }
        getData().then(function (data) {
          let rectid = $self.attr("target").replace("_g_comment-", "_rect-");
          let rect = d3.select(rectid);
          $(".stmtHighlight").removeClass("stmtHighlight");
          rect.attr("class", "nodestmtbox stmtHighlight")
            .on("click", function () {
              $(this).removeClass("stmtHighlight");
            });
          let width = rect.attr("width");
          let gNode = d3.select(rect.node().parentNode.parentNode);
          let gidx = parseInt(d3.select(rect.node().parentNode).attr("idx"));
          let pos = gNode.attr("transform")
            .split("translate")[1].split("(")[1].split(")")[0].split(",");

          let x = (parseFloat(pos[0]) + width / 2) * reductionRate;
          let y = (parseFloat(pos[1]) + gidx * 14) * reductionRate;

          let vMapPt = convertvMapPtToVPCoordinate(x, y);
          toCenter(parseFloat(vMapPt.x), parseFloat(vMapPt.y), 1);
        }).catch(function (err) {
          console.error(err); // Error 출력
        });
      } else {

      }

    }
  });


  zoom = d3.zoom().scaleExtent([reductionRate, 20]).on("zoom", zoomed);
  let transform = d3.zoomIdentity.translate(0, 0).scale(reductionRate);
  cfg.call(zoom).call(zoom.transform, transform).on("dblclick.zoom", null);
}

function registerRefreshEvents() {
  $("#id_btn-refresh").click(function () {
    query({
      "q": "cfg-disasm",
      "args": $("#uiFuncName").text()
    },
      function (json) {
        if (!isEmpty(json)) {
          let dims = reloadUI();
          drawCFG(dims, json);
        }
      });
  });
}

function draggableMinimap() {
  let $minimapHandler = $("#minimapDiv .move-minimap")
  let $minimapContainer = $("#minimapDiv")
  var dragging = false;
  var iX, iY;
  $minimapHandler.mousedown(function (e) {
    let minimapContainer = document.getElementById("minimapDiv");
    dragging = true;
    iX = e.clientX - minimapContainer.offsetLeft;
    iY = e.clientY - minimapContainer.offsetTop;
    minimapContainer.setCapture && minimapContainer.setCapture();
    return false;
  });
  document.onmousemove = function (e) {
    if (dragging) {
      var e = e || window.event;
      var oX = e.clientX - iX;
      var oY = e.clientY - iY;
      $minimapContainer.css({ "left": oX + "px", "top": oY + "px" });
      return false;
    }
  };
  $(document).mouseup(function (e) {
    dragging = false;
  });
}

function returnInitPositionMinimap() {
  $("#minimapDiv .return-minimap").on("click", function () {
    let $minimapContainer = $("#minimapDiv")
    $minimapContainer.css({ "left": "", "top": "" });
    $minimapContainer.css({ "right": "0", "bottom": "0" });
  });
}

function resizeMinimap() {
  $(".resize-minimap").on("click", function () {
    if ($(this).hasClass("minimize-minimap")) {
      $("#minimapDiv").addClass("active");
      d3.selectAll(".min-box")
        .style("border", "unset")
        .style("height", "0")
    } else {
      $("#minimapDiv").removeClass("active");
      d3.selectAll(".min-box")
        .style("height", "initial")
        .style("border", "1px solid #ccc")
    }
  });
}

function registerMinimapEvents() {
  draggableMinimap();
  resizeMinimap();
  returnInitPositionMinimap();
}

function isEmpty(obj) {
  for (var key in obj) {
    if (obj.hasOwnProperty(key))
      return false;
  }
  return true;
}
