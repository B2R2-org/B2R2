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

function isDict(d, name) {
  if (d.constructor != Object) {
    console.error("[" + name + "] " + "Parametes are not correct.");
    return false;
  }
  return true;
}

String.format = function () {
  // The string containing the format items (e.g. "{0}")
  // will and always has to be the first argument.
  var theString = arguments[0];

  // start with the second argument (i = 1)
  for (var i = 1; i < arguments.length; i++) {
    // "gm" = RegEx options for Global search (more than one instance)
    // and for Multiline search
    var regEx = new RegExp("\\{" + (i - 1) + "\\}", "gm");
    theString = theString.replace(regEx, arguments[i]);
  }

  return theString;
}

function copyToClipboard(doc, str) {
  let aux = doc.createElement("textarea");
  aux.value = str;
  doc.body.appendChild(aux);
  aux.select();
  doc.execCommand("copy");
  doc.body.removeChild(aux);
}

function popToast(type, content, seconds) {
  switch (type) {
    case "info":
      var x = document.getElementById("id_toast");
      x.className = "show";
      $(x).text(content);
      setTimeout(function () { x.className = x.className.replace("show", ""); }, seconds * 1000);
      break;
    case "alert":
      var x = document.getElementById("id_toast");
      x.className = "alert show";
      $(x).text(content);
      setTimeout(function () { x.className = x.className.replace("show", ""); }, seconds * 1000);
      break;
    default:
      break;
  }
}

function getGroupPos(transformAttr) {
  let pos = transformAttr.split("translate")[1].split("(")[1].split(")")[0].split(",");
  return pos.map(function (x) {
    return parseFloat(x);
  })
}

function query(arguments, callback) {
  function serialize(arguments) {
    var params = [];
    for (var arg in arguments)
      if (arguments.hasOwnProperty(arg)) {
        params.push(encodeURIComponent(arg) + "=" + encodeURIComponent(arguments[arg]));
      }
    return params.join("&");
  }
  let req = new XMLHttpRequest();
  let params = serialize(arguments);
  req.onreadystatechange = function () {
    // if (this.readyState == 4 && this.status == 200) { }
    if (this.readyState == 4) {
      if (this.responseText.length > 0) {
        callback(this.status, JSON.parse(this.responseText));
      } else {
        callback(this.status, this.responseText);
      }
    }
  }
  req.open("GET", "/ajax/?" + params, true);
  req.send();
}

function computeUIDimensions(doc) {
  let contentWidth = $(doc.defaultView).width();
  let mainContainer = $(doc).find(".main");
  let sidebarMenu = $(doc).find(".main__sidemenu");
  if (sidebarMenu.length > 0) {
    contentWidth -= sidebarMenu.width();
  }
  let sidebarContent = $(doc).find(".sidecontent");
  if (sidebarContent.length > 0) {
    contentWidth -= sidebarContent.width();
  }
  $(doc).find(".content-window").width(contentWidth);
  let heightGap = 0;
  let tabContainer = $(doc).find(".tab-container");
  if (tabContainer.length > 0) {
    heightGap = tabContainer.outerHeight();
  }
  let graphContainer = $(doc).find(".graph");
  let cfgVPDim = {
    width: contentWidth
      - parseInt(graphContainer.css("padding-right"))
      - rightMargin,
    height: mainContainer.outerHeight()
      - heightGap
      - bottomMargin
  }
  let minimapVPDim = {
    width: cfgVPDim.width * minimapRatio,
    height: cfgVPDim.height * minimapRatio,
  }
  $("#funcSelector").attr("style", "height: " + cfgVPDim.height + "px");
  return { cfgVPDim: cfgVPDim, minimapVPDim: minimapVPDim };
}

function UIElementInit(isShow) {
  if (isShow) {
    $(".minimap").show();
    $(".internel-wordsearch-container").show();
  } else {
    $(".minimap").hide();
    $(".internel-wordsearch-container").hide();
  }
}

function convertvMapPtToVPCoordinate(d, dx, dy) {
  let minimapBound = d.document.getElementById("minimapStage-" + d.tab).getBoundingClientRect();
  let viewportBound = d.document.getElementById("cfgStage-" + d.tab).getBoundingClientRect();
  let miniVPBound = d.document.getElementById("minimapVP-" + d.tab).getBoundingClientRect();
  let translateWidthRatio = minimapBound.width / viewportBound.width;
  let widthRatio = minimapRatio / translateWidthRatio;
  let halfWidth = miniVPBound.width / minimapRatio / 2;
  return { x: dx + halfWidth * widthRatio, y: dy };
}

function toCenter(d, dx, dy, zoom, transK, durationTime) {
  let cfg = d3.select(d.document).select("svg#cfg-" + d.tab);
  let miniVPBound = d.document.getElementById("minimapVP-" + d.tab).getBoundingClientRect();
  let minimapBound = d.document.getElementById("minimapStage-" + d.tab).getBoundingClientRect();
  let viewportBound = d.document.getElementById("cfgStage-" + d.tab).getBoundingClientRect();
  let translateWidthRatio = minimapBound.width / viewportBound.width;
  let widthRatio = minimapRatio / translateWidthRatio;

  let halfWidth = miniVPBound.width / minimapRatio / 2;
  let halfHeight = miniVPBound.height / minimapRatio / 2;
  let newX = (halfWidth - dx) * widthRatio;
  let newY = (halfHeight - dy) * widthRatio; // depends on widthRatio not heightRatio
  cfg.transition()
    .duration(durationTime)
    .call(zoom.transform,
      d3.zoomIdentity.translate(newX, newY).scale(transK));
}
