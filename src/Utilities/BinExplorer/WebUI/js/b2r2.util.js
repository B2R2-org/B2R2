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

function copyToClipboard(str) {
  let aux = document.createElement("textarea");
  aux.value = str;
  document.body.appendChild(aux);
  aux.select();
  document.execCommand("copy");
  document.body.removeChild(aux);
}

function popToast(type, content, seconds) {
  var x = document.getElementById("id_toast");
  x.className = "show";
  $(x).text(content);
  setTimeout(function () { x.className = x.className.replace("show", ""); }, seconds * 1000);
}

function getReductionRate() {
  console.log("getReductionRate")
  let currentTabNumber = $("#id_tabContainer li.tab.active").attr("counter");
  let extraRatio = 0.9;
  let r = document.getElementById("cfgGrp" + currentTabNumber).getBBox();
  let stageDim = {
    width: r.width,
    height: r.height
  };

  let dims = reloadUI();
  let reductionRate =
    Math.min(dims.cfgVPDim.width / stageDim.width,
      dims.cfgVPDim.height / stageDim.height) * extraRatio;

  // If the entire CFG is smaller than the cfgVP, then simply use the rate 1.
  // In other words, the maximum reductionRate is one.
  if (reductionRate >= 1) reductionRate = 1;
  return reductionRate;
}

function getGroupPos(transformAttr) {
  let pos = transformAttr.split("translate")[1].split("(")[1].split(")")[0].split(",");
  return pos.map(function (x) {
    return parseFloat(x);
  })
}