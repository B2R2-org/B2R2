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

function computeVPDimensions(graphContainer) {
  const box = graphContainer.node().getBoundingClientRect();
  const cfgVPDim = {
    width: box.width
      - parseInt(graphContainer.style("border-left-width"))
      - parseInt(graphContainer.style("border-right-width"))
      - parseInt(graphContainer.style("padding-left"))
      - parseInt(graphContainer.style("padding-right")),
    height: box.height
      - parseInt(graphContainer.style("border-bottom-width"))
      - parseInt(graphContainer.style("padding-bottom"))
  }
  const minimapVPDim = {
    width: cfgVPDim.width * minimapRatio,
    height: cfgVPDim.height * minimapRatio
  }
  return { cfgVPDim: cfgVPDim, minimapVPDim: minimapVPDim };
}

function query(args, callback) {
  function serialize(args) {
    var params = [];
    for (var arg in args)
      if (args.hasOwnProperty(arg)) {
        params.push(encodeURIComponent(arg)
          + "="
          + encodeURIComponent(args[arg]));
      }
    return params.join("&");
  }
  let req = new XMLHttpRequest();
  let params = serialize(args);
  req.onreadystatechange = function () {
    if (this.readyState == 4) {
      if (this.responseText.length > 0) {
        callback(this.status, JSON.parse(this.responseText));
      }
    }
  }
  req.open("GET", "/ajax/?" + params, true);
  req.send();
}

function copyToClipboard(str) {
  let aux = document.createElement("textarea");
  aux.value = str;
  document.body.appendChild(aux);
  aux.select();
  document.execCommand("copy");
  document.body.removeChild(aux);
}

function intToHex(d) {
  const s = d.toString(16);
  if (s.length < 2) return '0' + s;
  else return s;
}

function escapeChar(ch) {
  if (ch == "&") return "&amp;";
  else if (ch == "<") return "&lt;";
  else if (ch == ">") return "&gt;";
  else if (ch == "\"") return "&quot;";
  else return ch;
}

function intToPrintableChar(d) {
  if (d >= 32 && d < 127) return escapeChar(String.fromCharCode(d));
  else return ".";
}

function isEmpty(obj) {
  for (const prop in obj) {
    if (Object.hasOwn(obj, prop)) {
      return false;
    }
  }
  return true;
}
