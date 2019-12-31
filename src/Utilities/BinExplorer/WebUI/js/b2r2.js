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

// Offline mode renders a single function (CFG) only. Inter-function analysis is
// not supported in offline mode.
function runOffline() {
  let fileInput = document.getElementById("js-cfg-file");
  $("#js-bininfo").click(function () { fileInput.click(); });
  fileInput.addEventListener("change", function () {
    let file = fileInput.files[0];
    let reader = new FileReader();
    reader.onload = function () {
      let json = JSON.parse(reader.result);
      // let g = new FlowGraph(document, 1, dims, json, false);
      // g.drawGraph();
      // tab.setGraph(g);
    };
    try { reader.readAsText(file); }
    catch (_) { console.log("Error: File open failure."); }
  });
}

function abbreviateString(str, maxLen) {
  if (str.length < maxLen) return str;
  else return "... " + str.slice(str.length - maxLen + 4);
}

// Run in online mode (this is the default).
function runOnline() {
  const winManager = new WindowManager();
  winManager.initiate(new NavBar(winManager));
  KeyHandler.prepare(winManager);
  BinInfo.update();
}

function main() {
  if (window.location.protocol == "file:")
    return runOffline();
  else {
    return runOnline();
  }
}

if (typeof window === 'undefined') {
  // Do nothing for Node.js.
} else {
  window.addEventListener('load', function () { main(); }, false);
}

