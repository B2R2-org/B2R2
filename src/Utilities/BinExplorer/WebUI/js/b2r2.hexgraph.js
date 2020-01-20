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

class HexGraph extends Graph {
  constructor(div, kind) {
    super(div, kind);
    this.fetchAndDraw(kind);
  }

  drawSegSelectorBtn(btndiv) {
    const btn = btndiv.append("button")
      .classed("btn", true)
      .classed("btn-sm", true)
      .classed("dropdown-toggle", true)
      .attr("type", "button")
      .attr("id", "js-hex-segselector")
      .attr("data-toggle", "dropdown")
      .attr("aria-haspopup", true)
      .attr("aria-expanded", false)
      .text("Select segment ");
    btn.append("span").classed("caret", true);
  }

  drawSegSelector(segarr) {
    const div = this.container.append("div")
      .classed("c-graph__segselector", true);
    const btndiv = div.append("div")
      .classed("dropdown", true);
    this.drawSegSelectorBtn(btndiv);
    const menu = btndiv.append("ul")
      .classed("dropdown-menu", true)
      .attr("role", "menu")
      .attr("aria-labelledby", "js-hex-segselector");
    for (let i = 0; i < segarr.length; i++) {
      const addr = segarr[i].addr;
      const li = menu.append("li").attr("role", "presentation");
      li.append("a")
        .attr("role", "menuitem")
        .attr("href", "#")
        .text(intToHex(addr))
        .on("click", function () {
          const me = $(this);
          const win = me.closest(".c-graph").find(".l-graph__segment");
          const anchor = win.find("a[name='" + me.text() + "']");
          const top = win.scrollTop() + anchor.offset().top - 150;
          win.animate({ scrollTop: top });
        });
    }
  }

  countCharPerLine(dumpview, seg) {
    const view = dumpview.node();
    let cnt = null;
    let height = null;
    for (let i = 0; i < seg.bytes.length; i++) {
      const b = seg.bytes[i];
      view.innerHTML += intToHex(b) + " ";
      if (i == 0) height = dumpview.style("height");
      if (cnt === null && height != dumpview.style("height")) {
        cnt = i;
        break;
      }
    }
    return cnt;
  }

  fillAddrView(addrview, addr, size, numCharsPerLine) {
    let s = "";
    for (let a = addr; a < addr + size; a += numCharsPerLine)
      s += intToHex(a) + "<br/>";
    addrview.html(s);
  }

  fillDumpView(dumpview, seg) {
    let s = "";
    for (let i = 0; i < seg.bytes.length; i++) {
      const b = seg.bytes[i];
      s += intToHex(b) + " ";
    }
    dumpview.text(s);
  }

  fillASCIIView(asciiview, seg, numCharsPerLine) {
    let s = "";
    for (let i = 0; i < seg.bytes.length; i++) {
      const b = seg.bytes[i];
      s += intToPrintableChar(b);
      if ((i + 1) % numCharsPerLine == 0) s += "\n";
    }
    asciiview.html(s);
  }

  static getEndOffset(range) {
    return range.endOffset == range.startOffset
      ? range.endOffset + 1
      : range.endOffset;
  }

  static getCurrentSelection() {
    const s = window.getSelection();
    return s.getRangeAt(0);
  }

  registerDumpViewEvent(dumpview, asciiview, numCharsPerLine) {
    dumpview.on("click", function () {
      $(dumpview.node()).unmark();
      const range = HexGraph.getCurrentSelection();
      const s = 3 * Math.floor(range.startOffset / 3);
      const e = 3 * Math.floor((HexGraph.getEndOffset(range) + 5) / 3) - 4;
      $(dumpview.node()).markRanges([{ start: s, length: e - s }]);
      const sdiv3 = Math.floor(s / 3);
      const ss = sdiv3 + Math.floor(sdiv3 / numCharsPerLine);
      const ediv3 = Math.floor((e + 1) / 3);
      const se = ediv3 + Math.floor(ediv3 / numCharsPerLine);
      $(asciiview.node()).unmark();
      $(asciiview.node()).markRanges([ { start: ss, length: se - ss } ]);
    });
  }

  registerASCIIViewEvent(dumpview, asciiview, numCharsPerLine) {
    asciiview.on("click", function () {
      $(asciiview.node()).unmark();
      const range = HexGraph.getCurrentSelection();
      const s = range.startOffset;
      const e = HexGraph.getEndOffset(range);
      $(asciiview.node()).markRanges([ { start: s, length: e - s } ]);
      const ds = (s - Math.floor(s / (numCharsPerLine + 1))) * 3;
      const de = (e - Math.floor(e / (numCharsPerLine + 1))) * 3 - 1;
      $(dumpview.node()).unmark();
      $(dumpview.node()).markRanges([ { start: ds, length: de - ds } ]);
    });
  }

  registerEvents(dumpview, asciiview, numCharsPerLine) {
    this.registerDumpViewEvent(dumpview, asciiview, numCharsPerLine);
    this.registerASCIIViewEvent(dumpview, asciiview, numCharsPerLine);
  }

  drawSegHexdump(div, seg) {
    const addr = seg.addr;
    const size = seg.bytes.length;
    const title = div.append("ol").classed("breadcrumb", true);
    title.append("a").attr("name", intToHex(addr));
    title.append("li").text(intToHex(addr) + " (" + size + " bytes)");
    const body = div.append("div").classed("l-graph__hexdump", true);
    const addrview = body.append("div")
      .classed("unselectable", true)
      .classed("c-graph__hexaddr", true);
    const dataview = body.append("div").classed("l-graph__hexdata", true);
    const dumpview = dataview.append("div").classed("c-graph__hexdump", true);
    const asciiview = dataview.append("div").classed("c-graph__hexascii", true);
    const numCharsPerLine = this.countCharPerLine(dumpview, seg);
    this.fillAddrView(addrview, addr, size, numCharsPerLine);
    this.fillDumpView(dumpview, seg);
    this.fillASCIIView(asciiview, seg, numCharsPerLine);
    this.registerEvents(dumpview, asciiview, numCharsPerLine);
  }

  draw(segarr) {
    this.drawSegSelector(segarr);
    const wrapper =
      this.container.append("div").classed("l-graph__segment", true);
    for (let i = 0; i < segarr.length; i++) {
      const d = wrapper.append("div").classed("c-graph__segment", true);
      this.drawSegHexdump(d, segarr[i]);
    }
  }

  fetchAndDraw(kind) {
    const myself = this;
    query({ "q": kind, "args": "" }, function (_status, json) {
      myself.json = json;
      myself.draw(json);
    });
  }

  search(q) {
    return []; // FIXME
  }
}

