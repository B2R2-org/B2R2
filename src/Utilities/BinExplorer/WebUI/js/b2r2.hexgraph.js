/*
  B2R2 - the Next-Generation Reversing Platform

  Author: Sang Kil Cha <sangkilc@kaist.ac.kr>

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

  drawSegSelector(segarr) {
    const div = this.container.append("div")
      .classed("c-graph__segselector", true);
    const btndiv = div.append("div")
      .classed("dropdown", true);
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
          win.animate({ scrollTop: anchor.offset().top - 150 }, "slow");
        });
    }
  }

  activateCell(dumpview, asciiview, addr) {
    return function () {
      dumpview.selectAll("span").each(function () {
        const elm = d3.select(this);
        elm.classed("active", elm.attr("data-value") == addr);
      });
      asciiview.selectAll("span").each(function () {
        const elm = d3.select(this);
        elm.classed("active", elm.attr("data-value") == addr);
      });
    };
  }

  fillDumpView(dumpview, asciiview, seg) {
    const addr = seg.addr;
    for (let i = 0; i < seg.bytes.length; i++) {
      const b = seg.bytes[i];
      dumpview.append("span")
        .classed("c-graph__hexvalue", true)
        .attr("title", intToHex(addr + i))
        .attr("data-value", addr + i)
        .text(intToHex(b))
        .on("click", this.activateCell(dumpview, asciiview, addr + i));
      dumpview.append("i").text(" ");
    }
  }

  countNumBytesPerLine(dumpview) {
    let top = null;
    let cnt = 0;
    $(dumpview.node()).find("span").each(function () {
      if (top === null) {
        top = this.getBoundingClientRect().top;
      } else if (top != this.getBoundingClientRect().top) {
        return false;
      }
      cnt += 1;
      return true;
    });
    return cnt;
  }

  fillASCIIView(dumpview, asciiview, seg) {
    const numBytes = this.countNumBytesPerLine(dumpview);
    const wrap = asciiview.append("div");
    const addr = seg.addr;
    for (let i = 0; i < seg.bytes.length; i++) {
      const b = seg.bytes[i];
      wrap.append("span")
        .classed("c-graph__asciivalue", true)
        .attr("title", intToHex(addr + i))
        .attr("data-value", addr + i)
        .text(intToPrintableChar(b))
        .on("click", this.activateCell(dumpview, asciiview, addr + i));
      if ((i + 1) % numBytes == 0) wrap.append("br");
    }
  }

  drawSegHexdump(div, seg) {
    const addr = seg.addr;
    const size = seg.bytes.length;
    const title = div.append("ol").classed("breadcrumb", true);
    title.append("a").attr("name", intToHex(addr));
    title.append("li").text(intToHex(addr) + " (" + size + " bytes)");
    const body = div.append("div").classed("l-graph__hexdump", true);
    const dumpview =
      body.append("div")
        .classed("unselectable", true)
        .classed("c-graph__hexdump", true);
    const asciiview =
      body.append("div")
        .classed("unselectable", true)
        .classed("c-graph__hexascii", true);
    this.fillDumpView(dumpview, asciiview, seg);
    this.fillASCIIView(dumpview, asciiview, seg);
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
}

