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

class SearchDialog {
  constructor(winManager) {
    this.winManager = winManager;
    this.register();
  }

  clearResults() {
    const container = d3.select("#js-search-dialog .l-search-dialog-results");
    container.style("display", "none");
    container.html("");
  }

  showResults(results) {
    const container = d3.select("#js-search-dialog .l-search-dialog-results");
    const height = this.winManager.getCurrentHeight() * 0.4;
    container.style("display", "inline-block").style("height", height + "px");
    for (let i = 0; i < results.length; i++) {
      container.append("div")
        .classed("c-search-dialog__item", true)
        .html(results[i].val)
        .on("mouseover", results[i].onhover)
        .on("click", results[i].onclick);
    }
  }

  localSearch(q) {
    if (this.winManager.currentWin !== null) {
      const win = this.winManager.currentWin;
      // Search results = an array of records that look like below:
      // { val: "aaa", onclick: null, onhover: null }
      const results = this.winManager.windows[win].graph.search(q);
      this.clearResults();
      this.showResults(results);
    }
  }

  incSearch() {
    const q = $("#js-search-dialog .form-control").val().trim().toLowerCase();
    if (q) {
      this.localSearch(q);
    } else {
      this.clearResults();
    }
  }

  onKeyUp(myself) {
    let timer = null;
    let itemidx = -1;
    let items = null;
    const container = d3.select("#js-search-dialog .l-search-dialog-results");
    return function (e) {
      switch (e.keyCode) {
        case 16:
        case 17:
        case 18:
          break; // Ignore ctrl, alt, or shift keys.
        case 13: // enter key.
          items = container.selectAll(".c-search-dialog__item")
            .classed("active", false).nodes();
          if (itemidx >= 0 && itemidx <= items.length - 1) {
            $(items[itemidx]).trigger("click");
          } else {
            clearTimeout(timer);
            myself.incSearch();
          }
          break;
        case 38: // up arrow.
          items = container.selectAll(".c-search-dialog__item")
            .classed("active", false).nodes();
          itemidx = Math.max(itemidx - 1, 0);
          d3.select(items[itemidx]).classed("active", true);
          break;
        case 40: // down arrow.
          items = container.selectAll(".c-search-dialog__item")
            .classed("active", false).nodes();
          itemidx = Math.min(itemidx + 1, items.length - 1);
          d3.select(items[itemidx]).classed("active", true);
          break;
        default:
          clearTimeout(timer);
          timer = setTimeout(function () {
            myself.incSearch();
          }, incSearchInterval);
          break;
      }
    };
  }

  register() {
    $("#js-search-dialog").dialog({
      autoOpen: false,
      modal: true,
      resizable: false,
      position: { my: "top", at: "top+40%", of: window },
      height: 60,
      dialogClass: "c-search-dialog",
      open: function () {
        $(".ui-widget-overlay").bind("click", function () {
          $("#js-search-dialog").dialog("close");
        });
      },
      show: { effect: "blind", duration: 200 },
      hide: { effect: "blind", duration: 200 }
    });
    $("#js-search-dialog .form-control").keyup(this.onKeyUp(this));
  }
}

