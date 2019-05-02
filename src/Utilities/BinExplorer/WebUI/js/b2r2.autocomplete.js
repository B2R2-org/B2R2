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

function autocomplete(cfg) {
  resetSerchInput();

  let stmts = [];
  //stmts = [ address operand:[] meta:{pos, width, idx} ]
  let data = cfg.Nodes;
  for (let d in data) {
    for (let t in data[d].Terms) {
      let stmt = [];
      let terms = data[d].Terms[t];
      let address = terms[0][0].replace(":", "");
      stmt.push(address);
      for (let i = 1; i < terms.length - 1; i++) {
        //operand
        stmt.push(terms[i][0]);
      }

      //meta
      stmt.push({
        Nodeidx: parseFloat(d),
        idx: parseFloat(t),
        Pos: data[d].Pos,
        Width: data[d].Width
      });
      stmts.push(stmt);
    }
  }
  function removeAllItem() {
    $("#id-autocomplete-list").empty();
  }
  function searchItem() {
    $("#id_address-search").on("keyup", function (e) {
      removeAllItem();
      var lowerValue = this.value.toLowerCase();
      var value = this.value;
      if (value === "" || parseFloat(value) === 0) {
        deactiveStmt();
        return;
      }
      let list = []
      for (let s in stmts) {
        let stmt = stmts[s];
        //stmt = address operand:[] pos:{}
        let stmtstr = stmt.slice(0, -1).join("");
        let lowerStmtstr = stmtstr.toLowerCase();
        if (lowerStmtstr.indexOf(lowerValue) > -1) {
          let memory = stmt[0];
          let meta = stmt[stmt.length - 1];
          let item = '<div class="autocomplete-item" nidx=[NIDX] idx=[IDX]  width=[WIDTH] posX=[POSX]  posY=[POSY]>'
            .replace("[NIDX]", meta.Nodeidx)
            .replace("[IDX]", meta.idx)
            .replace("[WIDTH]", meta.Width)
            .replace("[POSX]", meta.Pos.X)
            .replace("[POSY]", meta.Pos.Y);
          let idx = lowerStmtstr.indexOf(value);
          if (idx < 16) {
            item += '<span class="memory">[CONTENT]</span>'.replace("[CONTENT]",
              memory.substr(0, idx)
              + "<strong>" + memory.substr(idx, value.length) + "</strong>"
              + memory.substr(idx + value.length));
            for (let i = 1; i < stmt.length - 1; i++) {
              item += '<span class="operand">[OPERAND]</span>'.replace("[OPERAND]", stmt[i]);
            }
          } else {
            item += '<span class="memory">[MEMORY]</span>'.replace("[MEMORY]", memory);
            item += '<span class="operand">[CONTENT]</span>'.replace("[CONTENT]",
              stmtstr.substr(16, idx - 16)
              + "<strong>" + stmtstr.substr(idx, value.length) + "</strong>"
              + stmtstr.substr(idx + value.length));
          }
          item += '</div>'
          list.push(item);
        }
      }
      $("#id-autocomplete-list").append(list.join(""));
    });
  }
  function addActiveItem() {
    $(document).on("click", ".autocomplete-item", function () {
      removeAllItem();
    });

    $(document).on("click", function (e) {
      if ($(".autocomplete-list").children().size() > 0) {
        if (!$(e.target).hasClass(".autocomplete-list")) {
          resetSerchInput();
          removeAllItem();
          deactiveStmt();
        }
      }
    });

    $(document).on("mouseover", ".autocomplete-list .autocomplete-item", function () {
      let x = parseFloat($(this).attr("posX"));
      let y = parseFloat($(this).attr("posY"));
      let width = parseFloat($(this).attr("width"));
      let idx = $(this).attr("idx");
      let stmt = $(this).text().substr(0, 16) + " " + $(this).text().substr(16);
      activeStmt(x, y, idx, width, stmt);
    });

    $(document).on("mouseout", ".autocomplete-item", function () {
      deactiveStmt();
    });
  }
  function focusNode(x, y) {
    // in graph.js
  }
  function activeStmt(x, y, idx, width, stmt) {
    let currentTabNumber = $("#id_tabContainer li.tab.active").attr("counter");
    let g = d3.select("#cfgStage-" + currentTabNumber).select("g").append("g").attr("class", "g-stmt-box");
    let box = g.append("rect");
    box
      .attr("width", width)
      .attr("height", 20)
      .attr("x", x)
      .attr("y", y + 15 * idx + 2)
      .attr("fill", "black");
    let tbox = g.append("text").attr("font-family", "'Inconsolata', monospace").text(stmt)
    tbox
      .attr("font-size", 16)
      .attr("x", x)
      .attr("y", y + 15 * idx + 15)
      .attr("fill", "yellow");

    // In minimap
    let minibox = d3.select("g#minimapStage-" + currentTabNumber).append("rect")
      .attr("class", "mini-stmt-box")
      .attr("fill", "yellow")
      .attr("stroke", "black")
      .attr("style", "outline: 1px solid black;")
      .attr("width", width * minimapRatio)
      .attr("height", 20 * minimapRatio)
      .attr("transform",
        "translate(" + x * minimapRatio +
        ", " + (y + 15 * idx + 2) * minimapRatio + ")");

    // remove when clicked;
    g.on("click", function () {
      g.remove();
      minibox.remove();
    });
  }
  function deactiveStmt() {
    d3.selectAll(".g-stmt-box").remove();
    d3.selectAll(".mini-stmt-box").remove();
  }

  function resetSerchInput() {
    $("#id_address-search").val("");
  }

  searchItem();
  addActiveItem();
}