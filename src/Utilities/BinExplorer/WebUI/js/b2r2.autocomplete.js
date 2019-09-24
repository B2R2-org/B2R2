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

class AutoComplete {
  constructor(d) {
    this.document = d.document;
    if (d.document === undefined)
      this.document = document;
    this.graphinfo = d.graphinfo;
    this.stmts = [];
    this.id = d.id;
    if (d.id === undefined)
      this.id = "#id-autocomplete-list";
    this.inputid = d.inputid;
    if (d.inputid === undefined)
      this.inputid = "#id_address-search";

  }

  reload(graphinfo) {
    this.clearInput();
    this.graphinfo = graphinfo;

    this.stmts = [];
    if (graphinfo.json != undefined) {
      let data = graphinfo.json.Nodes;
      for (let d in data) {
        for (let t in data[d].Terms) {
          let stmt = [];
          let terms = data[d].Terms[t];
          let address = terms[0][0];
          stmt.push(address);
          for (let i = 1; i < terms.length; i++) {
            //operand
            stmt.push(terms[i][0]);
          }

          //meta
          stmt.push({
            Nodeidx: parseFloat(d),
            idx: parseFloat(t),
          });
          this.stmts.push(stmt);
        }
      }
    }
  }

  removeElements() {
    $(this.document).find(this.id).empty();
  }

  activateStmtElements(x, y, width, stmt) {
    const self = this;
    self.deactiveStmtElements();
    let g = self.graphinfo.document.select(this.graphinfo.stage)
      .select("g").append("g")
      .attr("class", "g-stmt-box")
      .attr("transform", "translate(" + x + "," + y + ")");
    let box = g.append("rect");
    box
      .attr("width", width)
      .attr("height", 20)
      .attr("fill", "black");
    let tbox = g.append("text").attr("font-family", "'Inconsolata', monospace").text(stmt)
    tbox
      .attr("font-size", 15)
      .attr("y", 15)
      .attr("fill", "yellow");

    // In minimap
    let minibox = self.graphinfo.document.select(this.graphinfo.minimapStage).append("rect")
      .attr("class", "mini-stmt-box")
      .attr("fill", "yellow")
      .attr("stroke", "black")
      .attr("style", "outline: 1px solid black;")
      .attr("width", width * minimapRatio)
      .attr("height", 20 * minimapRatio)
      .attr("transform",
        "translate(" + x * minimapRatio +
        ", " + y * minimapRatio + ")");

    // remove when clicked;
    g.on("click", function () {
      self.deactiveStmtElements();
    });
  }

  deactiveStmtElements() {
    d3.select(this.document).selectAll(".g-stmt-box").remove();
    d3.select(this.document).selectAll(".mini-stmt-box").remove();
  }

  clearInput() {
    $(this.document).find(this.inputid).val("");
  }

  search(word) {
    this.removeElements();
    var lowerValue = word.toLowerCase();
    if (word === "") {
      this.deactiveStmtElements();
      return;
    }
    let list = []
    for (let s in this.stmts) {
      let stmt = this.stmts[s];
      let stmtstr = stmt.slice(0, -1).join("");
      let lowerStmtstr = stmtstr.toLowerCase();
      if (lowerStmtstr.indexOf(lowerValue) > -1) {
        let addr = stmt[0];
        let meta = stmt[stmt.length - 1];
        let item = '<div class="autocomplete-item" target=[TARGET] addr=[ADDR] idx=[IDX]>'
          .replace("[TARGET]", "#id_" + this.graphinfo.tab + "_rect-" + meta.Nodeidx + "-" + meta.idx)
          .replace("[IDX]", meta.idx)
          .replace("[ADDR]", addr);
        let idx = lowerStmtstr.indexOf(word);
        if (idx < 16) {
          item += '<span class="address">[CONTENT]</span>'.replace("[CONTENT]",
            addr.substr(0, idx)
            + "<strong>" + addr.substr(idx, word.length) + "</strong>"
            + addr.substr(idx + word.length));

          for (let i = 1; i < stmt.length - 1; i++) {
            item += '<span class="operand">[OPERAND]</span>'.replace("[OPERAND]", stmt[i]);
          }
        } else {
          item += '<span class="address">[MEMORY]</span>'.replace("[MEMORY]", addr);
          item += '<span class="operand">[CONTENT]</span>'.replace("[CONTENT]",
            stmtstr.substr(16, idx - 16)
            + "<strong>" + stmtstr.substr(idx, word.length) + "</strong>"
            + stmtstr.substr(idx + word.length));
        }
        item += '</div>'
        list.push(item);
      }
    }
    $(this.document).find(this.id).append(list.join(""));
  }

  registerEvents() {
    const self = this;
    $(self.document).on("keyup", self.inputid, function (e) {
      self.search(this.value);
    });

    $(self.document).on("click", ".autocomplete-item", function () {
      self.removeElements();
    });

    $(self.document).on("click", function (e) {
      if ($(self.document).find(".autocomplete-list").children().size() > 0) {
        if (!$(e.target).hasClass(".autocomplete-list")) {
          self.clearInput();
          self.removeElements();
          self.deactiveStmtElements();
        }
      }
    });

    $(self.document).on("mouseover", self.id + " .autocomplete-item", function () {
      let target = $(this).attr("target"); //#id_[tabNumber]_rect-[nodeIdx]-[StmtIdx]
      let rect = d3.select(self.document).select(target);
      let text = d3.select(self.document).select(target.replace("_rect-", "_text-"));
      let width = rect.attr("width");
      let gtext = d3.select(rect.node().parentNode);
      let gNode = d3.select(rect.node().parentNode.parentNode);
      let pos = getGroupPos(gNode.attr("transform"))
      let x = pos[0];
      let y = pos[1] + getGroupPos(gtext.attr("transform"))[1];
      let stmt = text.html().replace(/(<([^>]+)>)/ig, "");
      self.activateStmtElements(x, y, width, stmt);
    });

    $(self.document).on("mouseout", ".autocomplete-item", function () {
      self.deactiveStmtElements();
    });
  }
}
