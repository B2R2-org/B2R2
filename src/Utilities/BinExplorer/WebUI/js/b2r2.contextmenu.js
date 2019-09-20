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

class ContextMenu {
  constructor(d) {
    this.id = d.id;
    if (d.id === undefined)
      this.id = "#id_node-contextmenu";
    this.visible = false;
  }

  show(node, x, y) {
    $("#id_node-contextmenu")
      .css("display", "block")
      .css("top", y)
      .css("left", x)
      .attr("target", "#" + $(node).attr("id"));
    this.visible = true;
  }

  hide() {
    if (this.visible) {
      this.visible = false;
      $("#id_node-contextmenu")
        .css("display", "none")
        .attr("target", "#");
    }
  }

  registerEvents() {
    $(document).on("click", ".contextmenu-item", function() {
      let target_id = $("#id_node-contextmenu").attr("target");
      let textbox = d3.select(target_id);
      let gtext = d3.select(textbox.node().parentNode);
      switch ($(this).attr("value")) {
        case "copy":
          copyToClipboard(gtext.select(".string").text());
          popToast("info", "Line copied", 3);
          break;
        case "copy-address":
          copyToClipboard(gtext.select(".address").text());
          popToast("info", "Address copied", 3);
          break;
        default:
          break;
      }
    });

    $(document).on("click", function () {
      Root.ContextMenu.hide();
    });
  }
}