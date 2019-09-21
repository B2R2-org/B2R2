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
    if (d.id === undefined)
      this.id = "#id_node-contextmenu";
    else
      this.id = d.id;

    if (d.document === undefined)
      this.document = document;
    else
      this.document = d.document;

    this.visible = false;

    if ($("#" + this.id).val() === undefined)
      $(this.document.body).append(
          "<div id='" + this.id + "' class='contextmenu'>"
        + "  <div class='contextmenu-item' value='copy'>Copy</div>"
        + "  <div class='contextmenu-item' value='copy-address'>Copy Address</div>"
        + "</div>");
    this.menu = $(this.document.body).find("#" + this.id);
  }

  show(node, x, y) {
    this.menu
      .css("display", "block")
      .css("top", y)
      .css("left", x)
      .attr("target", "#" + $(node).attr("id"));
    this.visible = true;
  }

  hide() {
    if (this.visible) {
      this.visible = false;
      this.menu
        .css("display", "none")
        .attr("target", "#");
    }
  }

  registerEvents() {
    let self = this;

    $(this.document).on("click", ".contextmenu-item", function() {
      let target_id = self.menu.attr("target");
      let textbox = $(self.document.body).find(target_id);
      let gtext = textbox.parent();
      switch ($(this).attr("value")) {
        case "copy":
          copyToClipboard(self.document, gtext.find(".string").text());
          popToast("info", "Line copied", 3);
          break;
        case "copy-address":
          copyToClipboard(self.document, gtext.find(".address").text());
          popToast("info", "Address copied", 3);
          break;
        default:
          break;
      }
    });

    $(this.document).on("click", function () {
      self.hide();
    });
  }
}
