/*
  B2R2 - the Next-Generation Reversing Platform

  Author: Subin Jeong <cyclon2@kaist.ac.kr>
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

class MiniMap {
  constructor(d) {
    this.document = d.document;
    this.moveHandlerId = d.moveHandlerId
    this.returnHandlerId = d.returnHandlerId
    this.resizeHandlerId = d.resizeHandlerId
  }

  draggable() {
    let $minimapHandler = $(this.document).find(this.moveHandlerId);
    let $minimapContainer = $(this.document).find(Root.minimapContainerId);
    var dragging = false;
    var iX, iY;
    $minimapHandler.on("mousedown", function (e) {
      dragging = true;
      iX = e.clientX - $minimapContainer.get(0).offsetLeft;
      iY = e.clientY - $minimapContainer.get(0).offsetTop;
      $minimapContainer.get(0).setCapture && $minimapContainer.get(0).setCapture();
      return false;
    });
    self.document.onmousemove = function (e) {
      if (dragging) {
        var e = e || window.event;
        var oX = e.clientX - iX;
        var oY = e.clientY - iY;
        $minimapContainer.css({ "left": oX + "px", "top": oY + "px" });
        return false;
      }
    };
    $(self.document).on("mouseup", function (e) {
      dragging = false;
    });
  }

  returnPosition() {
    let $minimapContainer = $(this.document).find(Root.minimapContainerId);
    $minimapContainer.css({ "left": "", "top": "" });
    $minimapContainer.css({ "right": "0", "bottom": "0" });
  }

  minimize($this) {
    const self = this;
    if ($this.hasClass("minimize-minimap")) {
      $(self.document).find(Root.minimapContainerId).addClass("active");
      d3.select(self.document).selectAll(".min-box")
        .style("border", "unset")
        .style("height", "0")
    } else {
      $(self.document).find(Root.minimapContainerId).removeClass("active");
      d3.select(self.document).selectAll(".min-box")
        .style("height", "initial")
        .style("border", "1px solid #ccc")
    }
  }

  registerEvents() {
    const self = this;
    $(self.document).find(self.returnHandlerId).on("click", function () {
      self.returnPosition();
    });
    $(self.document).find(self.resizeHandlerId).on("click", function () {
      self.minimize($(this));
    });
    self.draggable();
  }
}