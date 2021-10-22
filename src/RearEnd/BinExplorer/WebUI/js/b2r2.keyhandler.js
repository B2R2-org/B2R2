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

class KeyHandler {
  static space(e, dlg) {
    e.preventDefault();
    dlg.clearResults();
    $("#js-search-dialog .form-control").val("");
    if ($("#js-search-dialog").dialog("isOpen")) {
      $("#js-search-dialog").dialog("close");
    } else {
      $("#js-search-dialog").dialog("open");
    }
    return false;
  }

  static prepareDialogs(winManager) {
    return new SearchDialog(winManager);
  }

  static prepare(winManager) {
    const dlg = KeyHandler.prepareDialogs(winManager);
    $(document).keypress(function (e) {
      const tag = e.target.tagName.toLowerCase();
      if (tag == "input" || tag == "textarea") return true;
      switch (e.which) {
        case 32: return KeyHandler.space(e, dlg);
        default: return true;
      }
    })
  }
}
