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

class TermGraph extends Graph {
  constructor(div, kind) {
    super(div, kind);
    this.promptstring = "B2R2>";
    this.draw();
  }

  scrollBottom() {
    const contentWin = this.termcontent.node();
    contentWin.scrollTop = contentWin.scrollHeight;
  }

  appendResult(result) {
    this.termcontent.append("span").classed("c-graph__termresult", true)
      .text(result);
    this.scrollBottom();
  }

  showIntro() {
    const myself = this;
    myself.appendResult("\
_|_|_|      _|_|    _|_|_|      _|_|   \n\
_|    _|  _|    _|  _|    _|  _|    _| \n\
_|_|_|        _|    _|_|_|        _|   \n\
_|    _|    _|      _|    _|    _|     \n\
_|_|_|    _|_|_|_|  _|    _|  _|_|_|_|");
    myself.appendResult("\n\nWelcome to B2R2's webconsole.");
    myself.appendResult("Type `help` in the prompt to get more information.");
    setTimeout(function () { myself.appendResult(""); }, 200);
  }

  execCommand() {
    const prompt = $(this.prompt.node());
    const cmd = prompt.val().trim();
    if (cmd.length == 0) {
      this.appendResult(this.promptstring);
    } else {
      const myself = this;
      myself.appendResult(this.promptstring + " " + cmd);
      query({ "q": "Command", "args": cmd }, function (_, result) {
        myself.appendResult(result);
      });
    }
    prompt.val("");
    d3.event.preventDefault();
    this.scrollBottom();
  }

  static onKeyDown(termgraph) {
    return function () {
      switch (d3.event.keyCode) {
        case 13: termgraph.execCommand(); break;
        default: break;
      }
    };
  }

  draw() {
    const div = this.container.append("div").classed("l-graph__terminal", true);
    this.termcontent = div.append("div").classed("c-graph__termcontent", true);
    const promptwrap = div.append("div").classed("l-graph__termprompt", true);
    promptwrap.append("span").text(this.promptstring);
    this.prompt = promptwrap.append("textarea")
      .classed("c-graph__termprompt", true)
      .attr("autofocus", true)
      .attr("spellcheck", false)
      .on("keydown", TermGraph.onKeyDown(this));
    this.showIntro();
  }
}
