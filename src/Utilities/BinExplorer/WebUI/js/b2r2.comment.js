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
function Comment() {
  $('#id_comment-modal').on("shown.bs.modal", function () {
    $("#id_comment").trigger("focus");
  });

  $(".comment-btn.close").on("click", function () {
    $("#id_comment-modal").modal('hide');
    $(".stmtHighlight").removeClass("stmtHighlight");
  });

  $(".comment-btn.comment").on("click", function () {
    $("#id_comment-modal").modal('hide');
    $(".stmtHighlight").removeClass("stmtHighlight");
    let target_id = $("#id_comment-modal").attr("target");
    let comment = $('#id_comment').val();
    let textbox = d3.select(target_id);
    let gtext = d3.select(textbox.node().parentNode);
    let gNode = d3.select(gtext.node().parentNode);
    let textid = "#id_text-" + target_id.split("_")[1];
    let prevTextWidth = d3.select(target_id).attr("width");

    let prevComment = "";
    if (gtext.select(".cfgDisasmComment").node() === null) {
      gtext.select("text").append("tspan")
        .text("").attr("class", "cfgDisasmComment")
        .attr("xml:space", "preserve")
        .attr("dx", "0px");
    } else {
      prevComment = gtext.select(".cfgDisasmComment").text();
    }
    let textDiff = comment.length - prevComment.length;
    let newWidth;
    if (comment.length > 0) {
      gtext.select(".cfgDisasmComment").text(" # " + comment);
    } else {
      gtext.select(".cfgDisasmComment").text("");
    }
    let rectNode = gNode.select(".cfgNode");
    let rectNodeBlur = gNode.select(".cfgNodeBlur");
    if (textDiff > 0) {
      let changedTextWidth = d3.select(textid).node().getComputedTextLength();
      if (prevTextWidth >= changedTextWidth) {
        newWidth = prevTextWidth;
      } else {
        newWidth = parseFloat(changedTextWidth) + 10;
      }
    } else {
      let textList = $(d3.select(target_id).node().parentNode.parentNode).find(".stmt");
      newWidth = -1;
      for (let i = 0; i < textList.length; i++) {
        let textwidth = textList[i].getComputedTextLength();
        if (newWidth < textwidth) {
          newWidth = parseFloat(textwidth);
        }
      }
      newWidth += 10;
    }


    let textboxList = $(target_id).parent().parent().find(".nodestmtbox");
    for (let i = 0; i < textboxList.length; i++) {
      $(textboxList[i]).attr("width", newWidth);
    }
    rectNode.attr("width", newWidth);
    rectNodeBlur.attr("width", newWidth);
    let gNodePos = gNode.attr("transform").split("translate")[1].split("(")[1].split(")")[0].split(",");
    let gx = parseFloat(gNodePos[0]) - (newWidth - prevTextWidth) / 2;
    gNode.attr("transform", "translate(" + gx + "," + gNodePos[1] + ")");

    // minimap node rescale
    let gminiNode = d3.select($("[miniid=" + gNode.attr("nodeid") + "]")).node()
      .attr("transform", "translate(" + gx * minimapRatio + "," + parseFloat(gNodePos[1]) * minimapRatio + ")");
    gminiNode.attr("width", newWidth * minimapRatio);

    // sidebar comment change
    let id = target_id.split("_")[1];
    let commentContainter = $(".comment-content[title='" + id + "']");
    let funcName = $("#uiFuncName").text();
    if (commentContainter.length > 0) {
      commentContainter.find(".comment-summary").text("# " + comment);
    } else if ($(".comment-section[value='" + funcName + "']").find(".comment-content").length > 0) {
      addComment(funcName, id, comment);
    } else {
      setComments(funcName, [{
        Terms: [
          [
            [
              id,
              "Mnemonic"
            ],
            [
              comment,
              "Comment"
            ]
          ]
        ]
      }])
    }
  });
}

function onCommentSubmit() {
  var key = window.event.keyCode;
  if (key === 13) {
    if (window.event.shiftKey) {
    } else {
      $(".comment-btn.comment").click();
    }
    return false;
  }
  else {
    return true;
  }
}

Comment();