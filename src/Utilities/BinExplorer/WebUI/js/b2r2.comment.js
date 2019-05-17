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

var commentLeftMargin = 10;
var commentTextMargin = 5;

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

    let current_tab_id = $("#id_tabContainer li.tab.active").attr("counter");
    let target_id = $("#id_comment-modal").attr("target");
    let comment = $('#id_comment').val();
    if (comment.length > 0) {
      setComment(current_tab_id, target_id, comment, true);
    } else {
      removeComment(target_id);
    }
  });
}

function setComment(tab_id, target_id, comment, isOpen) {
  // target_id = id_tabid_[element_type]-nodeid-idx
  let rect = d3.select(target_id);
  let gtext = d3.select(rect.node().parentNode);

  let commentList = comment.split("\n");
  let gComment;
  let commentDot;
  let gCommentid = "id_" + tab_id + "_g_comment-" + target_id.split("_rect-")[1];
  let commentDotid = "id_" + tab_id + "_comment_dot-" + target_id.split("_rect-")[1];
  if ($("#" + gCommentid).length > 0) {
    gComment = d3.select("#" + gCommentid);
  } else {
    gComment = gtext.append("g")
      .attr("id", gCommentid)
      .attr("class", "gComment");
  }
  if ($(rect.node().parentNode).find(".commentDot").length > 0) {
    commentDot = d3.select("#" + commentDotid)
  } else {
    commentDot = gComment.append('svg:foreignObject')
      .attr("id", commentDotid)
      .attr("class", "commentDot")
  }
  commentDot.attr("x", parseFloat(rect.attr("width")) - 20)
    .attr("y", 0)
    .attr("width", 16)
    .attr("height", 16)
    .attr("data-comment", comment)
    .html('<i title="Comment" class="fas fa-quote-left fa-sm comment-dot"></i>')
    .on("click", function () {
      let gid = "#" + $(this).attr("id").replace("_comment_dot-", "_g_comment-");
      $(gid).find(".commentRect").toggleClass("active");
      $(gid).find(".commentText").toggleClass("active");
      let gNode = $(this).parent().parent();
      gNode.append($(this).parent());
      let gcfg = gNode.parent();
      gcfg.append(gNode);
    });
  let x = parseFloat(rect.attr("width"));
  let commentRect;
  let commentText;
  if ($(rect.node().parentNode).find(".commentRect").length > 0) {
    gComment.select(".commentRect").remove();
    gComment.select(".commentText").remove();
  }
  commentRect = gComment.append("rect");
  commentText = gComment.append("text");

  commentRect
    .attr("class", "commentRect active")
    .attr("rx", 6)
    .attr("ry", 6)
    .attr("x", x + commentLeftMargin)
    .attr("y", 0)
    .attr("fill", "black")

  commentText
    .attr("class", "commentText active")
    .attr("id", "id_" + tab_id + "_comment-" + target_id.split("_rect-")[1])
    .attr("x", x + commentTextMargin + commentLeftMargin)
    .attr("y", 16)
    .selectAll("tspan")
    .data(commentList)
    .enter()
    .append("tspan")
    .attr("xml:space", "preserve")
    .attr("y", function (d, i) {
      return (i + 1) * 15;
    })
    .attr("x", commentText.attr("x"))
    .text(function (d) {
      return d;
    })
    .attr("fill", "#929dc0");
  commentText.on("click", function () {
    // inside a node
    let gid = "#id_" + tab_id + "_g-" + $(this).attr("id").split("_comment-")[1];
    $(gid).parent().append($(gid));

    // between nodes
    let gNode = $(this).parent().parent();
    gNode.append($(this).parent());
    let gcfg = gNode.parent().parent();
    gcfg.append(gNode.parent());
  }).on("dblclick", function () {
    $("#id_comment-modal").modal('show');
    commitInit(target_id, comment);
  });
  let commentTextPos = commentText.node().getBBox();
  commentRect
    .attr("width", parseFloat(commentTextPos.width) + 2 * commentTextMargin)
    .attr("height", parseFloat(commentTextPos.height) + 2 * commentTextMargin);

  if (isOpen) {
    commentRect.classed("active", true);
    commentText.classed("active", true);
  } else {
    commentRect.classed("active", false);
    commentText.classed("active", false);
  }

  // reload sidebar
  setSidebarComments();
}

function removeComment(target_id) {
  let gid = target_id.replace("_rect-", "_g_comment-");
  $(gid).remove();
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

function commitInit(target_id, comment) {
  $("#id_comment-modal").attr("target", target_id);
  $("#id_comment").val(comment);
}

Comment();