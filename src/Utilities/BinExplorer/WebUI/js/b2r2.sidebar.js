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

function Sidebar() {
  $(document).on("click", ".comment-function", function () {
    $icon = $(this).find(".comment-arrow")
    if ($icon.hasClass("fa-caret-right")) {
      $icon.removeClass("fa-caret-right");
      $icon.addClass("fa-caret-down");
      $icon.closest(".comment-section").find(".comment-list").show();
    } else {
      $icon.removeClass("fa-caret-down");
      $icon.addClass("fa-caret-right");
      $icon.closest(".comment-section").find(".comment-list").hide();
    }
  });

  $(document).on("click", ".sidebar-item", function () {
    $(".sidebar-item.active").removeClass("active");
    $(this).addClass("active");
    switch ($(this).attr("title")) {
      case "Functions":
        $("#id_CommentsListWrapper").hide();
        $("#id_FunctionsListWrapper").show();
        break
      case "Comments":
        $("#id_FunctionsListWrapper").hide();
        $("#id_CommentsListWrapper").show();
        setSidebarComments();
        break;
      default:
        break;
    }
  });
}

function templeteSidebarComment(id, addr, comment) {
  let item = "";
  item += "<div class='comment-content' target='#" + id + "' title='" + addr + "'>";
  item += "<small class='comment-memory'>" + addr + "</small>";
  item += "<div class='comment-summary'> # " + comment + "</div>";
  item += "</div>";
  return item;
}

function templateSidebarCommentList(funcName) {
  let tab_id = $("li[title=" + funcName + "]").attr("counter");
  let $gComments = $("#cfgGrp" + tab_id + " g.gComment");
  let item = "<div class='comment-section' value='" + funcName + "'>";
  item += "<div class='comment-function'>"
  item += "<i style='width: 10px' class='comment-arrow fas fa-caret-down'></i>";
  item += funcName;
  item += "</div>";
  item += "<div class='comment-list'>"
  for (let i = 0; i < $gComments.length; i++) {
    let $gComment = $($gComments[i]);
    let id = $gComment.attr("id");
    item += templeteSidebarComment(id, $gComment.parent().find(".stmt").text().split(" ")[0],
      $gComment.parent().find(".commentText").text());
  }
  item += "</div>";
  item += "</div>";

  return item;
}

function setSidebarComments() {
  $("#id_CommentList").empty();
  let tablist = $("#id_tabContainer li");
  let item = "";
  for (let i = 0; i < tablist.length; i++) {
    let tab = tablist[i];
    item += templateSidebarCommentList($(tab).attr("title"));
  }
  $("#id_CommentList").append(item);
}

function addComment(funcName, addr, comment) {
  let item = "<div class='comment-list'>";
  item += "<div class='comment-content' title='" + addr + "'>";
  item += "<small class='comment-memory'>" + addr + "</small>";
  item += "<div class='comment-summary'> # " + comment + "</div>";
  item += "</div>";
  item += "</div>";
  $("#id_CommentList .comment-section[value='" + funcName + "']").append(item);
}

Sidebar();
