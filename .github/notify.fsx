#!/usr/bin/env -S dotnet fsi
open System
open System.Text
open System.Net.Http

(* Posts a Google Chat card to the WEBHOOK_URL webhook. Two cards live here:
   the everyday one announcing a push, and the alarming one a workflow sends
   when it fails. They share their machinery, so both read as one family of
   messages in the chat room. *)

/// Escapes a string so that it can be embedded in a JSON string literal.
let escape (s: string) =
  let sb = StringBuilder()
  for ch in s do
    match ch with
    | '"' -> sb.Append "\\\"" |> ignore
    | '\\' -> sb.Append "\\\\" |> ignore
    | '\b' -> sb.Append "\\b" |> ignore
    | '\f' -> sb.Append "\\f" |> ignore
    | '\n' -> sb.Append "\\n" |> ignore
    | '\r' -> sb.Append "\\r" |> ignore
    | '\t' -> sb.Append "\\t" |> ignore
    | ch when ch < ' ' -> sb.Append $"\\u{int ch:x4}" |> ignore
    | ch -> sb.Append ch |> ignore
  sb.ToString()

/// Shortens a commit hash down to the seven characters GitHub shows.
let shorten (commitID: string) =
  if commitID.Length > 7 then commitID[..6] else commitID

/// Renders the card header, which carries the actor's avatar either way.
let header title subtitle login =
  $$"""
        "header": {
          "title": "{{title}}",
          "subtitle": "{{subtitle}}",
          "imageUrl": "https://github.com/{{login}}.png",
          "imageType": "CIRCLE"
        }"""

/// Renders a widget holding one line of formatted text.
let decoratedText text =
  $$"""
              {
                "decoratedText": {
                  "text": "{{text}}",
                  "wrapText": true
                }
              }"""

/// Renders a widget holding a paragraph of formatted text.
let textParagraph text =
  $$"""
              {
                "textParagraph": {
                  "text": "{{text}}"
                }
              }"""

/// Wraps text in the red that reads as a warning in a chat room. The quotes
/// stay backslashed, since the result goes straight into a JSON string.
let alert text = $$"""<font color=\"#c53129\">{{text}}</font>"""

/// The solid red fill that marks the button leading to a failed run.
let alertFill =
  """,
                      "color": {
                        "red": 0.84,
                        "green": 0.19,
                        "blue": 0.16,
                        "alpha": 1
                      }"""

/// Renders a button opening the given link; a fill, when given, colors it.
let button text url fill =
  $$"""
                    {
                      "text": "{{text}}",
                      "onClick": {
                        "openLink": {
                          "url": "{{url}}"
                        }
                      }{{fill}}
                    }"""

/// Renders a widget holding the given buttons side by side.
let buttonList buttons =
  let buttons = String.concat "," buttons
  $$"""
              {
                "buttonList": {
                  "buttons": [{{buttons}}
                  ]
                }
              }"""

/// Wraps a header and its widgets into a one-section card message.
let card cardID header widgets =
  let widgets = String.concat "," widgets
  $$"""
{
  "cards_v2": [
    {
      "cardId": "{{cardID}}",
      "card": {
{{header}},
        "sections": [
          {
            "collapsible": false,
            "widgets": [{{widgets}}
            ]
          }
        ]
      }
    }
  ]
}
"""

/// Reads the pushed commit message from msg.txt as a subject and a body.
let commitMessage () =
  let raw = (IO.File.ReadAllText "msg.txt").Replace("\r\n", "\n")
  let lines = raw.Trim().Split '\n'
  escape lines[0], escape (String.Join("\n", lines[1..]).Trim())

/// Builds the everyday card announcing a push.
let pushCard login branch commitID commitURL compareURL =
  let subject, body = commitMessage ()
  let title = $"{escape login} pushed to {escape branch}"
  let bodyWidgets = if body = "" then [] else [ textParagraph body ]
  let buttons =
    buttonList [ button "View commit" commitURL ""
                 button "Compare changes" compareURL "" ]
  [ decoratedText $"<b>{subject}</b>" ] @ bodyWidgets @ [ buttons ]
  |> card "push-notification" (header title (shorten commitID) login)

/// Builds the card warning that a workflow run has failed.
let failureCard login branch commitID commitURL runURL workflow =
  let workflow = escape workflow
  let branch = escape branch
  let shortID = shorten commitID
  let title = $"⚠️ {workflow} failed"
  let headline = alert $"<b>{workflow}</b> failed on <b>{branch}</b>"
  let buttons =
    buttonList [ button "View failed run" runURL alertFill
                 button "View commit" commitURL "" ]
  [ decoratedText headline
    textParagraph $"Commit {shortID} pushed by {escape login}."
    buttons ]
  |> card "failure-notification" (header title $"{branch} · {shortID}" login)

/// Prints how to call this script and gives up.
let usage () =
  eprintfn "Usage: notify.fsx MODE ARGS, where MODE ARGS is one of"
  eprintfn "push <actor> <branch> <commit> <commitURL> <compareURL>"
  eprintfn "failure <actor> <branch> <commit> <commitURL> <runURL> <workflow>"
  exit 1

let json =
  match fsi.CommandLineArgs[1..] with
  | [| "push"; actor; branch; commit; commitURL; compareURL |] ->
    pushCard actor branch commit commitURL compareURL
  | [| "failure"; actor; branch; commit; commitURL; runURL; workflow |] ->
    failureCard actor branch commit commitURL runURL workflow
  | _ -> usage ()

(* A fork's pull request gets no webhook, and neither does a local dry run, so
   print the card instead of failing on an empty URL. *)
let webhookURL = Environment.GetEnvironmentVariable "WEBHOOK_URL"
if String.IsNullOrEmpty webhookURL then
  Console.WriteLine "No WEBHOOK_URL is set; the card below was not sent."
  Console.WriteLine json
  exit 0

let succeeded, response =
  async {
    use client = new HttpClient()
    use content = new StringContent(json, Encoding.UTF8, "application/json")
    let! res = client.PostAsync(Uri webhookURL, content) |> Async.AwaitTask
    let! text = res.Content.ReadAsStringAsync() |> Async.AwaitTask
    return res.IsSuccessStatusCode, text
  }
  |> Async.RunSynchronously

Console.WriteLine response
if not succeeded then exit 1
