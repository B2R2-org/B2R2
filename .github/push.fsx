#!/usr/bin/env -S dotnet fsi
open System
open System.Text
open System.Net.Http

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

let webhookURL = Environment.GetEnvironmentVariable "WEBHOOK_URL"
let login = fsi.CommandLineArgs[1]
let actor = escape login
let branch = escape fsi.CommandLineArgs[2]
let commitID = fsi.CommandLineArgs[3]
let compareURL = fsi.CommandLineArgs[4]
let commitURL = fsi.CommandLineArgs[5]
let shortID = if commitID.Length > 7 then commitID[..6] else commitID
let raw = (IO.File.ReadAllText "msg.txt").Replace("\r\n", "\n")
let lines = raw.Trim().Split '\n'
let subject = escape lines[0]
let body = escape (String.Join("\n", lines[1..]).Trim())

let bodyWidget =
  if body = "" then
    ""
  else
    $$"""
              ,{
                "textParagraph": {
                  "text": "{{body}}"
                }
              }"""

let json = $$"""
{
  "cards_v2": [
    {
      "cardId": "push-notification",
      "card": {
        "header": {
          "title": "{{actor}} pushed to {{branch}}",
          "subtitle": "{{shortID}}",
          "imageUrl": "https://github.com/{{login}}.png",
          "imageType": "CIRCLE"
        },
        "sections": [
          {
            "collapsible": false,
            "widgets": [
              {
                "decoratedText": {
                  "text": "<b>{{subject}}</b>",
                  "wrapText": true
                }
              }{{bodyWidget}},
              {
                "buttonList": {
                  "buttons": [
                    {
                      "text": "View commit",
                      "onClick": {
                        "openLink": {
                          "url": "{{commitURL}}"
                        }
                      }
                    },
                    {
                      "text": "Compare changes",
                      "onClick": {
                        "openLink": {
                          "url": "{{compareURL}}"
                        }
                      }
                    }
                  ]
                }
              }
            ]
          }
        ]
      }
    }
  ]
}
"""

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
