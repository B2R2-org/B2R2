#!/usr/bin/env -S dotnet fsi
open System
open System.Text
open System.Net.Http

let url = fsi.CommandLineArgs[1]
let actor = fsi.CommandLineArgs[2]
let branch = fsi.CommandLineArgs[3]
let commitID = fsi.CommandLineArgs[4]
let compareURL = fsi.CommandLineArgs[5]
let msg = IO.File.ReadAllText "msg.txt"
let json = $$"""
{
  "cards_v2": [
    {
      "cardId": "Push Notification",
      "card": {
        "header": {
          "title": "`{{actor}}` pushed to {{branch}}",
          "subtitle": "{{commitID}}",
          "imageUrl": "https://softsec.kaist.ac.kr/depot/logos/github.png",
          "imageType": "CIRCLE"
        },
        "sections": [
          {
            "collapsible": false,
            "widgets": [
              {
                "decoratedText": {
                  "text": "{{msg}}",
                  "wrapText": true,
                  "onClick": {
                    "openLink": {
                      "url": "{{compareURL}}"
                    }
                  }
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
async {
  use client = new HttpClient ()
  use content = new StringContent (json, Encoding.UTF8, "application/json")
  let! msg = client.PostAsync (Uri url, content) |> Async.AwaitTask
  return! msg.Content.ReadAsStringAsync () |> Async.AwaitTask
}
|> Async.RunSynchronously
|> Console.WriteLine
