# ConsoleLogin from a new ASN

Trigger: Alert: AWS console login from an ASN not seen in 90 days  
Started 2026-09-18 14:00:00 UTC on Splunk (index main); last change 2026-09-19 14:05:00 UTC. Status: open.

## Timeline

### 2026-09-18

14:02  Pinned `userIdentity.arn` = `arn:aws:iam::123456789012:user/bob` on aws:cloudtrail (index main, Splunk) from event ev-1 at 13:59:55 in search `index=main sourcetype=aws:cloudtrail eventName=ConsoleLogin`. Reason: the principal on the alert.

14:03  Pinned `sourceIPAddress` = `203.0.113.9` on aws:cloudtrail (index main, Splunk) from event ev-1 at 13:59:55 in search `index=main sourcetype=aws:cloudtrail eventName=ConsoleLogin`.

14:04  VirusTotal on `sourceIPAddress` = `203.0.113.9`: 0 of 94 engines flag it; AS64496 (Example Hosting), first seen 2026-09-01.

14:06  From `userIdentity.arn` = `arn:aws:iam::123456789012:user/bob`, pivoted to aws:cloudtrail with `index=main sourcetype=aws:cloudtrail userIdentity.arn="arn:aws:iam::123456789012:user/bob" | stats count by eventName` (SPL): found 14 events, 3 event names, which surfaced `eventName` = `CreateAccessKey`.

14:06  Pinned `eventName` = `CreateAccessKey` on aws:cloudtrail (index main, Splunk) from event ev-9 at 14:05:00 in search `index=main sourcetype=aws:cloudtrail userIdentity.arn="arn:aws:iam::123456789012:user/bob"`. Reason: a new key minted four minutes after the login.

14:08  Finding on `eventName` = `CreateAccessKey`: The access key was created from the same IP as the console login, then used from a different one.

14:09  Parked `userAgent` = `aws-cli/2.15.0`: worth checking whether this CLI version is in the fleet; not on the path to the key.

14:12  Pinned `UserPrincipalName` = `bob@corp.example` on SigninLogs (workspace soc-prod, Sentinel) from event row-7 at 14:11:00 in search `SigninLogs | where UserPrincipalName == 'bob@corp.example'`. Reason: the same person on the Entra side.

14:14  From `UserPrincipalName` = `bob@corp.example`, pivoted to SigninLogs with `SigninLogs | where UserPrincipalName == 'bob@corp.example' | summarize count() by IPAddress, bin(TimeGenerated, 1h)` (KQL): found 2 IPs.

14:15  Verdict on `sourceIPAddress` = `203.0.113.9`: not a known scanner or VPN exit (known corpus).

### 2026-09-19

14:05  Finding: Handed to IR; key disabled at 14:40 the day before.

14:06  Pinned `accessKeyId` = `AKIAIOSFODNN7EXAMPLE` on aws:cloudtrail (index main, Splunk) from event ev-12 at 14:04:00 in search `index=main sourcetype=aws:cloudtrail eventName=CreateAccessKey`.

14:07  Marked `userAgent` = `aws-cli/2.15.0` known benign. Reason: aws-cli/2.15.0 is the fleet standard.

## Findings

- VirusTotal on `sourceIPAddress` = `203.0.113.9`: 0 of 94 engines flag it; AS64496 (Example Hosting), first seen 2026-09-01.
- The access key was created from the same IP as the console login, then used from a different one. (on `eventName` = `CreateAccessKey`)
- Verdict on `sourceIPAddress` = `203.0.113.9`: not a known scanner or VPN exit (known corpus).
- Handed to IR; key disabled at 14:40 the day before.

## Open threads

- `userAgent` = `aws-cli/2.15.0`: worth checking whether this CLI version is in the fleet; not on the path to the key
- `accessKeyId` = `AKIAIOSFODNN7EXAMPLE` on aws:cloudtrail (index main, Splunk), not followed up

## Appendix: values

| value | field | container | scope | platform | event | search | when | kind | reason |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| arn:aws:iam::123456789012:user/bob | userIdentity.arn | aws:cloudtrail | main | splunk | ev-1 2026-09-18 13:59:55 UTC | index=main sourcetype=aws:cloudtrail eventName=ConsoleLogin | 2026-09-18 14:02:00 UTC | pin | the principal on the alert |
| 203.0.113.9 | sourceIPAddress | aws:cloudtrail | main | splunk | ev-1 2026-09-18 13:59:55 UTC | index=main sourcetype=aws:cloudtrail eventName=ConsoleLogin | 2026-09-18 14:03:00 UTC | pin |  |
| CreateAccessKey | eventName | aws:cloudtrail | main | splunk | ev-9 2026-09-18 14:05:00 UTC | index=main sourcetype=aws:cloudtrail userIdentity.arn="arn:aws:iam::123456789012:user/bob" | 2026-09-18 14:06:00 UTC | pin | a new key minted four minutes after the login |
| aws-cli/2.15.0 | userAgent | aws:cloudtrail | main | splunk |  |  | 2026-09-18 14:09:00 UTC | parked | worth checking whether this CLI version is in the fleet; not on the path to the key |
| bob@corp.example | UserPrincipalName | SigninLogs | soc-prod | sentinel | row-7 2026-09-18 14:11:00 UTC | SigninLogs \| where UserPrincipalName == 'bob@corp.example' | 2026-09-18 14:12:00 UTC | pin | the same person on the Entra side |
| AKIAIOSFODNN7EXAMPLE | accessKeyId | aws:cloudtrail | main | splunk | ev-12 2026-09-19 14:04:00 UTC | index=main sourcetype=aws:cloudtrail eventName=CreateAccessKey | 2026-09-19 14:06:00 UTC | pin |  |

<details><summary>Machine copy (for import into Reach)</summary>

```json reach-notebook
{"kind":"reach-notebook","v":1,"investigation":{"id":"inv_fixture","title":"ConsoleLogin from a new ASN","created":1789740000000,"updated":1789826700000,"trigger":"Alert: AWS console login from an ASN not seen in 90 days","status":"open","entries":[{"id":"e1","kind":"pin","at":1789740120000,"reason":"the principal on the alert","field":"userIdentity.arn","value":"arn:aws:iam::123456789012:user/bob","from":{"platform":"splunk","container":"aws:cloudtrail","column":"userIdentity.arn","scope":"main","event":{"id":"ev-1","time":1789739995000},"search":{"text":"index=main sourcetype=aws:cloudtrail eventName=ConsoleLogin","sid":"1758204120.123"}}},{"id":"e2","kind":"pin","at":1789740180000,"field":"sourceIPAddress","value":"203.0.113.9","from":{"platform":"splunk","container":"aws:cloudtrail","column":"sourceIPAddress","scope":"main","event":{"id":"ev-1","time":1789739995000},"search":{"text":"index=main sourcetype=aws:cloudtrail eventName=ConsoleLogin","sid":"1758204120.123"}}},{"id":"e3","kind":"enrichment","at":1789740240000,"source":"VirusTotal","summary":"0 of 94 engines flag it; AS64496 (Example Hosting), first seen 2026-09-01","on":"e2","result":{"malicious":0,"harmless":94,"asn":64496}},{"id":"e4","kind":"pivot","at":1789740360000,"name":"aws:cloudtrail","origin":"e1","target":"e5","found":"14 events, 3 event names","query":{"text":"index=main sourcetype=aws:cloudtrail userIdentity.arn=\"arn:aws:iam::123456789012:user/bob\" | stats count by eventName","language":"SPL"},"from":{"platform":"splunk","container":"aws:cloudtrail","column":"eventName","scope":"main","search":{"text":"index=main sourcetype=aws:cloudtrail eventName=ConsoleLogin","sid":"1758204120.123"}}},{"id":"e5","kind":"pin","at":1789740360000,"reason":"a new key minted four minutes after the login","field":"eventName","value":"CreateAccessKey","from":{"platform":"splunk","container":"aws:cloudtrail","column":"eventName","scope":"main","event":{"id":"ev-9","time":1789740300000},"search":{"text":"index=main sourcetype=aws:cloudtrail userIdentity.arn=\"arn:aws:iam::123456789012:user/bob\""}}},{"id":"e6","kind":"note","at":1789740480000,"text":"The access key was created from the same IP as the console login, then used from a different one.","on":"e5","finding":true},{"id":"e7","kind":"parked","at":1789740540000,"field":"userAgent","why":"worth checking whether this CLI version is in the fleet; not on the path to the key","value":"aws-cli/2.15.0","from":{"platform":"splunk","container":"aws:cloudtrail","column":"userAgent","scope":"main"}},{"id":"e8","kind":"pin","at":1789740720000,"reason":"the same person on the Entra side","field":"UserPrincipalName","value":"bob@corp.example","from":{"platform":"sentinel","container":"SigninLogs","column":"UserPrincipalName","scope":"soc-prod","event":{"id":"row-7","time":1789740660000},"search":{"text":"SigninLogs | where UserPrincipalName == 'bob@corp.example'"}}},{"id":"e9","kind":"pivot","at":1789740840000,"name":"SigninLogs","origin":"e8","found":"2 IPs","query":{"text":"SigninLogs | where UserPrincipalName == 'bob@corp.example' | summarize count() by IPAddress, bin(TimeGenerated, 1h)","language":"KQL"}},{"id":"e10","kind":"verdict","at":1789740900000,"source":"known corpus","verdict":"not a known scanner or VPN exit","on":"e2"},{"id":"e11","kind":"note","at":1789826700000,"text":"Handed to IR; key disabled at 14:40 the day before.","finding":true},{"id":"e12","kind":"pin","at":1789826760000,"field":"accessKeyId","value":"AKIAIOSFODNN7EXAMPLE","from":{"platform":"splunk","container":"aws:cloudtrail","column":"accessKeyId","scope":"main","event":{"id":"ev-12","time":1789826640000},"search":{"text":"index=main sourcetype=aws:cloudtrail eventName=CreateAccessKey"}}},{"id":"e13","kind":"benign","at":1789826820000,"reason":"aws-cli/2.15.0 is the fleet standard","on":"e7"}],"from":{"platform":"splunk","container":"aws:cloudtrail","scope":"main"}}}
```

</details>
