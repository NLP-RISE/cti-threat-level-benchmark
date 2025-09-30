# Threat Report: 2022-10-06: Obama207 QAKBOT (QBOT) infection with Cobalt Strike


## Key Intelligence
* Date: 2022-10-06
* Threat Level: 1 (High)
* Tags: tlp:white

---

## Indicators of Compromise (IOCs)
### External analysis
* link: https://github.com/pan-unit42/tweets/blob/master/2022-09-29-IOCs-for-Obama207-Qakbot-and-Cobalt-Strike.txt

### Network activity
* ip-dst|port: 186.90.144.235|2222 — QAKBOT C2 TRAFFIC
* ip-dst|port: 186.81.122.168|443 — QAKBOT C2 TRAFFIC
* ip-dst|port: 85.86.242.245|443 — QAKBOT C2 TRAFFIC
* ip-dst|port: 193.3.19.137|443 — QAKBOT C2 TRAFFIC
* url: http://194.165.16.64/prepare/add.mp4a — GET / COBALT STRIKE TRAFFIC
* url: http://194.165.16.64/risk.ico — GET / COBALT STRIKE TRAFFIC
* url: http://194.165.16.64/target — POST / COBALT STRIKE TRAFFIC

## Objects
### file — File object describing a file with meta-information
* [Payload delivery] sha256: <sha256>
* [Payload delivery] filename: REF#5689_Sep_28.html
* [Other] size-in-bytes: 839474

### file — File object describing a file with meta-information
* [Payload delivery] sha256: <sha256>
* [Payload delivery] filename: attachment.zip
* [Other] size-in-bytes: 410653

### file — File object describing a file with meta-information
* [Payload delivery] sha256: <sha256>
* [Payload delivery] filename: REF.lnk
* [Other] size-in-bytes: 1245

### file — File object describing a file with meta-information
* [Payload delivery] sha256: <sha256>
* [Payload delivery] filename: gaffes\eloquentGlummer.js
* [Other] size-in-bytes: 154

### file — File object describing a file with meta-information
* [Payload delivery] sha256: <sha256>
* [Payload delivery] filename: gaffes\acknowledgeablyPartner.cmd
* [Other] size-in-bytes: 142

### file — File object describing a file with meta-information
* [Payload delivery] sha256: <sha256>
* [Payload delivery] filename: gaffes\wheelwright.db
* [Other] size-in-bytes: 712192
