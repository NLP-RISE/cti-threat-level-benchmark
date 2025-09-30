# Threat Report: 2025-01-29: Phorpiex - Downloader Delivering Ransomware


## Key Intelligence
* Date: 2025-01-29
* Threat Level: 2 (Medium)
* Tags: misp-galaxy:botnet="Phorpiex", misp-galaxy:financial-fraud="Ransomware", misp-galaxy:groups="LockBit Ransomware Actors & Affiliates", misp-galaxy:malpedia="Phorpiex", misp-galaxy:software="LockBit 3.0", misp-galaxy:mitre-attack-pattern="Registry Run Keys / Startup Folder - T1547.001", misp-galaxy:mitre-attack-pattern="Clear Persistence - T1070.009", misp-galaxy:mitre-attack-pattern="Malicious File - T1204.002", misp-galaxy:mitre-attack-pattern="Spearphishing Attachment - T1566.001", misp-galaxy:mitre-attack-pattern="Disable or Modify Tools - T1562.001", misp-galaxy:mitre-attack-pattern="Double File Extension - T1036.007", misp-galaxy:mitre-attack-pattern="Time Based Evasion - T1497.003", misp-galaxy:mitre-attack-pattern="Software Packing - T1027.002", misp-galaxy:mitre-attack-pattern="System Checks - T1497.001", misp-galaxy:mitre-attack-pattern="Masquerade File Type - T1036.008", misp-galaxy:mitre-attack-pattern="Application Layer Protocol - T1071", tlp:clear

---

## Indicators of Compromise (IOCs)
### Artifacts dropped
* mutex: PreLoad

### External analysis
* link: https://www.cybereason.com/blog/threat-analysis-phorpiex-downloader

### Network activity
* url: http://twizt.net — LNK file downloads spl.exe from this URL
* ip-dst: 193.233.132.177 — Used by SCR file pic0502024.jpg.scr

### Payload delivery
* email-src: jenny@gsd[.]com
* email-src: ebe6941ee8a10c14dc933ae37a0f43fc@gsd[.]com
* filename: lslut.exe — Downloaded from hxxp://twizt[.]net
* sha256: <sha256> — ZIP file related to TWIZT downloader variant, delivered via phishing emails.
* sha256: <sha256> — Document.doc.lnk within the attached ZIP file document.zip.
* sha256: <sha256> — ZIP file related to LockBit downloader variant, delivered via phishing emails.
* sha256: <sha256> — TWIZT downloader executable
* sha256: <sha256> — GandCrab downloader executable
* sha256: <sha256> — LockBit downloader executable

## Objects
### file — File object describing a file with meta-information
* [Payload delivery] filename: DeviceManager.exe
* [Payload delivery] sha256: <sha256>

### file — File object describing a file with meta-information
* [Payload delivery] filename: windrv.exe
* [Payload delivery] sha256: <sha256>

### file — File object describing a file with meta-information
* [Payload delivery] sha256: <sha256>
* [Payload delivery] filename: PIC0502024.jpg.scr
