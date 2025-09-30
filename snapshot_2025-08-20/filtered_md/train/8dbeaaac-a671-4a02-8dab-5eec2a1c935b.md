# Threat Report: 2022-09-12: Ragnar Locker Ransomware Targeting the Energy Sector


## Key Intelligence
* Date: 2022-09-12
* Threat Level: 2 (Medium)
* Tags: misp:tool="misp-scraper", osint:source-type="blog-post", misp:event-type="collection", misp-galaxy:sector="Energy", misp-galaxy:malpedia="RagnarLocker (Windows)", misp-galaxy:mitre-malware="Ragnar Locker - S0481", misp-galaxy:ransomware="Ragnar Locker", misp-galaxy:country="greece", misp-galaxy:mitre-attack-pattern="Data Encrypted for Impact - T1486", misp-galaxy:mitre-attack-pattern="Disable or Modify Tools - T1562.001", misp-galaxy:mitre-attack-pattern="Inhibit System Recovery - T1490", misp-galaxy:mitre-attack-pattern="Process Discovery - T1057", misp-galaxy:mitre-attack-pattern="Service Stop - T1489", misp-galaxy:mitre-attack-pattern="System Information Discovery - T1082", misp-galaxy:mitre-attack-pattern="System Location Discovery - T1614", misp-galaxy:mitre-attack-pattern="System Owner/User Discovery - T1033", tlp:white

---

## Indicators of Compromise (IOCs)
### Artifacts dropped
* regkey: *%LOCALAPPDATA%\packages\microsoft.windows.cortana\_cw5n1h2txyewy\localstate\devicesearchcache\appcache133057346751796032.txt.ragnar\_aabbddcc*

### External analysis
* link: https://www.cybereason.com/blog/threat-analysis-report-ragnar-locker-ransomware-targeting-the-energy-sector — Blog URL

### Other
* comment: THREAT ANALYSIS REPORT: Ragnar Locker Ransomware Targeting the Energy Sector — Blog title
* comment: wmic.exe shadowcopy delete: This system command deletes all shadow copies on the victim’s system, preventing data recovery by the victim — Ragnar Locker spawns the following children process:
* comment: vssadmin delete shadows /all /quiet: This system command also deletes shadow copies, preventing data recovery by the victim — Ragnar Locker spawns the following children process:
* comment: notepad.exe [User path]\RGNR_AABBCCDD.txt : This command launches Notepad.exe to show the ransom note to the victim — Ragnar Locker spawns the following children process:
* comment: Azerbaijan
Armenia
Belarus
Kazakhstan
Kyrgyzstan
Moldova
Tajikistan
Russia
Turkmenistan
Uzbekistan
Ukraine
Georgia — Excluded countries
* comment: vss, sql, memtas, mepocs, sophos, veeam, backup, pulseway, logme, logmein, connectwise, splashtop, kaseya, vmcompute, Hyper-v, vmms, Dfs — Stopped services

### Payload delivery
* sha256: <sha256> — Ragnar Locker Binary
* sha256: <sha256> — Ragnar Locker Binary
* sha256: <sha256> — Ragnar Locker Binary
* sha256: <sha256> — Ragnar Locker Binary
* sha256: <sha256> — Ragnar Locker Binary
* sha256: <sha256> — Ragnar Locker Binary
* sha256: <sha256> — Ragnar Locker Binary
* sha256: <sha256> — Ragnar Locker Binary
* sha256: <sha256> — Ragnar Locker Binary
* sha256: <sha256> — Ragnar Locker Binary
* sha256: <sha256> — Ragnar Locker Binary
* sha256: <sha256> — Ragnar Locker Binary
* sha256: <sha256> — Ragnar Locker Binary
* sha256: <sha256> — Ragnar Locker Binary
* sha256: <sha256> — Ragnar Locker Binary
* sha256: <sha256> — Ragnar Locker Binary
* sha256: <sha256> — Ragnar Locker Binary
* sha256: <sha256> — Ragnar Locker Binary
* sha256: <sha256> — Ragnar Locker Binary
* sha256: <sha256> — Ragnar Locker Binary
* sha256: <sha256> — Ragnar Locker Binary
* sha256: <sha256> — Ragnar Locker Binary
* sha256: <sha256> — Ragnar Locker Binary
* sha256: <sha256> — Ragnar Locker Binary
* sha256: <sha256> — Ragnar Locker Binary
* sha256: <sha256> — Ragnar Locker Binary
* sha256: <sha256> — Ragnar Locker Binary
* sha256: <sha256> — Ragnar Locker Binary
* sha256: <sha256> — Ragnar Locker Binary
* sha256: <sha256> — Ragnar Locker Binary
* sha256: <sha256> — Ragnar Locker Binary
* sha256: <sha256> — Ragnar Locker Binary
* sha256: <sha256> — Ragnar Locker Binary
* sha256: <sha256> — Ragnar Locker Binary
* sha256: <sha256> — Ragnar Locker Binary
* filename: ntuser.dat.log
* filename: bootfront.bin

## Objects
### file — File object describing a file with meta-information
* [Payload delivery] filename: RGNR_AABBCCDD.txt — Replace with the hashed computer name
* [Other] text: %PUBLIC%\Documents\
