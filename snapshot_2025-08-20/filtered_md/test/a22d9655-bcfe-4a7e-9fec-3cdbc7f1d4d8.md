# Threat Report: 2024-01-24: ESET takes part in global operation to disrupt the Grandoreiro banking trojan


## Key Intelligence
* Date: 2024-01-24
* Threat Level: 2 (Medium)
* Tags: tlp:white, misp-galaxy:malpedia="Grandoreiro", misp-galaxy:mitre-malware="Grandoreiro - S0531", misp-galaxy:target-information="Argentina", misp-galaxy:target-information="Brazil", misp-galaxy:target-information="Mexico", misp-galaxy:target-information="Spain"

---

## Indicators of Compromise (IOCs)
### External analysis
* link: https://www.welivesecurity.com/en/eset-research/eset-takes-part-global-operation-disrupt-grandoreiro-banking-trojan/

### Network activity
* ip-dst: 20.237.166.161 — C2
* ip-dst: 20.120.249.43 — C2
* ip-dst: 52.161.154.239 — C2
* ip-dst: 167.114.138.249 — C2
* ip-dst: 66.70.160.251 — C2
* ip-dst: 167.114.4.175 — C2
* ip-dst: 18.215.238.53 — C2
* ip-dst: 54.219.169.167 — C2
* ip-dst: 3.144.135.247 — C2
* ip-dst: 77.246.96.204 — C2
* ip-dst: 185.228.72.38 — C2
* ip-dst: 62.84.100.225 — Distribution serverr
* ip-dst: 20.151.89.252 — Distribution serverr

### Other
* comment: cloud providers such as Azure and AWS to host their network infrastructure
* comment: When a Latin American banking trojan successfully compromises a machine, it usually issues an HTTP GET request to a remote server
* comment: generated domains are registered via No-IP’s Dynamic DNS service (DDNS)

## Objects
### file — File object describing a file with meta-information
* [Payload delivery] sha1: <sha1>
* [Payload delivery] filename: Notif.FEL.RHKVYIIPFVBCGQJPOQÃ.msi

### file — File object describing a file with meta-information
* [Payload delivery] sha1: <sha1>
* [Payload delivery] filename: RYCB79H7B-7DVH76Y3-67DVHC6T20-CH377DFHVO-6264704.msi

### file — File object describing a file with meta-information
* [Payload delivery] sha1: <sha1>
* [Payload delivery] filename: pcre.dll

### file — File object describing a file with meta-information
* [Payload delivery] sha1: <sha1>
* [Payload delivery] filename: iconv.dll
