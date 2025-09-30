# Threat Report: 2021-05-27: APT Actors Exploiting Fortinet Vulnerabilities to Gain Access for Malicious Activity


## Key Intelligence
* Date: 2021-05-27
* Threat Level: 2 (Medium)
* Tags: misp-galaxy:mitre-tool="Mimikatz - S0002", tlp:white

---

## Indicators of Compromise (IOCs)
### External analysis
* vulnerability: CVE-2018-13379
* vulnerability: CVE-2020-12812
* vulnerability: CVE-2019-5591
* link: https://us-cert.cisa.gov/ncas/current-activity/2021/04/02/fbi-cisa-joint-advisory-exploitation-fortinet-fortios

### Other
* comment: The APT actors may have established new user accounts on domain controllers, servers, workstations, and the active directories. Some of these accounts appear to have been created to look similar to other existing accounts on the network, so specific account names may vary per organization. In addition to unrecognized user accounts or accounts established to masquerade as existing accounts, the following account usernames may be associated with this activity:
ï‚· â€œelieâ€
ï‚· â€œWADGUtilityAccountâ€
* comment: Associated Tools
ï‚· Mimikatz (credential theft)
ï‚· MinerGate (crypto mining)
ï‚· WinPEAS (privilege escalation)
ï‚· SharpWMI (Windows Management Instrumentation)
ï‚· BitLocker activation when not anticipated (data encryption)
ï‚· WinRAR where not expected (archiving)
ï‚· FileZilla where not expected (file transfer)
* comment: Unrecognized Scheduled Tasks
The APT actors may have made modifications to the Task Scheduler that may display as unrecognized scheduled tasks or â€œactions.â€ Specifically, the below established task may be associated with this activity:
ï‚· SynchronizeTimeZone
* comment: Outbound Traffic
Any FTP transfers over port 443
* comment: Alert number MI-000148-MW
* comment: Recommended Mitigations
ï‚· Immediately patch CVEs 2018-13379, 2020-12812, and 2019-5591.
ï‚· If FortiOS is not used by your organization, add the key artifact files used by FortiOS to your
organizationâ€™s execution denylist. Any attempts to install or run this program and its associated
files should be prevented.
ï‚· Review domain controllers, servers, workstations, and active directories for new or unrecognized
user accounts.
ï‚· Review Task Scheduler for unrecognized scheduled tasks. Additionally, manually review
operating system defined or recognized scheduled tasks for unrecognized â€œactionsâ€ (for example:
review the steps each scheduled task is expected to perform).
ï‚· Review antivirus logs for indications they were unexpectedly turned off.
ï‚· Regularly back up data, air gap, and password protect backup copies offline. Ensure copies of
critical data are not accessible for modification or deletion from the system where the data
resides.
ï‚· Implement network segmentation.
ï‚· Require administrator credentials to install software.
ï‚· Implement a recovery plan to maintain and retain multiple copies of sensitive or proprietary data
and servers in a physically separate, segmented, secure location (e.g., hard drive, storage device,
the cloud).
ï‚· Install updates/patch operating systems, software, and firmware as soon as updates/patches are
released.
ï‚· Use multifactor authentication where possible.
ï‚· Regularly change passwords to network systems and accounts, and avoid reusing passwords for
different accounts. Implement the shortest acceptable timeframe for password changes.
ï‚· Disable unused remote access/Remote Desktop Protocol (RDP) ports and monitor remote
access/RDP logs.
ï‚· Audit user accounts with administrative privileges and configure access controls with least
privilege in mind.
ï‚· Install and regularly update antivirus and anti-malware software on all hosts.
ï‚· Only use secure networks and avoid using public Wi-Fi networks. Consider installing and using a
virtual private network (VPN).
ï‚· Consider adding an email banner to emails received from outside your organization.
ï‚· Disable hyperlinks in received emails.

### Payload delivery
* filename: Audio.exe
* filename: frpc.exe
* md5: <md5>
* sha1: <sha1>
* imphash: <imphash>
* ssdeep: <ssdeep>
* filename: Frps.exe
* md5: <md5>
* sha1: <sha1>
* imphash: <imphash>
* ssdeep: <ssdeep>
