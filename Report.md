# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/nehalcanadaedu-maker/tor-threat-hunting-scenarios/blob/main/README.md)

## Quick Navigation

1. [Platforms and Languages Leveraged](#platforms-and-languages-leveraged)  
2. [Scenario](#scenario)  
3. [Investigation Steps](#steps-taken)  
4. [Chronological Event Timeline](#chronological-event-timeline)  
5. [Related Detection Queries](#related-queries)  
6. [Investigation Summary](#summary)  
7. [Response Taken](#response-taken)  

## Platforms and Languages Leveraged
- Windows 11 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched the DeviceFileEvents table for any files containing the string "tor" associated with the user nehal on endpoint nehalwindows11.

The investigation revealed that the user downloaded a TOR browser installer through Microsoft Edge. Microsoft Defender for Endpoint logged a FileRenamed event showing the temporary download file Unconfirmed 889517.crdownload being renamed to:

tor-browser-windows-x86_64-portable-15.0.15.exe

This confirmed that the TOR installer download completed successfully. The installer was downloaded to the following location:

C:\Users\nehal\Downloads\tor-browser-windows-x86_64-portable-15.0.15.exe

The activity began at:

2026-06-03T19:28:07Z

**Query used to locate events:**

```kql
DeviceFileEvents  
| where DeviceName == "nehalwindows11"  
| where InitiatingProcessAccountName == "nehal"  
| where FileName contains "tor"  
| where Timestamp >= datetime(2024-11-08T22:14:48.6065231Z)  
| order by Timestamp desc  
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="1262" height="277" alt="image" src="https://github.com/user-attachments/assets/dc836f32-0c21-41ea-ba6e-3d19e47d36dd" />

---

### 2. Searched the `DeviceProcessEvents` Table

The DeviceProcessEvents table was queried to identify execution activity associated with the TOR browser installer on endpoint nehalwindows11.

Analysis of the logs confirmed that the user nehal executed the file:

tor-browser-windows-x86_64-portable-15.0.15.exe

from the Downloads directory at:

2026-06-03T19:30:49Z

The event type ProcessCreated confirmed successful execution of the TOR installer, indicating that the installation process had begun on the endpoint. The process execution originated directly from the user context and was associated with the downloaded TOR installer binary.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "nehalwindows11"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.15.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc
```
<img width="1783" height="445" alt="image" src="https://github.com/user-attachments/assets/0293d6c8-59a0-4954-8605-2a369f5d5767" />

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

The DeviceProcessEvents table was analyzed to determine whether the user nehal successfully launched and used the TOR browser on endpoint nehalwindows11.

The investigation confirmed TOR browser execution activity beginning at:

2026-06-03T19:31:13Z

Multiple ProcessCreated events associated with firefox.exe and tor.exe were observed originating from the TOR Browser installation directory:

C:\Users\nehal\Desktop\Tor Browser\

The telemetry showed numerous TOR-related browser subprocesses being spawned, including browser tabs, GPU processes, utility processes, and TOR networking processes. Additionally, the execution of tor.exe confirmed that the TOR client service was initialized using local SOCKS proxy port 9150 and control port 9151.

This activity confirmed that the TOR browser launched successfully and was actively operating on the endpoint.

**Query used to locate events:**

```kql
DeviceProcessEvents  
| where DeviceName == "nehalwindows11"  
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine  
| order by Timestamp desc
```
<img width="1235" height="233" alt="image" src="https://github.com/user-attachments/assets/db4dfdae-ffc4-41e1-b5df-8ce15322d0e8" />

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

The DeviceNetworkEvents table was analyzed to identify outbound network connections associated with TOR browser activity on endpoint nehalwindows11.

The investigation confirmed multiple successful outbound connections initiated by tor.exe and firefox.exe from the TOR Browser installation directory:

C:\Users\nehal\Desktop\Tor Browser\

At 2026-06-03T20:18:05Z, the TOR process successfully established encrypted outbound connections over port 443 to multiple remote IP addresses and domains, including:

38.180.153.222
64.65.0.11
185.82.126.13

Associated domains included:

www.rmhvmxj5fhpx4ev7vqgq4.com
www.55zazvhrxt4lmbb.com
www.l5dcqpj.com

Additionally, at 2026-06-03T20:18:15Z, the TOR browser (firefox.exe) established a successful local SOCKS proxy connection to:

127.0.0.1:9150

This is a commonly used TOR local proxy port and further confirmed active TOR browser communication and routing behavior.

The investigation also identified an earlier failed connection attempt to 127.0.0.1:9150 at 2026-06-03T19:32:05Z, likely occurring during the TOR initialization process before the local proxy service became fully operational.

These network events confirmed active TOR network communication from the endpoint.

**Query used to locate events:**

```kql
DeviceNetworkEvents  
| where DeviceName == "nehalwindows11"  
| where InitiatingProcessAccountName != "system"  
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")  
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")  
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath  
| order by Timestamp desc
```
<img width="1242" height="272" alt="image" src="https://github.com/user-attachments/assets/5620a2c9-6057-4ff2-9e23-b38aca0c3bfc" />

---

## Chronological Event Timeline

| Timestamp (UTC)       | Event                                       | Action / Evidence                                                  | Process or File                                   | Additional Details                                                          |
| --------------------- | ------------------------------------------- | ------------------------------------------------------------------ | ------------------------------------------------- | --------------------------------------------------------------------------- |
| `2026-06-03 19:28:07` | TOR installer downloaded                    | `FileRenamed` confirmed the browser download completed             | `tor-browser-windows-x86_64-portable-15.0.15.exe` | Saved to `C:\Users\nehal\Downloads\`                                        |
| `2026-06-03 19:30:49` | TOR installer executed                      | `ProcessCreated` confirmed installation activity                   | `tor-browser-windows-x86_64-portable-15.0.15.exe` | Executed by user `nehal` from the Downloads directory                       |
| `2026-06-03 19:31:13` | TOR Browser launched                        | Multiple TOR-related processes were created                        | `firefox.exe`, `tor.exe`                          | Processes originated from `C:\Users\nehal\Desktop\Tor Browser\`             |
| `2026-06-03 19:32:05` | Initial local proxy connection failed       | `ConnectionFailed`                                                 | `firefox.exe`                                     | Connection attempted to `127.0.0.1:9150` while TOR was initializing         |
| `2026-06-03 20:18:05` | TOR network communication established       | Multiple successful encrypted outbound connections over port `443` | `tor.exe`                                         | Connections observed to `38.180.153.222`, `64.65.0.11`, and `185.82.126.13` |
| `2026-06-03 20:18:15` | Local SOCKS proxy communication established | `ConnectionSuccess`                                                | `firefox.exe`                                     | Browser connected to the TOR SOCKS proxy at `127.0.0.1:9150`                |

---

## Related Queries:
```kql
// Installer name == tor-browser-windows-x86_64-portable-(version).exe
// Detect the installer being downloaded
DeviceFileEvents
| where FileName startswith "tor"
```
<img width="1221" height="197" alt="image" src="https://github.com/user-attachments/assets/aba8f1c1-b67c-4c13-86dd-a1890c5d9ba5" />

```kql
// TOR Browser being silently installed
// Take note of two spaces before the /S (I don't know why)
DeviceProcessEvents
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.0.1.exe  /S"
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine
```
<img width="1190" height="256" alt="image" src="https://github.com/user-attachments/assets/1ea38d96-982d-4fbd-84d0-d33f76ad7a25" />


```kql
// TOR Browser or service was successfully installed and is present on the disk
DeviceFileEvents
| where FileName has_any ("tor.exe", "firefox.exe")
| project  Timestamp, DeviceName, RequestAccountName, ActionType, InitiatingProcessCommandLine
```
<img width="1266" height="207" alt="image" src="https://github.com/user-attachments/assets/e0e65df6-e18c-40ff-801a-f86bb97f036a" />


```kql
// TOR Browser or service was launched
DeviceProcessEvents
| where ProcessCommandLine has_any("tor.exe","firefox.exe")
| project  Timestamp, DeviceName, AccountName, ActionType, ProcessCommandLine
```
<img width="1205" height="297" alt="image" src="https://github.com/user-attachments/assets/6568dc92-bec7-4fe0-ab6c-bdf3d680c2da" />


```kql
// TOR Browser or service is being used and is actively creating network connections
DeviceNetworkEvents
| where InitiatingProcessFileName in~ ("tor.exe", "firefox.exe")
| where RemotePort in (9001, 9030, 9040, 9050, 9051, 9150)
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, RemoteIP, RemotePort, RemoteUrl
| order by Timestamp desc
```
<img width="1268" height="205" alt="image" src="https://github.com/user-attachments/assets/380a5aba-3960-4bfd-8010-2b4176a13867" />

```kql
// User shopping list was created and, changed, or deleted
DeviceFileEvents
| where FileName contains "shopping-list.txt"
```

<img width="1535" height="195" alt="Screenshot 2026-06-04 001506" src="https://github.com/user-attachments/assets/58988ae2-a2c1-442e-bdbe-c999bcf2da51" />

---
## Summary

The user "nehal" on the "nehalwindows11" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `nehalwindows11` by the user `nehal`. The device was isolated, and the user's direct manager was notified.

---


