<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/nehalcanadaedu-maker/tor-threat-hunting-scenarios/blob/main/README.md)

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

### 1. File Download – TOR Installer

* **Timestamp:** `2026-06-03T19:28:07Z`
* **Event:** The user `nehal` downloaded the TOR browser installer through Microsoft Edge. Defender for Endpoint detected the completion of the download when the temporary `.crdownload` file was renamed to the final executable.
* **Action:** File download completed.
* **File Name:** `tor-browser-windows-x86_64-portable-15.0.15.exe`
* **File Path:** `C:\Users\nehal\Downloads\tor-browser-windows-x86_64-portable-15.0.15.exe`

---

### 2. Process Execution – TOR Browser Installer

* **Timestamp:** `2026-06-03T19:30:49Z`
* **Event:** The user `nehal` executed the TOR installer from the Downloads directory, initiating the TOR browser installation process on endpoint `nehalwindows11`.
* **Action:** `ProcessCreated`
* **Command:** `tor-browser-windows-x86_64-portable-15.0.15.exe`
* **File Path:** `C:\Users\nehal\Downloads\tor-browser-windows-x86_64-portable-15.0.15.exe`

---

### 3. Process Execution – TOR Browser Launch

* **Timestamp:** `2026-06-03T19:31:13Z`
* **Event:** User `nehal` launched the TOR browser successfully. Multiple TOR-related processes, including `firefox.exe` and `tor.exe`, were subsequently created.
* **Action:** TOR browser process creation detected.
* **Processes Observed:** `firefox.exe`, `tor.exe`
* **TOR Process Path:** `C:\Users\nehal\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`
* **Browser Path:** `C:\Users\nehal\Desktop\Tor Browser\Browser\firefox.exe`

---

### 4. Network Connections – TOR Network Activity

* **Timestamp:** `2026-06-03T20:18:05Z`
* **Event:** The TOR browser established multiple outbound encrypted network connections over port `443` using `tor.exe`, confirming active TOR network communication.
* **Action:** `ConnectionSuccess`
* **Remote IP Addresses Observed:**

  * `38.180.153.222`
  * `64.65.0.11`
  * `185.82.126.13`
* **Associated Domains:**

  * `www.rmhvmxj5fhpx4ev7vqgq4.com`
  * `www.55zazvhrxt4lmbb.com`
  * `www.l5dcqpj.com`
* **Process:** `tor.exe`
* **Process Path:** `C:\Users\nehal\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

---

### 5. Local TOR Proxy Communication

* **Timestamp:** `2026-06-03T20:18:15Z`
* **Event:** The TOR browser (`firefox.exe`) successfully established a local SOCKS proxy connection to `127.0.0.1` on port `9150`, a commonly used TOR proxy port.
* **Action:** `ConnectionSuccess`
* **Remote IP:** `127.0.0.1`
* **Remote Port:** `9150`
* **Process:** `firefox.exe`
* **Process Path:** `C:\Users\nehal\Desktop\Tor Browser\Browser\firefox.exe`

---

### 6. Failed TOR Initialization Connection

* **Timestamp:** `2026-06-03T19:32:05Z`
* **Event:** A failed connection attempt to the local TOR SOCKS proxy port (`9150`) was detected during the TOR browser initialization process.
* **Action:** `ConnectionFailed`
* **Remote IP:** `127.0.0.1`
* **Remote Port:** `9150`
* **Process:** `firefox.exe`
* **Process Path:** `C:\Users\nehal\Desktop\Tor Browser\Browser\firefox.exe`

---

## Summary

The user "employee" on the "threat-hunt-lab" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `threat-hunt-lab` by the user `employee`. The device was isolated, and the user's direct manager was notified.

---
