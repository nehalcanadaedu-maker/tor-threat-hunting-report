# Threat Hunting Scenario: Unauthorized TOR Browser Usage

## Overview

This threat hunting scenario focuses on detecting unauthorized installation and usage of the TOR Browser within a monitored Windows environment. TOR may be used to bypass organizational network controls, conceal network activity, or communicate through anonymized channels. The objective of this exercise is to identify relevant telemetry, investigate indicators of compromise (IoCs), and validate detection logic using Microsoft Defender XDR and Microsoft Sentinel.

---

## Simulated Activity

The following actions were performed in an isolated lab environment to generate telemetry for analysis:

1. Download the TOR Browser installer from the official TOR Project website.
2. Install the TOR Browser.
3. Launch the TOR Browser.
4. Generate network activity through the TOR network.
5. Create a test file named `test_activity.txt` on the desktop.
6. Modify and delete the test file to generate file system events.
7. Review generated telemetry within Microsoft Defender XDR and Microsoft Sentinel.

---

## Detection Objectives

* Detect TOR Browser download activity.
* Identify TOR Browser installation events.
* Detect TOR-related process execution.
* Identify TOR-related network connections.
* Detect file creation, modification, and deletion activity associated with the simulation.
* Correlate process, file, and network telemetry during the investigation.

---

## Tables Used During Investigation

| Parameter | Description                                                                   |
| --------- | ----------------------------------------------------------------------------- |
| Name      | DeviceFileEvents                                                              |
| Purpose   | Detect file creation, modification, deletion, and TOR installation artifacts. |

| Parameter | Description                                                               |
| --------- | ------------------------------------------------------------------------- |
| Name      | DeviceProcessEvents                                                       |
| Purpose   | Detect TOR Browser installation, process execution, and related activity. |

| Parameter | Description                                                                                           |
| --------- | ----------------------------------------------------------------------------------------------------- |
| Name      | DeviceNetworkEvents                                                                                   |
| Purpose   | Detect outbound network connections associated with TOR processes and analyze communication patterns. |

---

## Investigation Goals

* Identify evidence of unauthorized software installation.
* Correlate process execution with network activity.
* Validate threat hunting queries and detection logic.
* Develop investigation workflows for identifying anonymized network usage.
* Improve organizational visibility into potentially unauthorized applications.

---

## Environment

* Microsoft Defender XDR
* Microsoft Sentinel
* Windows 11 Lab Environment

---

## Author

**Nehal Patel**

LinkedIn: https://www.linkedin.com/in/nehal-patel-162490300/

Date: June 2026

