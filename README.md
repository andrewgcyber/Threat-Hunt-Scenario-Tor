# Threat-Hunt-Scenario-Tor
# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/joshmadakor0/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
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

### 1. Searched the DeviceFileEvents table for files containing the string "tor" associated with device andrewgay-threa and user andrewcyber, identifying the start of Tor-related activity at 2026-07-27 14:57:26 UTC. The results revealed the creation of multiple Tor artifacts, including tor.exe, Tor Browser.lnk, Tor-Launcher.txt, tor-shopping-list.txt, and tor-shopping-list.lnk, indicating that a Tor Browser installer had been downloaded, extracted, and its components copied to the user's desktop. I then pivoted to DeviceProcessEvents to verify process execution and confirmed that tor-browser-windows-x86_64-portable-15.0.19.exe was executed with the command line tor-browser-windows-x86_64-portable-15.0.19.exe /S, where the /S switch indicates a silent installation. Correlating the file and process events confirmed the successful execution of the Tor Browser installer, the creation of multiple Tor-related files on the endpoint, and the presence of the user-created file tor-shopping-list.txt, providing a timeline of the installation and subsequent user activity.

Query used to locate events 


DeviceFileEvents
| where DeviceName == "andrewgay-threa"
| where FileName contains "tor"
| where Timestamp >= datetime(2026-07-27T14:57:26.1061885Z)
| where InitiatingProcessAccountName == "andrewcyber"
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName


___________
Searched the DeviceProcessEvents table for any ProcessCommandLine that contained the string 
“tor-browser-windows-x86_64-portable-15.0.19.exe”


At 11:10:14 AM on July 27, 2026, the user andrewcyber launched the Tor Browser Portable installer from their Downloads folder on the device andrewgay-threa. The installer file, tor-browser-windows-x86_64-portable-15.0.19.exe, was started with the /S command-line switch, indicating an attempt to run the installer in silent mode without displaying the normal installation prompts. Microsoft Defender recorded the creation of this process and captured the file's SHA-256 hash (0d4cc3a7b734a10c500217fb0df89452ee39185709193966831677bbd43c98f8) for identification.


Query used to locate event:
DeviceProcessEvents
| where DeviceName == "andrewgay-threa"
| where ProcessCommandLine contains "tor-browser-windows-x86_64"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine, AccountName


________________


Searched the DeviceProcessEvents table for any indication that user “andrewcyber” actually opened the tor browser. There was evidence that they did open it at 2026-07-27T15:11:29.3409067Z. There were several other instances of firefox.exe(Tor) as well as tor.exe spawned afterwords

Query used to locate events: 


DeviceProcessEvents
| where DeviceName =="andrewgay-threa"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine, AccountName


___________


Searched the DeviceNetworkEvents table for any indication the tor browser was used to establish a connection using any of the known tor ports. At 2026-07-27T15:12:08.4847434Z, the Tor Browser process (firefox.exe) running under the “andrewcyber” user account successfully established a network connection to the local host (127.0.0.1) on port 9150. The browser was launched from C:\Users\andrewcyber\Desktop\Tor Browser\Browser\firefox.exe. The connection to port 9150 indicates that the browser successfully communicated with the locally running Tor proxy, a normal step in routing browser traffic through the Tor network. There were a couple other connections to site over port 443


Query used to locate events:


DeviceNetworkEvents
| where DeviceName == "andrewgay-threa"
| where InitiatingProcessAccountName != "system"
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")
| project Timestamp, DeviceName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessAccountName, InitiatingProcessFolderPath
| order by Timestamp desc






---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2024-11-08T22:14:48.6065231Z`
- **Event:** The user "employee" downloaded a file named `tor-browser-windows-x86_64-portable-14.0.1.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2024-11-08T22:16:47.4484567Z`
- **Event:** The user "employee" executed the file `tor-browser-windows-x86_64-portable-14.0.1.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.0.1.exe /S`
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2024-11-08T22:17:21.6357935Z`
- **Event:** User "employee" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\employee\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2024-11-08T22:18:01.1246358Z`
- **Event:** A network connection to IP `176.198.159.33` on port `9001` by user "employee" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2024-11-08T22:18:08Z` - Connected to `194.164.169.85` on port `443`.
  - `2024-11-08T22:18:16Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "employee" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2024-11-08T22:27:19.7259964Z`
- **Event:** The user "employee" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\employee\Desktop\tor-shopping-list.txt`

---

## Summary

The user "employee" on the "threat-hunt-lab" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `threat-hunt-lab` by the user `employee`. The device was isolated, and the user's direct manager was notified.

---
