# Threat-Hunt-Scenario-Tor
# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/andrewgcyber/Threat-Hunt-Scenario-Tor/blob/main/README.md)

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

### 1. Tor Browser Threat Hunt Timeline Report
Device: andrewgay-threa
 User: andrewcyber
 Date: July 27, 2026
Chronological Timeline
11:10:14 AM – Tor Browser installer executed
The earliest evidence of Tor Browser activity was the execution of tor-browser-windows-x86_64-portable-15.0.19.exe from the user's Downloads directory. Microsoft Defender recorded the installer being launched with the command line:
tor-browser-windows-x86_64-portable-15.0.19.exe /S
The /S switch indicates the installer was executed in silent mode, suppressing the normal installation prompts. Defender also recorded the installer SHA-256 hash:
0d4cc3a7b734a10c500217fb0df89452ee39185709193966831677bbd43c98f8
This confirmed the beginning of the Tor Browser installation.

11:10:31 AM – 11:11:40 AM – Tor Browser files created
Reviewing DeviceFileEvents showed numerous Tor-related files being created shortly after the installer executed. The activity indicated that the installer extracted the portable Tor Browser files and copied components onto the user's Desktop.
Artifacts observed included:
tor.exe
Tor Browser.lnk
Tor-Launcher.txt
tor-shopping-list.txt
tor-shopping-list.lnk
The presence of tor-shopping-list.txt and its shortcut suggests the user created or interacted with a text document after Tor Browser had been installed.

11:10:40 AM – Installer process completion
A second process event associated with the installer was recorded, confirming successful completion of the installation process before the browser was launched.

11:11:29 AM – Tor Browser launched
Process creation events showed the user launching Tor Browser (firefox.exe) from:
C:\Users\andrewcyber\Desktop\Tor Browser\Browser\
Immediately after launch, Microsoft Defender recorded numerous child processes including:
firefox.exe
tor.exe
Firefox content processes
GPU process
Utility process
Renderer processes
The spawning of these child processes is consistent with normal Tor Browser initialization.

11:11:42 AM – Tor service initialized
The tor.exe process started using its standard Tor configuration files located within the Tor Browser directory.
The recorded command line showed Tor creating:
Local SOCKS proxy on 127.0.0.1:9150
Local Control Port on 127.0.0.1:9151
These ports are standard for Tor Browser and indicate the Tor service initialized successfully.

11:11:47 AM – 11:11:51 AM – Initial outbound Tor network connections
Within seconds of the Tor service starting, tor.exe successfully established multiple encrypted outbound connections over TCP port 443 to external systems.
Connections included:
193.187.91.79
91.214.191.60
51.89.81.247
Microsoft Defender also recorded several associated remote URLs. These successful outbound TLS connections indicate Tor began communicating with external Tor infrastructure to establish its circuits.

11:12:08 AM – Firefox connected to the local Tor proxy
The Tor Browser process (firefox.exe) successfully connected to:
127.0.0.1:9150
This local connection confirms the browser was successfully communicating with the locally running Tor SOCKS proxy, allowing browser traffic to be routed through the Tor network.

11:12:47 AM – 11:15:02 AM – Continued browser activity
Additional Firefox content processes were created as browsing activity continued. These processes represent additional browser tabs and renderer processes that are expected during normal Tor Browser operation.

11:15:05 AM – Local proxy connection failure
One network event showed firefox.exe experiencing a failed connection attempt to:
127.0.0.1:9150
Although this indicates a temporary communication failure between Firefox and the local Tor proxy, it does not appear to have prevented continued Tor usage because additional Tor activity occurred afterward.

11:20:16 AM – 11:20:19 AM – Tor Browser reopened
A second sequence of process creation events was observed.
Microsoft Defender recorded:
firefox.exe launching again
tor.exe starting again
Multiple Firefox child processes being created
This indicates the user reopened Tor Browser or started a second browser session.

11:20:26 AM – Additional outbound Tor connections
Following the second launch, tor.exe again established successful outbound encrypted connections over TCP port 443 to external Tor infrastructure, including:
51.89.81.247
91.214.191.60
These successful network connections demonstrate the second Tor Browser session also successfully connected to the Tor network.



---

## Summary

The evidence shows that andrewcyber executed the Tor Browser Portable 15.0.19 installer in silent mode, resulting in the successful extraction and creation of multiple Tor Browser artifacts on the endpoint, including tor.exe, Tor Browser.lnk, Tor-Launcher.txt, and a user-created file named tor-shopping-list.txt. Shortly after installation, the user launched Tor Browser, causing firefox.exe and tor.exe to execute along with the expected browser child processes. The Tor service initialized successfully by creating the standard local SOCKS proxy (127.0.0.1:9150) and Control Port (127.0.0.1:9151), after which tor.exe established multiple encrypted outbound connections over TCP port 443 to external Tor infrastructure. Defender also recorded firefox.exe successfully communicating with the local Tor proxy on 127.0.0.1:9150, confirming browser traffic was being routed through the Tor service. A later set of process and network events showed the browser being launched again, followed by another successful series of outbound Tor connections. Overall, the collected telemetry confirms the successful installation, execution, and active use of Tor Browser on the endpoint during the investigation period. 


---

## Response Taken

TOR usage was confirmed on endpoint andrewgay-threa by the user “andrewcyber”. The device was isolated and the user's direct manager was notified.


---
