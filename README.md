# Official `Tor` Project 

<img width="482" height="323" alt="image" src="https://github.com/user-attachments/assets/f68293a8-48ff-4687-ae46-35b6993b602a" />


# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/Kelvin-CyberQ/Threat-Hunting-Scenario/blob/main/Threat-Hunting-Scenario-Tor-event-creation.md)

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

### 1. Searched the `DeviceFileEvents` Table

Searched the DeviceFileEvents table for ANY file that had the string “tor” in it and discovered what looked like the user “kelzteck” downloaded a tor installer, did something that resulted in many tor-related files being copied to the desktop and the creation of a file called “tor-shoping-list.txt” on the desktop. 
These events began at: 2025-07-27T18:41:40.7658703Z


**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "kel-99"
| where InitiatingProcessAccountName == "kelzteck"
| where FileName contains "tor"
| where Timestamp >= datetime(2025-07-27T18:41:40.7658703Z)
| order by Timestamp desc 
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="1072" height="600" alt="image" src="https://github.com/user-attachments/assets/f962425e-3281-4874-8957-5f6c588acee6" />


### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-14.5.5.exe  /s". Based on the logs returned, at `2025-07-27T18:47:21.7513471Z` an employee on the "kel-99" device ran the file “tor-browser-windows-x86_64-portable-14.5.5.exe” from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql
DeviceProcessEvents
| where DeviceName == "kel-99"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.5.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1072" height="571" alt="image" src="https://github.com/user-attachments/assets/205296a5-4fff-4406-a609-5d220cee5dbb" />

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "kel-99" actually opened the TOR browser. There was evidence that they did open it at `2025-07-27T18:49:14.8538462Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "kel-99"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc 
```
<img width="1072" height="571" alt="image" src="https://github.com/user-attachments/assets/3a2277ed-65ee-4b64-bc76-4193f3530511" />

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At ``2025-07-27T18:49:29.0631801Z`, an employee on the "`kelzteck`" device successfully established a connection to the remote IP address `46.22.165.111` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\kelzteck\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "kel-99"
| where InitiatingProcessAccountName != "system"
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")
| project Timestamp,DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc
```
<img width="1072" height="415" alt="image" src="https://github.com/user-attachments/assets/06b4b6f4-50c9-40dd-a42b-8e2b40613d31" />

---

## Chronological Event Timeline 

<h3>Tor Browser Installation and Activity Timeline</h3>

<table>
  <thead>
    <tr>
      <th>#</th>
      <th>Timestamp (UTC)</th>
      <th>Source Log</th>
      <th>File Path</th>
      <th>Action</th>
      <th>Event</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>1</td>
      <td>18 : 41 : 40</td>
      <td>DeviceFileEvents</td>
      <td><code>C:\Users\Kelzteck\Downloads\tor-browser-windows-x86_64-portable-14.5.5.exe</code></td>
      <td>File downloaded</td>
      <td><code>tor-browser-windows-x86_64-portable-14.5.5.exe</code> finishes downloading into Downloads</td>
    </tr>
    <tr>
      <td>2</td>
      <td>18 : 42 : 10</td>
      <td>DeviceProcessEvents</td>
      <td><code>C:\Users\Kelzteck\Downloads\tor-browser-windows-x86_64-portable-14.5.5.exe</code></td>
      <td>Process created</td>
      <td>User kelzteck executes the installer</td>
    </tr>
    <tr>
      <td>3</td>
      <td>18 : 42 : 29</td>
      <td>DeviceProcessEvents</td>
      <td><code>C:\Users\Kelzteck\Downloads\tor-browser-windows-x86_64-portable-14.5.5.exe</code></td>
      <td>Process created</td>
      <td>Second launch of the installer</td>
    </tr>
    <tr>
      <td>4</td>
      <td>18 : 47 : 21</td>
      <td>DeviceProcessEvents</td>
      <td><code>C:\Users\Kelzteck\Downloads\tor-browser-windows-x86_64-portable-14.5.5.exe</code></td>
      <td>Process created</td>
      <td>Installer is re-run silently, targeting Desktop\Tor Browser</td>
    </tr>
    <tr>
      <td>5</td>
      <td>18 : 47 : 22 – 18 : 59 : 48</td>
      <td>DeviceFileEvents</td>
      <td><code>C:\Users\Kelzteck\Desktop\Tor Browser\...</code></td>
      <td>Multiple files created</td>
      <td>Bulk creation of Tor Browser program files (e.g., <code>tor.exe</code>, <code>firefox.exe</code>) under Desktop\Tor Browser\Browser\TorBrowser</td>
    </tr>
    <tr>
      <td>6</td>
      <td>18 : 49 : 14</td>
      <td>DeviceProcessEvents</td>
      <td><code>C:\Users\Kelzteck\Desktop\Tor Browser\Browser\firefox.exe</code></td>
      <td>Process created</td>
      <td><code>firefox.exe</code> (Tor Browser UI) starts from the new install path</td>
    </tr>
    <tr>
      <td>7</td>
      <td>18 : 49 : 29</td>
      <td>DeviceNetworkEvents</td>
      <td><code>C:\Users\Kelzteck\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe</code></td>
      <td>Network connect</td>
      <td>First outbound Tor handshake – <code>tor.exe</code> connects to 23.190.168.243 : 9001</td>
    </tr>
    <tr>
      <td>8</td>
      <td>18 : 49 : 31 – 18 : 49 : 32</td>
      <td>DeviceNetworkEvents</td>
      <td><code>C:\Users\Kelzteck\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe</code></td>
      <td>Network connect</td>
      <td>Additional bootstrap traffic from <code>tor.exe</code> to relays 45.83.105.223 : 443, 46.22.165.111 : 9001, 64.65.0.85 : 443</td>
    </tr>
    <tr>
      <td>9</td>
      <td>19 : 00 : 10</td>
      <td>DeviceProcessEvents</td>
      <td><code>C:\Users\Kelzteck\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe</code></td>
      <td>Process created</td>
      <td>New <code>tor.exe</code> helper instance spawns (background service)</td>
    </tr>
    <tr>
      <td>10</td>
      <td>19 : 00 : 21</td>
      <td>DeviceNetworkEvents</td>
      <td><code>C:\Users\Kelzteck\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe</code></td>
      <td>Network connect</td>
      <td><code>tor.exe</code> builds a circuit to 46.22.165.111 : 9001 and reaches hidden service https://www.dnvks4xxv.com</td>
    </tr>
    <tr>
      <td>11</td>
      <td>19 : 00 : 22 – 19 : 05</td>
      <td>DeviceNetworkEvents</td>
      <td><code>C:\Users\Kelzteck\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe</code></td>
      <td>Network connect (ongoing)</td>
      <td>Continuing Tor traffic over ports 9001 and 443 to multiple relays</td>
    </tr>
    <tr>
      <td>12</td>
      <td>19 : 31 : 05</td>
      <td>DeviceFileEvents</td>
      <td><code>C:\Users\Kelzteck\Desktop\tor-shopping-list.txt</code></td>
      <td>File created</td>
      <td>User creates <code>tor-shopping-list.txt</code> on the Desktop (and corresponding shortcut in Recent Files)</td>
    </tr>
  </tbody>
</table>
`

---

## Summary

The user "kel-99" on the "Kelzteck" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `Kelzteck` by the user `kel-99`. The device was isolated, and the user's direct manager was notified.

---
