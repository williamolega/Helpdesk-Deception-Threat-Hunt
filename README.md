# Threat Hunt Report: Helpdesk Deception

## Platforms and Languages Leveraged
- Log Analytics Workspaces (Microsoft Azure)
- Kusto Query Language (KQL)

## Scenario

October is known to be spooky, and this year is no different. In the first half of the month, an unfamiliar script surfaced in the user's Downloads directory. Not long after, multiple machines were found to start spawning processes originating from the Downloads folder as well. The machines were found to share the same types of files, naming patterns, and similar executables. The goal is to identify what the attacker has compromised and to eradicate any persistence they may have established.

### High-Level IoC Discovery Plan
- **Check `DeviceProcessEvents`** to identify the suspicious machine, recon attempts in network & priviledges.
- **Check `DeviceFileEvents`** to identify any security posture changes, consolidation of artifacts, and any planted narratives.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections and transfer attempts.

---

## Starting Point

establish the suspicious machine
```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-16))
| where ProcessCommandLine contains "Download"
| where ProcessCommandLine matches regex @"(?i)(desk|help|support|tool).*\.exe"
```
<img width="1838" height="447" alt="image" src="https://github.com/user-attachments/assets/624843d7-198a-4c26-a4e4-1570703bf002" />

Question: Identify the most suspicious machine based on the given conditions

<details>
<summary>Click to see answer</summary>
  
  Answer: `gab-intern-vm`
</details>

---

### 🚩 1. Initial Execution Detection

```kql
DeviceProcessEvents
    //search the first half of October 2025
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-16))
    //suspicious machine
| where DeviceName == "gab-intern-vm"
    //looking for unusual executions
| where ProcessCommandLine contains "powershell"
| project TimeGenerated, DeviceName, ProcessCommandLine
| order by TimeGenerated asc
```
<img width="1820" height="390" alt="image" src="https://github.com/user-attachments/assets/84a0a9ff-120b-43da-be66-4d9de293f1f0" />

Question: What was the first CLI parameter name used during the execution of the suspicious program?

<details>
<summary>Click to see answer</summary>
  
  Answer: `-ExecutionPolicy`
</details>

---

### 🚩 2. Defense Disabling

```kql
//search for artifact creation
DeviceFileEvents
    //search the first half of October 2025
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
    //suspicious machine
| where DeviceName == "gab-intern-vm"
    //search for tamper
| where FileName matches regex @"(?i)(tamper)"
| project TimeGenerated, DeviceName, ActionType, FileName, FolderPath
| order by TimeGenerated asc

```
<img width="1828" height="423" alt="image" src="https://github.com/user-attachments/assets/71e3a830-df5c-4511-a56c-a07ecd9470da" />

Question: What was the name of the file related to this exploit?

<details>
<summary>Click to see answer</summary>
  
  Answer: `DefenderTamperArtifact.lnk`
</details>

---

### 🚩 3. Quick Data Probe

```kql
//looking for checks, actions that read data
DeviceProcessEvents
    //search the first half of October 2025
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
    //suspicious machine
| where DeviceName == "gab-intern-vm"
    //action
| where FileName contains "powershell"
    //hint offered
| where ProcessCommandLine contains "clip"
| project TimeGenerated, DeviceName, ActionType, FileName, FolderPath, ProcessCommandLine
| order by TimeGenerated asc

```
<img width="1826" height="480" alt="image" src="https://github.com/user-attachments/assets/9a4278b8-c675-441a-9df8-00617f3583d7" />

Question: Provide the command value tied to this particular exploit.

<details>
<summary>Click to see answer</summary>
  
  Answer: `"powershell.exe" -NoProfile -Sta -Command "try { Get-Clipboard | Out-Null } catch { }"`
</details>

---

### 🚩 4. Host Context Recon

```kql
   //looking for activity/actions
DeviceProcessEvents
    //search the first half of October 2025
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
    //suspicious machine
| where DeviceName == "gab-intern-vm"
    //hint offered
| where ProcessCommandLine contains "qwi"
| project TimeGenerated, DeviceName, ActionType, FileName, FolderPath, ProcessCommandLine
| order by TimeGenerated asc

```
<img width="1835" height="518" alt="image" src="https://github.com/user-attachments/assets/ad98c9f7-ff8c-49a2-b464-2dde764f3afb" />

Question: Point out when the last recon attempt was.

<details>
<summary>Click to see answer</summary>
  
  Answer: `2025-10-09T12:51:44.3425653Z`
</details>

---

### 🚩 5. Storage Surface Mapping

```kql
   //looking for discovery of storage, looking for chekcs of available storage
DeviceProcessEvents
    //search the first half of October 2025
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
    //suspicious machine
| where DeviceName == "gab-intern-vm"
    //look for filesystem/share surface enumeration, lightweight storage checks
| where tolower(ProcessCommandLine) has_any ("net share", "net view", "dir /s", "Get-Volume", "Get-SmbShare", "wmic", "fsutil fsinfo drives", "Get-CimInstance -ClassName Win32_LogicalDisk")
| project TimeGenerated, DeviceName, AccountName, FolderPath, ProcessCommandLine
| order by TimeGenerated asc
```
<img width="1835" height="481" alt="image" src="https://github.com/user-attachments/assets/0a3f932a-f744-48f2-9205-40851e317dad" />

Question: Provide the 2nd command tied to this activity.

<details>
<summary>Click to see answer</summary>
  
  Answer: `"cmd.exe" /c wmic logicaldisk get name,freespace,size`
</details>

---

### 🚩 6. Connectivity & Name Resolution Check

```kql
   //looking for checks on the network and name resolution
DeviceProcessEvents
    //search the first half of October 2025
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
    //suspicious machine
| where DeviceName == "gab-intern-vm"
| where ProcessCommandLine has_any ("ping", "nslookup", "curl", "Test-NetConnection", "tracert")
    //action taken for checks
| where FileName contains "powershell" or FileName contains "cmd"
    //validate Network reachability
| where ProcessCommandLine has_any ("ping", "tracert", "nslookup")
    //hint offered
| where IsProcessRemoteSession == "true"
| project TimeGenerated, DeviceName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessParentFileName, IsProcessRemoteSession
| order by TimeGenerated asc
```
<img width="1829" height="562" alt="image" src="https://github.com/user-attachments/assets/f7541770-2420-4a03-9280-536f5a41667a" />

Question: Provide the File Name of the initiating parent process.

<details>
<summary>Click to see answer</summary>
  
  Answer: `RuntimeBroker.exe`
</details>

---

### 🚩 7. Interactive Session Discovery

```kql
    //looking for actions to detect sessions
DeviceProcessEvents
    //search the first half of October 2025
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
    //suspicious machine
| where DeviceName == "gab-intern-vm"
    //qwinsta command displays info on active user session
| where ProcessCommandLine contains ("qwi")
| project TimeGenerated, DeviceName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessUniqueId
```
<img width="1834" height="532" alt="image" src="https://github.com/user-attachments/assets/d67deef9-645f-461f-b894-4eea2ced8d25" />

Question: What is the unique ID of the initiating process?

<details>
<summary>Click to see answer</summary>
  
  Answer: `2533274790397065`
</details>

---

### 🚩 8. Runtime Application Inventory

```kql

```
picture
Question: Provide the file name of the process that best demonstrates a runtime process enumeration event on the target host.

<details>
<summary>Click to see answer</summary>
  
  Answer: `tasklist.exe`
</details>

---

### 🚩 9. Privilege Surface Check

```kql
   //looking for attempts to understand priviledges available
DeviceProcessEvents
    //search the first half of October 2025
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
    //suspicious machine
| where DeviceName == "gab-intern-vm"
| where ProcessCommandLine contains "whoami"
| project TimeGenerated, DeviceName, FileName, FolderPath, ProcessCommandLine
| order by TimeGenerated asc
| take 1
```
<img width="1835" height="510" alt="image" src="https://github.com/user-attachments/assets/22c8ce83-1fef-474e-b1b7-30bc6852f86f" />

Question: Identify the timestamp of the very first attempt.

<details>
<summary>Click to see answer</summary>
  
  Answer: `2025-10-09T12:52:14.3135459Z`
</details>

---

### 🚩 10. Proof-of-Access & Egress Validation

```kql
   //looking for actions that validate outbound reachability and attempt to capture host state
DeviceNetworkEvents
    //search the first half of October 2025
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
    //suspicious machine
| where DeviceName == "gab-intern-vm"
    //Initiating Parent File Name related to network events/outward connectivity probes
| where InitiatingProcessParentFileName contains "runtimebroker.exe"
| project TimeGenerated, ActionType, DeviceName, InitiatingProcessFileName, RemoteUrl
| order by TimeGenerated asc
```
<img width="1834" height="515" alt="image" src="https://github.com/user-attachments/assets/4b2a4f3b-d678-4ba1-b97d-97e02e1bd950" />

Question: Which outbound destination was contacted first?

<details>
<summary>Click to see answer</summary>
  
  Answer: `www.msftconnecttest.com`
</details>

---

### 🚩 11. Bundling / Staging Artifacts

```kql
   //Looking for File system events. Looking for consolidation of artifacts
DeviceFileEvents
    //search the first half of October 2025
| where TimeGenerated between (datetime(2025-10-09) .. datetime(2025-10-16))
    //suspicious machine
| where DeviceName == "gab-intern-vm"
    //Executable file responsible for launching the current process
| where InitiatingProcessParentFileName contains "runtimebroker.exe"
    //hint offered
| where FileName has_any ("zip")
| project TimeGenerated, DeviceName, FileName, FolderPath, InitiatingProcessFileName
| order by TimeGenerated asc
```
<img width="1834" height="461" alt="image" src="https://github.com/user-attachments/assets/57d42d93-cca5-4752-a7df-e8f51f1af917" />

Question: Provide the full folder path value where the artifact was first dropped into.

<details>
<summary>Click to see answer</summary>
  
  Answer: `C:\Users\Public\ReconArtifacts.zip`
</details>

---

### 🚩 12. Outbound Transfer Attempt (Simulated)

```kql
   //Looking for network event indicating outbound transfers
DeviceNetworkEvents
    //search the first half of October 2025
| where TimeGenerated between (datetime(2025-10-09) .. datetime(2025-10-16))
    //suspicious machine
| where DeviceName == "gab-intern-vm"
    //Executable file responsible for launching the current process
| where InitiatingProcessParentFileName contains "runtimebroker.exe"
| project TimeGenerated, DeviceName, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessParentFileName
| order by TimeGenerated desc
```
<img width="1842" height="510" alt="image" src="https://github.com/user-attachments/assets/e5849d93-159a-43ff-a22e-760c2ee1ee49" />

Question: Provide the IP of the last unusual outbound connection.

<details>
<summary>Click to see answer</summary>
  
  Answer: `100.29.147.161`
</details>

---

### 🚩 13. Scheduled Re-Execution Persistence

```kql
   //looking for creation of scheduler-related events
DeviceProcessEvents
    //search the first half of October 2025
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
    //suspicious machine
| where DeviceName == "gab-intern-vm"
    //Executable file responsible for launching the current process
| where InitiatingProcessParentFileName contains "runtimebroker.exe"
| project TimeGenerated, DeviceName, FileName, FolderPath, ProcessCommandLine
| order by TimeGenerated desc
```
<img width="1834" height="511" alt="image" src="https://github.com/user-attachments/assets/0f03dd2d-dd50-45dd-8877-228aa83f297a" />

Question: Provide the value of the task name down below.

<details>
<summary>Click to see answer</summary>
  
  Answer: `SupportToolUpdater`
</details>

---

### 🚩 14. Autorun Fallback Persistence

```kql

```
picture

Question: What was the name of the registry value?

<details>
<summary>Click to see answer</summary>
  
  Answer: `RemoteAssistUpdater`
</details>
---

### 🚩 15. Planted Narrative / Cover Artifact

```kql
    //Looking for "explanatory" file creation. 
DeviceFileEvents
    //Time should be immediately after creating the scheduler event
| where TimeGenerated > (todatetime('2025-10-09T13:01:29.7815532Z'))
    //suspicious machine
| where DeviceName == "gab-intern-vm"
| order by TimeGenerated asc
```
<img width="1831" height="607" alt="image" src="https://github.com/user-attachments/assets/718cf402-0b2f-43ca-a85a-ce5c69dc9dfb" />

Question: Identify the file name of the artifact left behind.

<details>
<summary>Click to see answer</summary>
  
  Answer: `SupportChat_log.lnk`
</details>

---

| Flag | Description                        | Value |
|------|------------------------------------|-------|
|Start | Suspicious Machine                 | gab-intern-vm |
| 1    | 1st CLI parameter used in execution            | -ExecutionPolicy |
| 2    | File related to Exploit            | DefenderTamperArtifact.lnk |
| 3    | Exploit Command Value              | "powershell.exe" -NoProfile -Sta -Command "try { Get-Clipboard | Out-Null } catch { }" |
| 4    | Last Recon Attempt                 | 2025-10-09T12:51:44.3425653Z |
| 5    | 2nd Command tied to Mapping                | "cmd.exe" /c wmic logicaldisk get name,freespace,size |
| 6    | Initiating Parent Process File Name                     | RuntimeBroker.exe |
| 7    | Initiating Process Unique ID              | 2533274790397065 |
| 8    | Process Inventory                     | tasklist.exe |
| 9    | 1st attempt timestamp      | 2025-10-09T12:52:14.3135459Z |
| 10   | 1st Outbound Destination          | www.msftconnecttest.com |
| 11   | Artifact 1st full folder path            | C:\Users\Public\ReconArtifacts.zip |
| 12   | Unusual outbound IP          | 100.29.147.161 |
| 13   | Task Name Value               | SupportToolUpdater |
| 14   | Registry Value Name                      | RemoteAssistUpdater |
| 15   | Artifact left behind               | SupportChat_log.lnk |

---

🧠 Logical Flow & Analyst Reasoning
0 ➝ 1 🚩: An unfamiliar script surfaced in the user’s Downloads directory. Was this SupportTool.ps1 executed under the guise of IT diagnostics?

1 ➝ 2 🚩: Initial execution often precedes an attempt to weaken defenses. Did the operator attempt to tamper with security tools to reduce visibility?

2 ➝ 3 🚩: With protections probed, the next step is quick data checks. Did they sample clipboard contents to see if sensitive material was immediately available?

3 ➝ 4 🚩: Attackers rarely stop with clipboard data. Did they expand into broader environmental reconnaissance to understand the host and user context?

4 ➝ 5 🚩: Recon of the system itself is followed by scoping available storage. Did the attacker enumerate drives and shares to see where data might live?

5 ➝ 6 🚩: After scoping storage, connectivity is key. Did they query network posture or DNS resolution to validate outbound capability?

6 ➝ 7 🚩: Once network posture is confirmed, live session data becomes valuable. Did they check active users or sessions that could be hijacked or monitored?

7 ➝ 8 🚩: Session checks alone aren’t enough — attackers want a full picture of the runtime. Did they enumerate processes to understand active applications and defenses?

8 ➝ 9 🚩: Process context often leads to privilege mapping. Did the operator query group memberships and privileges to understand access boundaries?

9 ➝ 10 🚩: With host and identity context in hand, attackers often validate egress and capture evidence. Was there an outbound connectivity check coupled with a screenshot of the user’s desktop?

10 ➝ 11 🚩: After recon and evidence collection, staging comes next. Did the operator bundle key artifacts into a compressed archive for easy movement?

11 ➝ 12 🚩: Staging rarely stops locally — exfiltration is tested soon after. Were outbound HTTP requests attempted to simulate upload of the bundle?

12 ➝ 13 🚩: Exfil attempts imply intent to return. Did the operator establish persistence through scheduled tasks to ensure continued execution?

13 ➝ 14 🚩: Attackers rarely trust a single persistence channel. Was a registry-based Run key added as a fallback mechanism to re-trigger the script?

14 ➝ 15 🚩: Persistence secured, the final step is narrative control. Did the attacker drop a text log resembling a helpdesk chat to possibly justify these suspicious activities? 
