---
layout: default
title: Network Monitoring, Event Tracing and Memory Scanning
tags: []
header_type       : "hero"
include_on_search : true
show_tags         : true
---

<div class="bs-component">
    <div class="progress">
        <div class="progress-bar progress-bar-striped progress-bar-animated" role="progressbar" aria-valuemin="0" aria-valuemax="100" style="width: 58.3%; background-color:#eb34e1"></div>
    </div>
</div>

## Introduction

This chapter explores additional log sources, frameworks and technologies that can augment telemetry, and detection and response capabilities. In this chapter, we explore Zeek, ETW, osquery, YARA, and Sigma.


<hr>

## Chapter Content

This section provides reproductions of the key figures and code snippets seen in this chapter.

#### Network Monitoring with Zeek

##### Plugins

Commands to install MITRE ATT&CK's BZAR and confirm successful installation.

```sh
ubuntu@ip-10-0-1-50:/home/ubuntu# sudo -s
root@ip-10-0-1-50:/home/ubuntu# /opt/zeek/bin/zkg install zeek/mitre-attack/bzar
root@ip-10-0-1-50:/home/ubuntu# /opt/zeek/bin/zkg list

zeek/mitre-attack/bzar (installed: master) - BZAR - Bro/Zeek ATT&CK-based Analytics and Reporting.
```

##### Notable Logs

An example of a JSON entry from the `dce_rpc.log` Zeek log file, showing a `DRSGetNCChanges` operation.

```json
{
    "ts":"...",
    "uid":"CwDSP63BmWPjMwYOj4",
    "id.orig_h":"10.0.1.30",
    "id.orig_p":58906,
    "id.resp_h":"10.0.1.14",
    "id.resp_p":49667,
    "rtt":0.0007340908050537109,
    "named_pipe":"49667",
    "endpoint":"drsuapi",
    "operation":"DRSGetNCChanges"
}
```

An example of an entry from the `notice.log` Zeek log file when BZAR detects a file moved to the Attack Range domain controller.

```json
{
    "ts": "...",
    "uid": "CwDSP63BmWPjMwYOj4",
    "id.orig_h": "10.0.1.30",
    "id.orig_p": 58906,
    "id.resp_h": "10.0.1.14",
    "id.resp_p": 445,
    "proto": "tcp",
    "note": "ATTACK::Lateral_Movement",
    "msg": "Detected SMB::FILE_WRITE to admin file share '\\\\ar-win-dc\\c$temp\\agpt.exe'",
    "sub": "T1021.002 Remote Services: SMB/Windows Admin Shares + T1570 Lateral Tool Transfer",
    "src": "10.0.1.30",
    "dst": "10.0.1.14",
    "p": 445,
    "actions": [
        "Notice::ACTION_LOG"
    ],
    "suppress_for": 3600
}
```

##### Event Tracing for Windows

Use of the `logman` tool to list existing event tracing sessions.

```sh
PS C:\Users\Administrator> logman -ets

Data Collector Set                      Type                          Status
------------------------------------------------------------------------------
Eventlog-Security                       Trace                         Running
EventLog-Application                    Trace                         Running
EventLog-System                         Trace                         Running
--snip--
SYSMON TRACE                            Trace                         Running
SysmonDnsEtwSession                     Trace                         Running
```

Further use of `logman` to retrieve details of a specific trace (in this case Sysmon's use of ETW for DNS query logging).

```sh
PS C:\Users\Administrator> logman 'SysmonDnsEtwSession' -ets

Name:                 SysmonDnsEtwSession
Status:               Running
Root Path:            %systemdrive%\PerfLogs\Admin
Segment:              Off
Schedules:            On
Segment Max Size:     1 MB

Name:                 SysmonDnsEtwSession\SysmonDnsEtwSession
Type:                 Trace
Append:               Off
Circular:             Off
Overwrite:            Off
Buffer Size:          64
Buffers Lost:         0
Buffers Written:      195
Buffer Flush Timer:   1
Clock Type:           Performance
File Mode:            Real-time

Provider:
Name:                 Microsoft-Windows-DNS-Client
Provider Guid:        {1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}
Level:                4 (win:Informational)
KeywordsAll:          0x0
KeywordsAny:          0xffffffffffffffff 
--snip--
Properties:           64
Filter Type:          0
```

A command to fetch an execute the contents of a remote file via PowerShell, resulting in the initial domain name resolution which will produce a DNS Client Event entry.

```powershell
iex(iwr https://aguidetopurpleteaming.com/resources/7/etw.txt)
```

##### Filtering for Events of Interest

As performed in [Chapter 4](/part-II/collecting-telemetry/), we can query the DNS logs produced by Event Tracing using Event Viewer or `wevtutil`. An example query for DNS lookups of this site can be performed as follows.

```xml
<QueryList>
  <Query Id="0" Path="Microsoft-Windows-DNS-Client/Operational">
    <Select Path="Microsoft-Windows-DNS-Client/Operational">     
      *[EventData[Data[@Name='QueryName']='aguidetopurpleteaming.com']]
    </Select>
  </Query>
</QueryList>
```

An example of an event log result is shown here.

```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-DNS-Client" Guid="{1c95126e-7eea-49a9-a3fe-a378b03ddb4d}" /> 
    <EventID>3006</EventID> 
    <Level>4</Level> 
    --snip--
    <EventRecordID>1054</EventRecordID> 
    <Correlation ActivityID="{a9fa96ac-7f96-0001-2ed6-faa9967fda01}" /> 
    <Execution ProcessID="5584" ThreadID="3904" /> 
    <Channel>Microsoft-Windows-DNS-Client/Operational</Channel> 
    <Computer>ar-win-dc</Computer> 
    <Security UserID="S-1-5-21-1097896708-1628162418-3612758767-500" /> 
  </System>
  <EventData>
    <Data Name="QueryName">aguidetopurpleteaming.com</Data> 
    <Data Name="QueryType">1</Data> 
    <Data Name="QueryOptions">1073766400</Data> 
    <Data Name="ServerList" /> 
    <Data Name="IsNetworkQuery">0</Data> 
    <Data Name="NetworkQueryIndex">0</Data> 
    <Data Name="InterfaceIndex">0</Data> 
    <Data Name="IsAsyncQuery">0</Data> 
  </EventData>
</Event>
```

By comparison, here is the equivalent Sysmon event for the DNS lookup.

```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385f-c22a-43e0-bf4c-06f5698ffbd9}" /> 
    <EventID>22</EventID> 
    <Level>4</Level> 
    --snip--
    <EventRecordID>3050</EventRecordID> 
    <Correlation /> 
    <Execution ProcessID="2732" ThreadID="3460" /> 
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel> 
    <Computer>ar-win-dc</Computer> 
    <Security UserID="S-1-5-18" /> 
  </System>
  <EventData>
    --snip--
    <Data Name="ProcessGuid">{46d76aeb-f24a-6602-1802-00000000d702}</Data> 
    <Data Name="ProcessId">5584</Data> 
    <Data Name="QueryName">aguidetopurpleteaming.com</Data> 
    <Data Name="QueryStatus">0</Data> 
    <Data Name="QueryResults">::ffff:185.199.110.153;::ffff:185.199.111.153;::ffff:185.199.108.153;::ffff:185.199.109.153;</Data> 
    <Data Name="Image">C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data> 
    <Data Name="User">AR-WIN-DC\Administrator</Data> 
  </EventData>
</Event>
```


#### Osquery

##### Exploring Configurations and Query Packs

Here is the Attack Range Linux host osquery configuration found at `/etc/osquery/osquery.conf`.

```json
{
  "options": {
    "logger_path": "/var/log/osquery",
    "schedule_splay_percent": "10",
    --snip--
    "utc": "true"
  },
  "schedule": {
    "crontab": {
       "query" : "SELECT * FROM crontab;",
       "interval": 300
    },
    --snip--
    "system_info": {
      "query": "SELECT hostname, cpu_brand, physical_memory FROM system_info;",
      "interval": 3600
    }
  },
  "decorators": {
    "load": [
      "SELECT uuid AS host_uuid FROM system_info;",
      "SELECT user AS username FROM logged_in_users ORDER BY time DESC LIMIT 1;"
    ]
  },
  "packs": {
    "osquery-monitoring": "/opt/osquery/share/osquery/packs/osquery-monitoring.conf",
    "incident-response": "/opt/osquery/share/osquery/packs/incident-response.conf",
    "it-compliance": "/opt/osquery/share/osquery/packs/it-compliance.conf",
    "vuln-management": "/opt/osquery/share/osquery/packs/vuln-management.conf",
    "hardware-monitoring": "/opt/osquery/share/osquery/packs/hardware-monitoring.conf",
    "ossec-rootkit": "/opt/osquery/share/osquery/packs/ossec-rootkit.conf",
    "attack-range": "/opt/osquery/share/osquery/packs/attack-range.conf"
  },
  --snip--
}
```

Outputting the contents of one of the query packs referenced in the above configuration, we can see the following.

```json
root@ar-linux:~# cat /opt/osquery/share/osquery/packs/attack-range.conf
{
  "platform": "linux",
  "queries": {
    "process_events":{
      "query": "SELECT auid, cmdline, ctime, cwd, egid, euid, gid, parent, path, pid, time, uid FROM process_events WHERE path NOT IN ('/bin/sed', '/usr/bin/tr', '/bin/gawk', '/bin/date', '/bin/mktemp', '/usr/bin/dirname', '/usr/bin/head', '/usr/bin/jq', '/bin/cut', '/bin/uname', '/bin/basename') and cmdline NOT LIKE '%_key%' AND cmdline NOT LIKE '%secret%';",
      "interval": 10,
      "description": "Process events collected from the audit framework"
    },
    "authorized_keys": {
      "query": "SELECT * FROM users CROSS JOIN authorized_keys USING (uid);",
      "interval": 86400,
      "description": "A line-delimited authorized_keys table."
    },
    "behavioral_reverse_shell": {
      "query": "SELECT DISTINCT(processes.pid), processes.parent, processes.name, processes.path, processes.cmdline, processes.cwd, processes.root, processes.uid, processes.gid, processes.start_time, process_open_sockets.remote_address, process_open_sockets.remote_port, (SELECT cmdline FROM processes AS parent_cmdline WHERE pid=processes.parent) AS parent_cmdline FROM processes JOIN process_open_sockets USING (pid) LEFT OUTER JOIN process_open_files ON processes.pid = process_open_files.pid WHERE (name='sh' OR name='bash') AND remote_address NOT IN ('0.0.0.0', '::', '') AND remote_address NOT LIKE '10.%' AND remote_address NOT LIKE '192.168.%';",
      "interval": 600,
      "description": "Find shell processes that have open sockets"
    }
  },
  "file_paths": {
    "configuration": [
      "/etc/shadow",
      --snip--
      "/etc/crontab"
    ],
    "binaries": [
      "/usr/bin/%%",
      --snip--
      "/usr/sbin/%%"
    ]
  }
}
```

An example of a <i>discovery</i> query that can be used to apply different osquery packs and configurations based on the results of the query.

```json
{
  "discovery": [
    "SELECT pid FROM processes WHERE name = 'apache2';",
    "SELECT hostname FROM system_info WHERE hostname like 'ar-web%';"
  ],
  "queries": {
    --snip--
  }
}
```


##### Running Queries on the Command Line

Using the osquery CLI tool, `osqueryi`, to run queries interactively. First, getting the loaded queries and their scheduled frequency.

```sh
root@ar-linux:~# osqueryi

osquery> SELECT name, interval FROM osquery_schedule;
+--------------------------------------------------+----------+
| name                                             | interval |
+--------------------------------------------------+----------+
| crontab                                          | 300      |
| system_info                                      | 3600     |
| system_profile                                   | 3600     |
--snip--
| pack_attack-range_authorized_keys                | 86400    |
| pack_attack-range_behavioral_reverse_shell       | 600      |
| pack_attack-range_dns_resolvers                  | 3600     |
| pack_attack-range_ec2_instance_metadata          | 3600     |
| pack_attack-range_ec2_instance_metadata_snapshot | 86400    |
| pack_attack-range_ec2_instance_tags              | 3600     |
+--------------------------------------------------+----------+
```

Then, running a query to see the list of local users (formatting with JSON output).

```sh
root@ar-linux:~# osqueryi --json 'SELECT username FROM users;'
[
    {"username":"root"},
    {"username":"daemon"},
    {"username":"bin"},
    {"username":"sys"},
    --snip--
    {"username":"agpt"},
]
```

Another query to fetch `crontab` entries.

```sh
root@ar-linux:~# osqueryi --json 'SELECT command FROM crontab;'

+---------------------------------------------------------------------------+
| command                                                                   |
+---------------------------------------------------------------------------+
| root cd / && run-parts --report /etc/cron.hourly                          |
--snip--
| root test -e /run/systemd/system || SERVICE_MODE=1 /sbin/e2scrub_all ...  |
+---------------------------------------------------------------------------+
```

A log entry produced in `/var/log/osquery/osqueryd.results.log` that highlights a change to system configuration as a result of the scheduled queries in the osquery configuration.

```json
{
    "name": "crontab",
    "hostIdentifier": "ec26f56f-e007-0deb-74b7-8278550336d3",
    --snip--
    "epoch": 0,
    "counter": 3,
    "numerics": false,
    "decorations": {
        "host_uuid": "ec26f56f-e007-0deb-74b7-8278550336d3",
        "username": ""
    },
    "columns": {
        "command": "whoami",
        "day_of_month": "*",
        "day_of_week": "*",
        "event": "",
        "hour": "*",
        "minute": "0",
        "month": "*",
        "path": "/var/spool/cron/crontabs/root"
    },
    "action": "added"
}
```

#### YARA Scanning

##### Exploring Rule Syntax

A YARA rule from Florian Roth for detecting strings known to be present in Mimikatz.

| Sourced from: <a target="_blank" href="https://github.com/Neo23x0/signature-base/blob/c943048164788661f6d25f58fbfd849acdeddc38/yara/gen_mimikatz.yar">https://github.com/Neo23x0/signature-base/blob/c943048164788661f6d25f58fbfd849acdeddc38/yara/gen_mimikatz.yar</a>

```yara
rule Mimikatz_Strings {
   meta:
      description = "Detects Mimikatz strings"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "not set"
      date = "2016-06-08"
      score = 65
      id = "d8f63b71-c66c-5c10-9268-2d8970f7c8a1"
   strings:
      $x1 = "sekurlsa::logonpasswords" fullword wide ascii
      $x2 = "List tickets in MIT/Heimdall ccache" fullword ascii wide
      $x3 = "kuhl_m_kerberos_ptt_file ; LsaCallKerberosPackage %08x" fullword ascii wide
      $x4 = "* Injecting ticket :" fullword wide ascii
      $x5 = "mimidrv.sys" fullword wide ascii
      $x6 = "Lists LM & NTLM credentials" fullword wide ascii
      $x7 = "\\_ kerberos -" wide ascii
      $x8 = "* unknow   :" fullword wide ascii
      $x9 = "\\_ *Password replace ->" wide ascii
      $x10 = "KIWI_MSV1_0_PRIMARY_CREDENTIALS KO" ascii wide
      $x11 = "\\\\.\\mimidrv" wide ascii
      $x12 = "Switch to MINIDUMP :" fullword wide ascii
      $x13 = "[masterkey] with password: %s (%s user)" fullword wide
      $x14 = "Clear screen (doesn't work with redirections, like PsExec)" fullword wide
      $x15 = "** Session key is NULL! It means allowtgtsessionkey is not set to 1 **" fullword wide
      $x16 = "[masterkey] with DPAPI_SYSTEM (machine, then user): " fullword wide
   condition:
      (
         ( uint16(0) == 0x5a4d and 1 of ($x*) ) or
         ( 3 of them )
      )
      /* exclude false positives */
      and not pe.imphash() == "77eaeca738dd89410a432c6bd6459907"
}
```

##### Detecting Mimikatz Strings

Running the `yara64.exe` binary and the above rules against the Mimikatz binary.

```sh
PS C:\Users\Administrator> .\yara64.exe .\gen_mimikatz.yar .\mimikatz.exe
mimikatz .\mimikatz.exe
Mimikatz_Strings .\mimikatz.exe
HKTL_Mimikatz_SkeletonKey_in_memory_Aug20_1 .\mimikatz.exe
HKTL_mimikatz_icon .\mimikatz.exe
```

Doing the same thing against a running process of Mimikatz by providing the process ID as an argument.

```sh
PS C:\Users\Administrator> .\yara64.exe .\gen_mimikatz.yar 7656
mimikatz 7656
Mimikatz_Strings 7656
HKTL_Mimikatz_SkeletonKey_in_memory_Aug20_1 7656
```


#### Sigma

A Sigma rule to detect the process arguments of the Mimikatz binary.

| Sourced from: <a target="_blank" href="https://github.com/SigmaHQ/sigma/blob/7f83008e9ee84ce0e2bcb1474dc002b41cdfe8a5/rules/windows/process_creation/proc_creation_win_hktl_mimikatz_command_line.yml">https://github.com/SigmaHQ/sigma/blob/7f83008e9ee84ce0e2bcb1474dc002b41cdfe8a5/rules/windows/process_creation/proc_creation_win_hktl_mimikatz_command_line.yml</a>

```yaml
title: HackTool - Mimikatz Execution
id: a642964e-bead-4bed-8910-1bb4d63e3b4d
status: test
description: Detection well-known mimikatz command line arguments
references:
    - https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment
    - https://tools.thehacker.recipes/mimikatz/modules
author: Teymur Kheirkhabarov, oscd.community, David ANDRE (additional keywords), Tim Shelton
date: 2019-10-22
modified: 2023-02-21
tags:
    - attack.credential-access
    - attack.t1003.001
    - attack.t1003.002
    - attack.t1003.004
    - attack.t1003.005
    - attack.t1003.006
logsource:
    category: process_creation
    product: windows
detection:
    selection_tools_name:
        CommandLine|contains:
            - 'DumpCreds'
            - 'mimikatz'
    selection_function_names: # To cover functions from modules that are not in module_names
        CommandLine|contains:
            - '::aadcookie' # misc module
            - '::detours' # misc module
            - '::memssp' # misc module
            - '::mflt' # misc module
            - '::ncroutemon' # misc module
            - '::ngcsign' # misc module
            - '::printnightmare' # misc module
            - '::skeleton' # misc module
            - '::preshutdown'  # service module
            - '::mstsc'  # ts module
            - '::multirdp'  # ts module
    selection_module_names:
        CommandLine|contains:
            - 'rpc::'
            - 'token::'
            - 'crypto::'
            - 'dpapi::'
            - 'sekurlsa::'
            - 'kerberos::'
            - 'lsadump::'
            - 'privilege::'
            - 'process::'
            - 'vault::'
    condition: 1 of selection_*
falsepositives:
    - Unlikely
level: high
```

The `pip` command to install dependencies for using pySigma.

```sh
pip install pysigma pysigma-backend-splunk pysigma-pipeline-sysmon
```

A script, `sigma_to_splunk.py`, that opens the above Sigma rule from the same directory and converts it to Splunk SPL queries that leverage Sysmon logs.

```python
from sigma.collection import SigmaCollection
from sigma.pipelines.sysmon import sysmon_pipeline
from sigma.backends.splunk import SplunkBackend

rule_text = open("./proc_creation_win_hktl_mimikatz_command_line.yml", "rb").read()
pipeline = sysmon_pipeline()
backend = SplunkBackend(pipeline)
rules = SigmaCollection.from_yaml(rule_text)

print("Query: \n\n" + "\n".join(backend.convert(rules)))
```

The output of the above tool.

```sh
ubuntu@agpt:/Tools$ python3 ./sigma_to_splunk.py
Query: 

EventID=1 CommandLine IN ("*DumpCreds*", "*mimikatz*") OR CommandLine IN ("*::aadcookie*", "*::detours*", "*::memssp*", "*::mflt*", "*::ncroutemon*", "*::ngcsign*", "*::printnightmare*", "*::skeleton*", "*::preshutdown*", "*::mstsc*", "*::multirdp*") OR CommandLine IN ("*rpc::*", "*token::*", "*crypto::*", "*dpapi::*", "*sekurlsa::*", "*kerberos::*", "*lsadump::*", "*privilege::*", "*process::*", "*vault::*")
```

An example Mimikatz command that can be executed to trigger the Sigma rule and produce a result in Splunk.

```powershell
.\mimikatz.exe privilege::debug sekurlsa::logonpasswords exit
```




<hr>

## Resources

The following resources expand on topics covered in this chapter.
<br/>
<br/>



#### Zeek Network Monitoring
<div class="row row-cols-1 row-cols-md-1">
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>The BZAR Zeek plugin, leveraging Zeek data to detect attacker activity mapped to MITRE ATT&CK</h6>
                <p><i>"BZAR (Bro/Zeek ATT&CK-based Analytics and Reporting)," GitHub, accessed September 15, 2024</i></p>
                <a target="_blank" href="https://github.com/mitre-attack/bzar" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>Details of the BZAR extension and its coverage of MITRE ATT&CK techniques</h6>
                <p><i>"BZAR – Bro/Zeek ATT&CK-based Analytics and Reporting: Detecting Adversary Behaviors via Internal Network Monitoring," M.I.Fernandez, October 9, 2019</i></p>
                <a target="_blank" href="https://old.zeek.org/zeekweek2019/slides/bzar.pdf" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>The JA3 plugin for Zeek</h6>
                <p><i>"JA3 - A method for profiling SSL/TLS Clients," Zeek, accessed September 15, 2024</i></p> 
                <a target="_blank" href="https://packages.zeek.org/packages/view/cebd1c8c-9348-11eb-81e7-0a598146b5c6" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>The Dovehawk plugin for Zeek</h6>
                <p><i>"Dovehawk Zeek Module," Zeek, accessed September 15, 2024</i></p>
                <a target="_blank" href="https://packages.zeek.org/packages/view/ca24044b-9348-11eb-81e7-0a598146b5c6" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>A complete overview of the logs that Zeek can generate, including log examples and applications</h6>
                <p><i>Zeek, accessed September 15, 2024</i></p>
                <a target="_blank" href="https://docs.zeek.org/en/master/logs/index.html" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>Inclusion of Zeek detection capabilities in Microsoft Defender for Endpoint</h6>
                <p><i>"New network-based detections and improved device discovery using Zeek," Elad Solomon, November 28, 2022</i></p>
                <a target="_blank" href="https://techcommunity.microsoft.com/t5/microsoft-defender-for-endpoint/new-network-based-detections-and-improved-device-discovery-using/ba-p/3682111" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
</div>

#### Event Tracing for Windows (ETW)
<div class="row row-cols-1 row-cols-md-1">
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>An overview of ETW architecture, concepts, telemetry and utilities</h6>
                <p><i>"A Primer On Event Tracing For Windows (ETW)," Nasreddine Bencherchali, August 15, 2021</i></p>
                <a target="_blank" href="https://nasbench.medium.com/a-primer-on-event-tracing-for-windows-etw-997725c082bf" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>The open-source Havoc C2 framework, with ETW bypass capabilities leveraging hardware breakpoints</h6>
                <p><i>"Havoc," Paul Ungur, accessed April 29, 2024</i></p>
                <a target="_blank" href="https://github.com/HavocFramework/Havoc" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>An example of tooling to patch ETW and inhibit log generation, in this case a Cobalt Strike BOF</h6>
                <p><i>"ETW," Alfie Champion, accessed April 29, 2024</i></p>
                <a target="_blank" href="https://github.com/ajpc500/BOFs/tree/main/ETW" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>Applying ETW telemetry to detect the offensive use of .NET</h6>
                <p><i>"Detecting Malicious Use of .NET – Part 1," Noora Hyvärinen, August 10, 2018</i></p>
                <a target="_blank" href="https://blog.f-secure.com/detecting-malicious-use-of-net-part-1/" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>Ruben Boonen’s SilkETW project, a great utility for experimenting with ETW telemetry in a lab environment</h6>
                <p><i>"SilkETW," Ruben Boonen, accessed March 30, 2024</i></p>
                <a target="_blank" href="https://github.com/mandiant/SilkETW" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>An example of leveraging ETW telemetry for LDAP queries to identify reconnaissance activities</h6>
                <p><i>"Hunting for Suspicious LDAP Activity with SilkETW and YARA," Riccardo Ancarani, October 19, 2019</i></p>
                <a target="_blank" href="https://riccardoancarani.github.io/2019-10-19-hunting-for-domain-enumeration/" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>Provides a background to ETW, including an offensive perspective on tampering with tracing to hide malicious activities</h6>
                <p><i>"Tampering with Windows Event Tracing: Background, Offense, and Defense," Palantir, December 24, 2018</i></p>
                <a target="_blank" href="https://blog.palantir.com/tampering-with-windows-event-tracing-background-offense-and-defense-4be7ac62ac63" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>A low-level analysis of Sysmon's DNS logging capability and how it can be evaded</h6>
                <p><i>"Evading Sysmon DNS Monitoring," Adam Chester, June 15, 2019</i></p>
                <a target="_blank" href="https://blog.xpnsec.com/evading-sysmon-dns-monitoring/" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>Further tampering with ETW to suppress indicators of in-memory .NET tradecraft</h6>
                <p><i>"Hiding your .NET - ETW," Adam Chester, March, 2020</i></p>
                <a target="_blank" href="https://www.mdsec.co.uk/2020/03/hiding-your-net-etw/" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
</div>

#### Osquery
<div class="row row-cols-1 row-cols-md-1">
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>The osquery schema including the tables and fields that can be queried</h6>
                <p><i>"Schema," osquery, accessed May 3, 2024</i></p>
                <a target="_blank" href="https://www.osquery.io/schema/current" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>Fleet, an open source solution for enterprise management of osquery</h6>
                <p><i>"Fleet," GitHub, accessed September 15, 2024</i></p>
                <a target="_blank" href="https://github.com/fleetdm/fleet" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>Guidance on configuring osquery and its components</h6>
                <p><i>"Configuring an osquery deployment," osquery, accessed March 30, 2024</i></p>
                <a target="_blank" href="https://osquery.readthedocs.io/en/stable/deployment/configuration/\#configuration-components" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>The built-in osquery packs included to extend its query configuration</h6>
                <p><i>"osquery packs," osquery, accessed May 2, 2024</i></p>
                <a target="_blank" href="https://github.com/osquery/osquery/tree/master/packs" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>More information on using the <code>osqueryi</code> command line tool</h6>
                <p><i>"Using osqueryi," osquery, accessed March 30, 2024</i></p>
                <a target="_blank" href="https://osquery.readthedocs.io/en/stable/introduction/using-osqueryi/" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>A walkthrough for getting started with osquery, centralising logs and developing detections</h6>
                <p><i>"osquery For Security," Chris Long, January 19, 2016</i></p>
                <a target="_blank" href="https://medium.com/@clong/osquery-for-security-b66fffdf2daf#.tr5fk7r2a" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>A deeper dive into advanced osquery functionality, including file integrity monitoring, and process and socket activity monitoring</h6>
                <p><i>"osquery For Security - Part 2," Chris Long, March 16, 2017</i></p>
                <a target="_blank" href="https://medium.com/@clong/osquery-for-security-part-2-2e03de4d3721" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
</div>

#### YARA
<div class="row row-cols-1 row-cols-md-1">
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>A set of rules from Florian Roth's open sourced YARA rule collection to detect Mimikatz</h6>
                <p><i>"gen_mimikatz.yar," GitHub, accessed November 2, 2024</i></p>
                <a target="_blank" href="https://github.com/Neo23x0/signature-base/blob/c943048164788661f6d25f58fbfd849acdeddc38/yara/gen_mimikatz.yar" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>A comprehensive guide to writing YARA rules</h6>
                <p><i>"Writing YARA rules," YARA, accessed March 30, 2024</i></p>
                <a target="_blank" href="https://yara.readthedocs.io/en/stable/writingrules.html" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>Details on integrating YARA into osquery</h6>
                <p><i>"YARA-based scanning with osquery," Oqsuery, accessed March 30, 2024</i></p>
                <a target="_blank" href="https://osquery.readthedocs.io/en/stable/deployment/yara/" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
</div>

#### Sigma
<div class="row row-cols-1 row-cols-md-1">
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>Details on the design of Sigma and its rule schema</h6>
                <p><i>"Sigma Specification - Generic Signature Format for SIEM Systems," GitHub, accessed September 15, 2024</i></p>
                <a target="_blank" href="https://github.com/SigmaHQ/sigma-specification" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>pySigma, a Python library to convert Sigma rules into tool-specific queries</h6>
                <p><i>"pySigma," GitHub, accessed September 15, 2024</i></p>
                <a target="_blank" href="https://github.com/SigmaHQ/pySigma" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>A Sigma rule to command-line use of Mimikatz</h6>
                <p><i>"proc_creation_win_hktl _mimikatz_command_line.yml," GitHub, accessed September 15, 2024</i></p>
                <a target="_blank" href="https://github.com/SigmaHQ/sigma/blob/7f83008e9ee84ce0e2bcb1474dc002b41cdfe8a5/rules/windows/process_creation/proc_creation_win_hktl_mimikatz_command_line.yml" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
</div>


<div class="container">
  <div class="row">
    <div class="col" style="text-align: left">
      <a href="/part-II/collecting-telemetry/" class="btn btn-primary"><< Chapter 6</a>
    </div>
    <div class="col" style="text-align: right">
      <a href="/part-II/lotl-with-atomic-red-team/" class="btn btn-primary">Chapter 8 >></a>
    </div>
  </div>
</div>
