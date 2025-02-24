---
layout: default
title: Environment Setup
tags: []
header_type       : "hero"
include_on_search : true
show_tags         : true
---

<div class="bs-component">
    <div class="progress">
        <div class="progress-bar progress-bar-striped progress-bar-animated" role="progressbar" aria-valuemin="0" aria-valuemax="100" style="width: 41.6%; background-color:#eb34e1"></div>
    </div>
</div>

## Introduction

This chapter introduces Splunk's Attack Range and goes through the steps required to deploy a test environment for adversary emulation. Once deployed some of the features of the environment are detailed, including the ability to access hosts via Apache Guacamole, query logs via Splunk and automate attacks via Atomic Red Team and PurpleSharp.

<hr>

## Chapter Content

This section provides reproductions of the key figures and code snippets seen in this chapter.

#### Deploying Splunk's Attack Range

<figure>
<img src="/assets/images/5/arch-0.png" style="width: 75%" title="Figure 5-1"/>
<figcaption>Figure 5-1: An overview of the instances deployed in the Attack Range</figcaption>
</figure>


##### Setting Up the Docker Image

Commands to download and run the Attack Range Docker image.

```sh
docker pull ajpc500/attack_range
docker run -it ajpc500/attack_range
```

Commands to configure the AWS CLI within the docker container.

```sh
aws configure
AWS Access Key ID [None]: AKIA...M67D
AWS Secret Access Key [None]: I1+DB...Xsdc
Default region name [None]: us-east-2
Default output format [None]: json
```

Commands to create an `~/.ssh` directory in the container and populate it with a private key.

```sh
mkdir ~/.ssh/
echo 'PRIVATE_KEY_CONTENT' > ~/.ssh/id_rsa
chmod 600 ~/.ssh/id_rsa
```

##### Configuring Attack Range

The complete `attack_range.yml` configuration file.

```yaml
general:
  cloud_provider: aws
  attack_range_password: A_STRONG_PASSWORD
  key_name: attack-range-key-pair
  ip_whitelist: IP_CIDR_RANGE
  attack_range_name: agpt
aws:
  private_key_path: ~/.ssh/id_rsa
  region: us-east-2
  use_elastic_ips: '0'
windows_servers:
- hostname: ar-win-dc
  windows_image: windows-server-XXXX
  create_domain: '1'
  win_sysmon_config: "SwiftOnSecurity.xml"
  aurora_agent: '1'  
  bad_blood: '1'
- hostname: ar-win-2
  windows_image: windows-server-XXXX
  join_domain: '1'
  win_sysmon_config: "SwiftOnSecurity.xml"  
  aurora_agent: '1'
  install_red_team_tools: '1'
linux_servers:
- hostname: ar-linux
  sysmon_config: "SysMonLinux-CatchAll.xml"
zeek_server:
  zeek_server: '1'
kali_server:
  kali_server: '1'
```

#### Using the Attack Range

##### Managing the Lab

Commands to interact with the Attack Range, including stopping and starting the deployed resources.

```sh
python attack_range.py show   # Show deployed resources
python attack_range.py stop   # Stop running instances
python attack_range.py resume   # Restart running instances
python attack_range.py destroy   # Teardown Attack Range
```

##### Querying Logs in Splunk

A Splunk SPL query leveraging Sysmon logs to identify instances of the `hostname` and `whoami` commands executed by the `Administrator` user.

```perl
index="win"
host="ar-win-dc"
Channel="Microsoft-Windows-Sysmon/Operational"
EventID=1
user=Administrator
(CommandLine="hostname" OR CommandLine="whoami")
| table host, user, parent_process, process_id, process
```

An equivalent query for Sysmon for Linux logs, identfying the same commands executed by the `ubuntu` user.

```perl
index="unix"
host="ar-linux"
Channel="Linux-Sysmon/Operational"
EventID=1
user=ubuntu
(CommandLine="hostname" OR CommandLine="whoami")
| table host, user, parent_process, process_id, process
```

##### Importing and Exporting Log Data

A command to query and dump logs from a Splunk search, limited to the last two hours.

```sh
python attack_range.py dump --file_name attack_data/dump.log --search 'index=win CommandLine="hostname"' --earliest 2h
```

An abridged example of the XML event log data dumped by the above command.

```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
    <System>
        <Provider Name='Microsoft-Windows-Sysmon' Guid='{5770385f-c22a-43e0-bf4c-06f5698ffbd9}' />
        <EventID>1</EventID>
        --snip--
        <Execution ProcessID='3260' ThreadID='3832' />
        <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
        <Computer>***ar-win-dc.attackrange.local***</Computer>
        <Security UserID='S-1-5-18' />
    </System>
    <EventData>
        <Data Name='ProcessId'>5432</Data>
        <Data Name='CommandLine'>***hostname***</Data>
        <Data Name='User'>***ATTACKRANGE\Administrator***</Data>
        --snip--
        <Data Name='Hashes'>
            MD5=7F95220A65A5A5D4A98873E86EF2E549,SHA256=1BFF2907C456F99277F45F9B2A21B1B3F11F6C01587D9E6D6F0B2B5F1472FE92,IMPHASH=5CD891320C666621E9783444DB8CBA78</Data>
        <Data Name='ParentProcessId'>5360</Data>
        <Data Name='ParentImage'>C:\Windows\System32\cmd.exe</Data>
        <Data Name='ParentCommandLine'>"C:\Windows\system32\cmd.exe" </Data>
        <Data Name='ParentUser'>ATTACKRANGE\Administrator</Data>
    </EventData>
</Event>
```

A command to inject the dumped logs back into a Splunk instance (for example, to analyze historical activity in a fresh Splunk deployment).

```sh
python attack_range.py replay --file_name attack_data/dump.log --source test --sourcetype test
```


##### Automating Attack Execution

A command to execute PurpleSharp on a host to perform credential access activities.

```sh
python attack_range.py simulate -e PurpleSharp -te T1003.001 -t ar-win-attack-range-key-pair-agpt-0
```

A similar Attack Range command, taking advantage of PurpleSharp's JSON playbooks feature to run multiple actions in a chained simulation.

```sh
python attack_range.py simulate -e PurpleSharp -t ar-win-attack-range-key-pair-agpt-1 -p configs/purplesharp_playbook_T1110_003.pb
```


<hr>

## Resources

The following resources expand on topics covered in this chapter.
<br/>
<br/>


#### Choosing a Lab Environment

<div class="row row-cols-1 row-cols-md-1">
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>More information on the ingestion of AWS CloudTrail and Azure Activity Logs for performing and detecting cloud-based attack scenarios using the Attack Range</h6>
                <p><i>"Attack Range Cloud," Attack Range, accessed April 18, 2024</i></p>
                <a target="_blank" href="https://attack-range.readthedocs.io/en/latest/Attack_Range_Cloud.html" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>If you’re performing attacks against cloud resources, you should familiarize yourself with the penetration testing and simulated events terms for your relevant provider. AWS, for example, provides details here</h6>
                <p><i>"Penetration Testing," Amazon Web Services</i></p>
                <a target="_blank" href="https://aws.amazon.com/security/penetration-testing/" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>Azure's guidance on penetration testing in cloud environments can be found here</h6>
                <p><i>"Penetration testing," Microsoft</i></p>
                <a target="_blank" href="https://learn.microsoft.com/en-us/azure/security/fundamentals/pen-testing" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>

</div>

#### Deploying the Attack Range

<div class="row row-cols-1 row-cols-md-1">
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>AWS's pricing calculator which can help forecast the associated costs for running lab environments</h6>
                <p><i>"AWS Pricing Calculator," Amazon Web Services</i></p>
                <a target="_blank" href="https://calculator.aws/" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>

</div>

#### Configuring Attack Range

<div class="row row-cols-1 row-cols-md-1">
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>AWS's guidance on the functionality, pricing and quotas for its Elastic IP Address feature</h6>
                <p><i>"Elastic IP Addresses," Amazon Web Services</i></p>
                <a target="_blank" href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/elastic-ip-addresses-eip.html" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>SwiftOnSecurity's popular SysInternals Sysmon configuration</h6>
                <p><i>"sysmon-config," GitHub, accessed April 28, 2024</i></p>
                <a target="_blank" href="https://github.com/SwiftOnSecurity/sysmon-config" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>The BadBlood Active Directory tool used to populate the lab with fictitious resources</h6>
                <p><i>"BadBlood," GitHub, accessed April 28, 2024</i></p>
                <a target="_blank" href="https://github.com/davidprowe/BadBlood" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>The complete list of red team tools pre-installed in the Attack Range</h6>
                <p><i>"red_team_tools," GitHub, accessed April 28, 2024</i></p>
                <a target="_blank" href="https://github.com/splunk/attack_range/blob/develop/terraform/ansible/roles/red_team_tools/tasks/main.yml" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>The underlying concepts, applications, and pricing for AWS's VPC Traffic Mirroring feature</h6>
                <p><i>"What is Traffic Mirroring?" Amazon Web Services</i></p>
                <a target="_blank" href="https://docs.aws.amazon.com/vpc/latest/mirroring/what-is-traffic-mirroring.html" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
</div>

#### Completing AWS Validations

<div class="row row-cols-1 row-cols-md-1">
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>Details of the vCPU usage for each EC2 instance type, should you choose to further expand your Attack Range with additional hosts</h6>
                <p><i>"AWS EC2 Instance Types," Amazon Web Services</i></p>
                <a target="_blank" href="https://aws.amazon.com/ec2/instance-types/" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>

</div>

#### Accessing Pre-Installed Tools

<div class="row row-cols-1 row-cols-md-1">
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>A searchable list of the offensive security tools pre-installed on the Kali Linux operating system</h6>
                <p><i>"Kali Tools," Kali, accessed March 16, 2024</i></p>
                <a target="_blank" href="https://www.kali.org/tools/" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>

</div>

#### Querying Logs in Splunk

<div class="row row-cols-1 row-cols-md-1">
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>More details on Splunk's query language, SPL</h6>
                <p><i>"About the search language," Splunk, accessed March 16, 2024</i></p>
                <a target="_blank" href="https://docs.splunk.com/Documentation/SplunkCloud/latest/Search/Aboutthesearchlanguage" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>

</div>

#### Automated Attack Execution

<div class="row row-cols-1 row-cols-md-1">
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>BlackHat USA 2020 Arsenal talk from Mauricio Velazco introducing PurpleSharp and its capabilities</h6>
                <p><i>"BlackHat 2020 Arsenal - PurpleSharp: Adversary Simulation for the Blue Team by Mauricio Velazco," YouTube, accessed March 16, 2024</i></p>
                <a target="_blank" href="https://www.youtube.com/watch?v=yaeNwdElYaQ" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>

    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>Details of the attack simulation capabilities of the Attack Range</h6>
                <p><i>"Attack Simulation," Attack Range, accessed April 28, 2024</i></p>
                <a target="_blank" href="https://attack-range.readthedocs.io/en/latest/Attack_Simulation.html" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>

    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>PurpleSharp's supported credential access capabilities</h6>
                <p><i>"Credential Access," PurpleSharp, accessed April 28, 2024</i></p>
                <a target="_blank" href="https://www.purplesharp.com/en/latest/techniques/credential_access.html" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>

    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>Using JSON playbooks to execute chained techniques with PurpleSharp</h6>
                <p><i>"JSON Playbooks," PurpleSharp, accessed April 28, 2024</i></p>
                <a target="_blank" href="https://www.purplesharp.com/en/latest/using-purplesharp/json_playbooks.html" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>

    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>More examples of PurpleSharp playbooks for multi-step attack simulations</h6>
                <p><i>"PurpleTeamPlaybook," GitHub, accessed March 16, 2024</i></p>
                <a target="_blank" href="https://github.com/mvelazc0/PurpleTeamPlaybook" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>

</div>


<div class="container">
  <div class="row">
    <div class="col" style="text-align: left">
      <a href="/part-I/the-scenario-based-methodology/" class="btn btn-primary"><< Chapter 4</a>
    </div>
    <div class="col" style="text-align: right">
      <a href="/part-II/collecting-telemetry/" class="btn btn-primary">Chapter 6 >></a>
    </div>
  </div>
</div>