---
layout: default
title: The Atomic Methodology
tags: []
header_type       : "hero"
include_on_search : true
show_tags         : true
---


<div class="bs-component">
    <div class="progress">
        <div class="progress-bar progress-bar-striped progress-bar-animated" role="progressbar" aria-valuemin="0" aria-valuemax="100" style="width: 25%; background-color:#eb34e1"></div>
    </div>
</div>

## Introduction

This chapter introduces the atomic purple teaming methodology. It explores the applications for the methodology, as well as inputs that may help you shape your exercises. The chapter considers what an exercise targeting enumeration of the Domain Admins Active Directory group might look like, and how you can evaluate your test suites to ensure they provide the breadth and depth required.

The chapter considers key metrics to capture when performing your atomic testing, and also highlights micro-emulation as a hybrid form of purple team testing that can help overcome some of the shortfalls of 'pure' atomic tests.

The complete test suite produced in this chapter can be found here:

<details>
<summary>Domain Admins enumeration techniques</summary>
<table class="table">
  <thead class="thead-light">
    <tr>
      <th scope="col">Test name</th>
      <th scope="col">Command</th>
      <th scope="col">Type</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>A <code>net</code> command with a shortened domain flag</td>
      <td><code>net group "domain admins" /dom</code></td>
      <td><code>net</code></td>
    </tr>
    <tr>
      <td>A <code>net</code> command with a reordered flag</td>
      <td><code>net group /domain "domain admins"</code></td>
      <td><code>net</code></td>
    </tr>
    <tr>
      <td>An obfuscated<br/><code>net</code> command</td>
      <td><code>set GROUP="Domain Admins"</code><br/><code>n^e^t g^r^o^u^p %GROUP% /d^o</code></td>
      <td><code>net</code></td>
    </tr>
    <tr>
      <td>An ADSI searcher script</td>
      <td>
        <code>$Group = [ADSI]"LDAP://CN=Domain Admins, CN=Users, DC=Contoso,DC=com"</code><br/>
        <code>$Group.member | ForEach-Object {</code><br/>
        <code>$Searcher = [adsisearcher]"(distinguishedname=$_)"</code><br/>
        <code>$Searcher.FindOne().Properties.cn</code><br/>
        <code>}</code><br/>
      </td>
      <td>PowerShell</td>
    </tr>
    <tr>
      <td>An RSAT Active Directory cmdlet</td>
      <td><code>Get-ADGroupMember -Identity "Domain Admins"</code></td>
      <td>PowerShell</td>
    </tr>
    <tr>
      <td>A PowerView command</td>
      <td><code>Get-DomainGroupMember "Domain Admins"</code></td>
      <td>PowerShell</td>
    </tr>
    <tr>
      <td>An AdFind command</td>
      <td>
        <code>AdFind.exe -b "CN=Domain Admins, CN=Users,</code><br/>
        <code>    DC=Contoso, DC=com" member</code>
      </td>
      <td>AdFind</td>
    </tr>
    <tr>
      <td>The use of StandIn</td>
      <td>
        <code>execute-assembly /tools/StandIn.exe --group </code><br/>
        <code>    "Domain Admins"</code>
      </td>
      <td>In-memory .NET execution</td>
    </tr>
    <tr>
      <td>The use of Ldapsearch</td>
      <td><code>ldapsearch "CN=Domain Admins" member</code></td>
      <td>BOF</td>
    </tr>
    <tr>
      <td>The use of Recon-AD</td>
      <td><code>Recon-AD-Groups Domain Admins</code></td>
      <td>Reflective DLL</td>
    </tr>
    <tr>
      <td>The use of SOCKS with Impacket net.py</td>
      <td>
        <code>socks 8080</code> (on Cobalt Strike beacon)<br/>
        <code>proxychains python net.py user:pass@dc group -name “Domain Admins”</code> (on attacker host command line)
      </td>
      <td>SOCKS and Impacket</td>
    </tr>
  </tbody>
</table>

</details>

<hr>

## Chapter Content

This section provides reproductions of the key figures and code snippets seen in this chapter.

#### Scoping and Dechaining

<figure>
<img src="/assets/images/3/example-attack-chain.png" style="width: 75%" title="Figure 3-1"/>
<figcaption>Figure 3-1: An example attack chain that includes initial access, execution, and discovery phases</figcaption>
</figure>


#### Generating Test Cases

##### net.exe

The complete Sigma rule for detecting reconnaissance performed with the `net.exe` and `net1.exe` binaries.

| Sourced from: <a target="_blank" href="https://github.com/SigmaHQ/sigma/blob/fad4742996c55d8d4663e611f84877a2b741dc46/rules/windows/process_creation/proc_creation_win_net_groups_and_accounts_recon.yml">https://github.com/SigmaHQ/sigma/blob/fad4742996c55d8d4663e611f84877a2b741dc46/rules/windows/process_creation/proc_creation_win_net_groups_and_accounts_recon.yml</a>

```yaml
title: Suspicious Group And Account Reconnaissance Activity Using Net.EXE
id: d95de845-b83c-4a9a-8a6a-4fc802ebf6c0
status: test
description: |
    Detects suspicious reconnaissance command line activity on Windows systems using Net.EXE
    Check if the user that executed the commands is suspicious (e.g. service accounts, LOCAL_SYSTEM)
references:
    - https://redcanary.com/blog/how-one-hospital-thwarted-a-ryuk-ransomware-outbreak/
    - https://thedfirreport.com/2020/10/18/ryuk-in-5-hours/
    - https://research.nccgroup.com/2022/08/19/back-in-black-unlocking-a-lockbit-3-0-ransomware-attack/
author: Florian Roth (Nextron Systems), omkar72, @svch0st, Nasreddine Bencherchali (Nextron Systems)
date: 2019-01-16
modified: 2023-03-02
tags:
    - attack.discovery
    - attack.t1087.001
    - attack.t1087.002
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith:
              - '\net.exe'
              - '\net1.exe'
        - OriginalFileName:
              - 'net.exe'
              - 'net1.exe'
    # Covers group and localgroup flags
    selection_group_root:
        CommandLine|contains:
            - ' group '
            - ' localgroup '
    selection_group_flags:
        CommandLine|contains:
            # Add more groups for other languages
            - 'domain admins'
            - ' administrator' # Typo without an 'S' so we catch both
            - ' administrateur' # Typo without an 'S' so we catch both
            - 'enterprise admins'
            - 'Exchange Trusted Subsystem'
            - 'Remote Desktop Users'
            - 'Utilisateurs du Bureau à distance' # French for "Remote Desktop Users"
            - 'Usuarios de escritorio remoto' # Spanish for "Remote Desktop Users"
            - ' /do' # short for domain
    filter_group_add:
        # This filter is added to avoid the potential case where the point is not recon but addition
        CommandLine|contains: ' /add'
    # Covers 'accounts' flag
    selection_accounts_root:
        CommandLine|contains: ' accounts '
    selection_accounts_flags:
        CommandLine|contains: ' /do' # short for domain
    condition: selection_img and ((all of selection_group_* and not filter_group_add) or all of selection_accounts_*)
falsepositives:
    - Inventory tool runs
    - Administrative activity
level: medium
```

##### PowerShell

A code snippet to enumerate Domain Admin members with PowerShell:

```powershell
$Group = [ADSI]"LDAP://CN=Domain Admins,CN=Users,DC=Contoso,DC=com"
$Group.member | ForEach-Object {
    $Searcher = [adsisearcher]"(distinguishedname=$_)"
    $Searcher.FindOne().Properties.cn 
}
```

Domain enumeration via the Active Directory PowerShell module:

```powershell
Get-ADGroupMember -Identity "Domain Admins"
```

Use of PowerSploit to enumerate Domain Admins:

```powershell
Get-DomainGroupMember "Domain Admins"
```

#### Evaluating Test Suites

##### Attack Sophistication

<figure>
<img src="/assets/images/3/attack-sophistication-pyramid.png" style="width: 75%" title="Figure 3-2"/>
<figcaption>Figure 3-2: Attack techniques arranged in a pyramid of sophistication and prevalence</figcaption>
</figure>


#### Plotting Results

<figure>
<img src="/assets/images/3/graph-strong-tel.png" style="width: 75%" title="Figure 3-3"/>
<figcaption>Figure 3-3: Atomic purple team results plotted with a strong telemetry score</figcaption>
</figure>

<figure>
<img src="/assets/images/3/graph-strong-prev.png" style="width: 75%" title="Figure 3-4"/>
<figcaption>Figure 3-4: Atomic purple team with a strong prevention score</figcaption>
</figure>

<figure>
<img src="/assets/images/3/graph-tap-across-phases.png" style="width: 75%" title="Figure 3-5"/>
<figcaption>Figure 3-5: Atomic purple team results plotted on a graph across multiple ATT&CK tactics</figcaption>
</figure>

<figure>
<img src="/assets/images/3/graph-alerting-pot.png" style="width: 75%" title="Figure 3-6"/>
<figcaption>Figure 3-6: Capturing the alerting potential</figcaption>
</figure>







<hr>

## Resources

The following resources expand on topics covered in this chapter.
<br/>
<br/>

#### Applications of Atomic Purple Teaming

<div class="row row-cols-1 row-cols-md-1">
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>Techniques for breaking out of Citrix environments</h6>
                <p><i>Michael Yardley, "Breaking Out of Citrix and other Restricted Desktop Environments," Pen Test Partners, June 6, 2014</i></p>
                <a target="_blank" href="https://www.pentestpartners.com/security-blog/breaking-out-of-citrix-and-other-restricted-desktop-environments/" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>

</div>
#### Scoping and Dechaining

<div class="row row-cols-1 row-cols-md-1">
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>Examples of the many techniques for performing HTML smuggling</h6>
                <p><i>Alfie Champion, "HTML Smuggling: Recent observations of threat actor techniques," delivr.to, January 6, 2023</i></p>
                <a target="_blank" href="https://blog.delivr.to/html-smuggling-recent-observations-of-threat-actor-techniques-74501d5c8a06" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>

    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>Operational considerations and technical implementation details of environmental keying and execution guardrails</h6>
                <p><i>Brandon McGrath, "Execution Guardrails: No One Likes Unintentional Exposure," TrustedSec, August 6, 2024</i></p>
                <a target="_blank" href="https://trustedsec.com/blog/execution-guardrails-no-one-likes-unintentional-exposure" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>

</div>
#### Inputs

<div class="row row-cols-1 row-cols-md-1">
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>A whitepaper covering the extensive abuse potential of misconfigured Active Directory Certificate Services (ADCS)</h6>
                <p><i>Will Schroeder, Lee Chagolla-Christensen, "Certified Pre-Owned," SpecterOps, June 22, 2022</i></p>
                <a target="_blank" href="https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>

    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>A collection of post-exploitation techniques targeting components of the identify provider, Okta</h6>
                <p><i>Adam Chester, "Okta for Red Teamers," TrustedSec, September 18, 2023</i></p>
                <a target="_blank" href="https://trustedsec.com/blog/okta-for-red-teamers" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>

</div>
#### Generating Test Cases

<div class="row row-cols-1 row-cols-md-1">
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>Examples of command line obfuscation techniques</h6>
                <p><i>Daniel Bohannon, "DOSfuscation: Exploring the Depths of Cmd.exe Obfuscation and Detection Techniques," Mandiant, 2019</i></p>
                <a target="_blank" href="https://www.mandiant.com/media/22686" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>

    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>A Sigma rule to detect the enumeration of high value groups like enterprise and domain administrators via the built-in net.exe executable</h6>
                <p><i>Florian Roth, omkar72, @svch0st, Nasreddine Bencherchali, "proc_creation_win_net_groups_and_accounts_recon.yml", GitHub, accessed January 12, 2025</i></p>
                <a target="_blank" href="https://github.com/SigmaHQ/sigma/blob/fad4742996c55d8d4663e611f84877a2b741dc46/rules/windows/process\_creation/proc\_creation\_win\_net\_groups\_and\_accounts\_recon.yml" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>

    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>An overview of detection and prevention mechanisms introduced by Microsoft in Windows PowerShell version 5 and onwards</h6>
                <p><i>"PowerShell loves the Blue Team," Microsoft, June 9, 2015</i></p>
                <a target="_blank" href="https://devblogs.microsoft.com/powershell/powershell-the-blue-team/" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>

    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>An overview of the architecture and impact of the Antimalware Scan Interface</h6>
                <p><i>"How the Antimalware Scan Interface (AMSI) helps you defend against malware," Microsoft, August 23, 2019</i></p>
                <a target="_blank" href="https://learn.microsoft.com/en-us/windows/win32/amsi/how-amsi-helps" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>

    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>Introducing <code>execute-assembly</code> to Cobalt Strike</h6>
                <p><i>Raphael Mudge, "Cobalt Strike 3.11 – The snake that eats its tail," Cobalt Strike, April 9, 2018</i></p>
                <a target="_blank" href="https://www.cobaltstrike.com/blog/cobalt-strike-3-11-the-snake-that-eats-its-tail" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>

    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>Introducing <i>Beacon Object Files</i> to Cobalt Strike v4.1</h6>
                <p><i>Raphael Mudge, "Cobalt Strike 4.1 – The Mark of Injection," Cobalt Strike, June 25, 2020</i></p>
                <a target="_blank" href="https://www.cobaltstrike.com/blog/cobalt-strike-4-1-the-mark-of-injection" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>

</div>
#### Evaluating Test Suites

<div class="row row-cols-1 row-cols-md-1">
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>Introducing the concept of capability abstraction</h6>
                <p><i>Jared Atkinson, "Capability Abstraction," SpecterOps, Feb 6, 2020</i></p>
                <a target="_blank" href="https://posts.specterops.io/capability-abstraction-fbeaeeb26384" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>

</div>
#### Plotting Results

<div class="row row-cols-1 row-cols-md-1">
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>Guidance on the detection and prevention of web shell malware</h6>
                <p><i>Australian Signals Directorate, "Detect and Prevent Web Shell Malware," Australian Signals Directorate, June 9, 2020</i></p>
                <a target="_blank" href="https://media.defense.gov/2020/Jun/09/2002313081/-1/-1/0/CSI-DETECT-AND-PREVENT-WEB-SHELL-MALWARE-20200422.PDF" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>

</div>

#### Micro-Emulation

<div class="row row-cols-1 row-cols-md-1">
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>Release of the micro-emulation framework from the Center for Threat-informed Defense</h6>
                <p><i>Mike Cunningham and Jamie Williams, "Ahhh, This Emulation is Just Right: Introducing Micro Emulation Plans," September 15, 2022</i></p>
                <a target="_blank" href="https://medium.com/mitre-engenuity/ahhh-this-emulation-is-just-right-introducing-micro-emulation-plans-7bf4c26451d3" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>

    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>A micro-emulation plan replicating web shell activity</h6>
                <p><i>"Micro Emulation Plan: Web Shells", GitHub, accessed January 12, 2025</i></p>
                <a target="_blank" href="https://github.com/center-for-threat-informed-defense/adversary_emulation_library/tree/9786a3297c855ea8dfa6c321befa397473b32f41/micro_emulation_plans/src/webshell" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>

    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>A micro-emulation plan replicating the popular C2 framework technique <i>Fork-n-Run</i></h6>
                <p><i>"Micro Emulation Plan: Named Pipes", GitHub, accessed January 12, 2025</i></p>
                <a target="_blank" href="https://github.com/center-for-threat-informed-defense/adversary_emulation_library/tree/9786a3297c855ea8dfa6c321befa397473b32f41/micro_emulation_plans/src/named_pipes" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>

    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>A micro-emulation plan replicating Active Directory enumeration through LDAP queries, Windows APIs and built-in executables</h6>
                <p><i>"Micro Emulation Plan: Active Directory Enumeration", GitHub, accessed January 12, 2025</i></p>
                <a target="_blank" href="https://github.com/center-for-threat-informed-defense/adversary_emulation_library/tree/9786a3297c855ea8dfa6c321befa397473b32f41/micro_emulation_plans/src/ad_enum" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>

    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>A micro-emulation plan replicating user-driven execution of an initial access payload that could be delivered via phishing</h6>
                <p><i>"Micro Emulation Plan: User Execution", GitHub, accessed January 12, 2025</i></p>
                <a target="_blank" href="https://github.com/center-for-threat-informed-defense/adversary_emulation_library/blob/9786a3297c855ea8dfa6c321befa397473b32f41/micro_emulation_plans/src/user_execution/README_user_execution.md" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>

    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>Demonstration of IcedID malware delivery via an ISO disk image file, designed to bypass Mark of the Web</h6>
                <p><i>"Malicious ISO File Leads to Domain Wide Ransomware", The DFIR Report, April 3, 2023</i></p>
                <a target="_blank" href="https://thedfirreport.com/2023/04/03/malicious-iso-file-leads-to-domain-wide-ransomware/" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>

    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>Another example of disk image based initial compromise to delivery QakBot malware</h6>
                <p><i>"Surge of QakBot Activity Using Malspam, Malicious XLSB Files", Center for Internet Security, accessed January 12, 2025</i></p>
                <a target="_blank" href="https://www.cisecurity.org/insights/blog/surge-of-qakbot-activity-using-malspam-malicious-xlsb-files" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>

    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>Bumblebee malware infection achieved via an LNK and DLL file contained in an ISO disk image</h6>
                <p><i>"Malicious ISO File Leads to Domain Wide Ransomware", The DFIR Report, September 26, 2022</i></p>
                <a target="_blank" href="https://thedfirreport.com/2022/09/26/bumblebee-round-two" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>

    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>An article covering a Microsoft 'Patch Tuesday' in which the Mark of the Web bypass for ISO disk images was patched</h6>
                <p><i>"Microsoft fixes Windows zero-day bug exploited to push malware", BleepingComputer, November 22, 2022</i></p>
                <a target="_blank" href="https://www.bleepingcomputer.com/news/microsoft/microsoft-fixes-windows-zero-day-bug-exploited-to-push-malware/" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>

</div>

<div class="container">
  <div class="row">
    <div class="col" style="text-align: left">
      <a href="/part-I/offensive-and-defensive-frameworks/" class="btn btn-primary"><< Chapter 2</a>
    </div>
    <div class="col" style="text-align: right">
      <a href="/part-I/the-scenario-based-methodology/" class="btn btn-primary">Chapter 4 >></a>
    </div>
  </div>
</div>