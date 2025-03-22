---
layout: default
title: Offensive and Defensive Frameworks
# tags: [mitre-att&ck, diamond-model, tactics, techniques, procedures, TTPs, pyramid-of-pain, cyber-kill-chain]
tags: []
header_type       : "hero"
include_on_search : true
show_tags         : true
---

<div class="bs-component">
    <div class="progress">
        <div class="progress-bar progress-bar-striped progress-bar-animated" role="progressbar" aria-valuemin="0" aria-valuemax="100" style="width: 16.6%; background-color:#eb34e1"></div>
    </div>
</div>

## Introduction

This chapter provides an overview of key frameworks that enable the community to analyze, track and better articulate adversary activity. Frameworks like David J Bianco's Pyramid of Pain also allow you to better evaluate the scope of your detections. All of this plays a key role in how threat intelligence, detection engineering and adversary emulation teams work together.

<hr>

## Chapter Content

This section provides reproductions of the key figures and code snippets seen in this chapter.

#### Tactics Techniques, and Procedures

<figure>
<img src="/assets/images/2/ttp-pyramid.png" style="width: 75%" title="Figure 2-1"/>
<figcaption>Figure 2-1: A depiction of TTPs as a pyramid, highlighting the one-to-many relationships between tactics and techniques, and between techniques and procedures</figcaption>
</figure>

#### MITRE ATT&CK
##### Object Relationships

<figure>
<img src="/assets/images/2/mitre-object-relationship.png" style="width: 75%" title="Figure 2-2"/>
<figcaption>Figure 2-2: Relationships between the object types in ATT&CK</figcaption>
</figure>

##### Techniques and Sub-techniques

<figure>
<img src="/assets/images/2/windows-execution-tactic.png" style="width: 50%" title="Figure 2-3"/>
<figcaption>Figure 2-3: The Execution column in the ATT&CK Enterprise matrix</figcaption>
</figure>

##### Navigator

<figure>
<img src="/assets/images/2/demo-navigator-2.png" style="width: 90%" title="Figure 2-4"/>
<figcaption>Figure 2-4: The ATT&CK Navigator home page, showing options to create or open an existing layer</figcaption>
</figure>

<figure>
<img src="/assets/images/2/demo-navigator-3.png" style="width: 90%" title="Figure 2-5"/>
<figcaption>Figure 2-5: The ATT&CK Navigator showing the commented and color-coded techniques used by APT29</figcaption>
</figure>

#### ATT&CK Tools
##### D3FEND

<figure>
<img src="/assets/images/2/d3fend-relationships.png" style="width: 75%" title="Figure 2-6"/>
<figcaption>Figure 2-6: The object relationships for an executable binary</figcaption>
</figure>

##### Cyber Analytics Repository

A pseudocode implementation of an analytic used to detect the dumping of the LSASS process with a utility called ProcDump:

<code>
processes = search Process:Create <br/>
procdump_lsass = filter processes where ( <br/>
  exe = "procdump*.exe"  and <br/>
  command_line = "*lsass*") <br/>
output procdump_lsass
</code>

#### The Diamond Model of Intrusion Analysis

<figure>
<img src="/assets/images/2/diamond-model.png" style="width: 75%" title="Figure 2-7"/>
<figcaption>Figure 2-7: The features and meta-features of a Diamond Model event</figcaption>
</figure>

##### Extended Model 

<figure>
<img src="/assets/images/2/diamond-model-extended.png" style="width: 75%" title="Figure 2-8"/>
<figcaption>Figure 2-8: The Extended Diamond Model, including overlayed social-political and technology meta-features</figcaption>
</figure>

##### Activity Threads

<figure>
<img src="/assets/images/2/diamond-model-thread.png" style="width: 75%" title="Figure 2-9"/>
<figcaption>Figure 2-9: Activity threads plotted to show Diamond Events used in intrusions across multiple adversaries and victims</figcaption>
</figure>

##### Activity-Attack Graphs

<figure>
<img src="/assets/images/2/diamond-model-activity-attack-graph.png" style="width: 75%" title="Figure 2-10"/>
<figcaption>Figure 2-10: An activity-attack graph, which highlights hypothetical adversary activity alongside known activity threads</figcaption>
</figure>

#### The Pyramid of Pain

<figure>
<img src="/assets/images/2/pyramid-of-pain.png" style="width: 75%" title="Figure 2-11"/>
<figcaption>Figure 2-11: The layers of the Pyramid of Pain</figcaption>
</figure>



<hr>

## Resources

The following resources expand on topics covered in this chapter.
<br/>
<br/>

#### Tactics, Techniques, and Procedures

<div class="row row-cols-1 row-cols-md-1">
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>NIST Special Publication that provides a definition of tactics, techniques and procedures</h6>
                <p><i>Chris Johnson, Lee Badger, David Waltermire, Julie Snyder and Clem Skorupka, "Guide to Cyber Threat Information Sharing" NIST, October, 2016</i></p>
                <a target="_blank" href="https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-150.pdf" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>

</div>
#### MITRE ATT&CK

<div class="row row-cols-1 row-cols-md-1">
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>An overview of the design for MITRE ATT&CK, including object model definitions and design choices</h6>
                <p><i>Blake E. Strom, Andy Applebaum, Doug P. Miller, Kathryn C. Nickels, Adam G. Pennington, Cody B. Thomas, "MITRE ATT&CK: Design and Philosophy" MITRE Corporation, March, 2020</i></p>
                <a target="_blank" href="https://attack.mitre.org/docs/ATTACK_Design_and_Philosophy_March_2020.pdf" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>Introduction of the Impact tactic in MITRE ATT&CK</h6>
                <p><i>"Updates - April 2019” MITRE Corporation, accessed February 29, 2024</i></p>
                <a target="_blank" href="https://attack.mitre.org/resources/updates/updates-april-2019/" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>A complete list of the data sources present in MITRE ATT&CK</h6>
                <p><i>"Data Sources” MITRE Corporation, accessed January 12, 2025</i></p>
                <a target="_blank" href="https://attack.mitre.org/datasources/" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
    
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>A breakdown of Russian cyber-offensive activity and its origins across federal security and foreign intelligence services (FSB and SVR) and other government and military organizations</h6>
                <p><i>"Russian State-Sponsored and Criminal Cyber Threats to Critical Infrastructure" CISA, May 9, 2022</i></p>
                <a target="_blank" href="https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-110a" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>

</div>
#### ATT&CK Tools

<div class="row row-cols-1 row-cols-md-1">
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>A list maintained by MITRE of projects that allow you to access, extend, transform and operationalize the ATT&CK framework</h6>
                <p><i>"ATT&CK Data & Tools” MITRE Corporation, accessed January 12, 2025</i></p>
                <a target="_blank" href="https://attack.mitre.org/resources/related-projects/" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>

    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>A Python module for accessing ATT&CK data</h6>
                <p><i>"Introduction”, accessed January 12, 2025</i></p>
                <a target="_blank" href="https://attackcti.com/" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>

    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>The DeTT&CT project, for analyzing the quality and coverage of data sources in relation to MITRE ATT&CK</h6>
                <p><i>"DeTTECT” GitHub, accessed January 12, 2025</i></p>
                <a target="_blank" href="https://github.com/rabobank-cdc/DeTTECT" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>

    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>The ATT&CK Navigator, for overlaying data on the MITRE ATT&CK matrices</h6>
                <p><i>"attack-navigator” GitHub, accessed January 12, 2025</i></p>
                <a target="_blank" href="https://github.com/mitre-attack/attack-navigator" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>

    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>The D3FEND project, a companion to ATT&CK that lists defensive techniques and countermeasures</h6>
                <p><i>"D3FEND" The MITRE Corporation, accessed January 12, 2025</i></p>
                <a target="_blank" href="https://d3fend.mitre.org/" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>

</div>
#### The Cyber Kill Chain

<div class="row row-cols-1 row-cols-md-1">
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>An introduction to Lockheed Martin's Cyber Kill Chain, including details of each of its stages from an adversary and defender perspective</h6>
                <p><i>"Gaining the Advantage: Applying Cyber Kill Chain Methodology to Network Defense” Lockheed Martin, 2015</i></p>
                <a target="_blank" href="https://www.lockheedmartin.com/content/dam/lockheed-martin/rms/documents/cyber/Gaining_the_Advantage_Cyber_Kill_Chain.pdf" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>

</div>
#### The Diamond Model of Intrusion Analysis

<div class="row row-cols-1 row-cols-md-1">
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>The original research paper detailing the structure, philosophy, and applications of the Diamond Model</h6>
                <p><i>Sergio Caltagirone, Andrew Pendergast and Christopher Betz, "The Diamond Model of Intrusion Analysis” US Department of Defense, May 7, 2013</i></p>
                <a target="_blank" href="https://apps.dtic.mil/sti/pdfs/ADA586960.pdf" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>

</div>
#### The Pyramid of Pain

<div class="row row-cols-1 row-cols-md-1">
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>David J Bianco's blog outlining the usage and application of the Pyramid of Pain</h6>
                <p><i>David J Bianco, "The Pyramid of Pain,” last modified January 17, 2014</i></p>
                <a target="_blank" href="https://detect-respond.blogspot.com/2013/03/the-pyramid-of-pain.html" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>

    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>Details of the Microsoft Windows security feature, Credential Guard</h6>
                <p><i>"Credential Guard overview” Microsoft, September 5, 2023</i></p>
                <a target="_blank" href="https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>

    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>A joint advisory from the United Kingdom's National Cyber Security Centre (NCSC) and the United States' National Security Agency (NSA) detailing the threat group Turla's abuse of OilRig infrastructure</h6>
                <p><i>"Advisory: Turla group exploits Iranian APT to expand coverage of victims” NCSC and NSA, October 21, 2019</i></p>
                <a target="_blank" href="https://www.ncsc.gov.uk/news/turla-group-exploits-iran-apt-to-expand-coverage-of-victims" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>

    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>An example of a static user agent implemented in NCC Group's ScoutSuite tool</h6>
                <p><i>accessed February 29, 2024</i></p>
                <a target="_blank" href="https://github.com/nccgroup/ScoutSuite/blob/967ec5476151aa0256e3a37240e354be00a23176/ScoutSuite/utils.py#L111" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>

    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>Another example of a static user agent implemented in SpecterOps's AzureHound tool</h6>
                <p><i>accessed February 29, 2024</i></p>
                <a target="_blank" href="https://github.com/BloodHoundAD/AzureHound/blob/d2ff1b66bcd343e615255f37ca08fcd018b3b6a4/constants/misc.go#L36" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>

    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>Code in SpecterOps's SharpHound tool designed to create consistently named output files</h6>
                <p><i>accessed February 29, 2024</i></p>
                <a target="_blank" href="https://github.com/BloodHoundAD/SharpHound/blob/ef2b8b388e0e0af2bfa5c08975b6fc869f924729/src/BaseContext.cs#L99" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>

</div>

<div class="container">
  <div class="row">
    <div class="col" style="text-align: left">
      <a href="/part-I/the-basics-of-purple-teaming/" class="btn btn-primary"><< Chapter 1</a>
    </div>
    <div class="col" style="text-align: right">
      <a href="/part-I/the-atomic-methodology/" class="btn btn-primary">Chapter 3 >></a>
    </div>
  </div>
</div>