---
layout: default
title: Implementing a Purple Teaming Function
tags: []
header_type       : "hero"
include_on_search : true
show_tags         : true
---


<div class="bs-component">
    <div class="progress">
        <div class="progress-bar progress-bar-striped progress-bar-animated" role="progressbar" aria-valuemin="0" aria-valuemax="100" style="width: 100%; background-color:#eb34e1"></div>
    </div>
</div>


## Introduction

In Part III of the book, we focus on organizing exercises and establishing a purple teaming function in your organization. In this first chapter we consider effective methods for reporting and tracking your emulation activities, whether that be via spreadsheet, ticketing system or a purpose-built platform like SRA's VECTR.

<hr>

## Chapter Content

This section provides reproductions of the key figures and code snippets seen in this chapter.

#### Maturing Your Purple Team Processes

##### Attack Automation

###### Development Considerations

<div class="bs-component">
    <div class="alert alert-warning">
        See ProcDump in the LOLBAS project: <a target="_blank" href="https://lolbas-project.github.io/lolbas/OtherMSBinaries/Procdump/">https://lolbas-project.github.io/lolbas/OtherMSBinaries/Procdump/</a>
    </div>
</div>

A command that leverages the `procdump.exe` LOLBIN to load an arbitrary DLL.

```sh
C:\Tools> procdump.exe -md malware.dll foobar
```

###### Alert Regression Testing

<figure>
<img src="/assets/images/12/alert-regression.png" style="width: 100%" title="Figure 12-1"/>
<figcaption>Figure 12-1: A workflow for operationalizing attack automation for alert regression testing</figcaption>
</figure>


##### A Continuous Purple Teaming Cycle

<img src="/assets/images/12/continuous-purple-teaming.png" style="width: 100%" title="A Continuous Purple Teaming Cycle"/>



<hr>

## Resources

The following resources expand on topics covered in this chapter.
<br/>
<br/>

#### Attack Automation
<div class="row row-cols-1 row-cols-md-1">
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>Documented LOLBAS options for ProcDump</h6>
                <p><i>"ProcDump," LOLBAS, accessed December 15, 2024</i></p>
                <a target="_blank" href="https://lolbas-project.github.io/lolbas/OtherMSBinaries/Procdump/" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
</div>

#### A Continuous Purple Teaming Cycle
<div class="row row-cols-1 row-cols-md-1">
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>A Sigma rule for the detection of anomalous web server child processes</h6>
                <p><i>"process_creation/proc_creation_win_webshell_susp_process_spawned_from_webserver.yml", GitHub, accessed December 15, 2024</i></p>
                <a target="_blank" href="https://github.com/SigmaHQ/sigma/blob/9f54b01218bde8ed60177d1b210cb3ccf625237b/rules/windows/process_creation/proc_creation_win_webshell_susp_process_spawned_from_webserver.yml" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
</div>



<div class="container">
  <div class="row">
    <div class="col" style="text-align: left">
      <a href="/part-III/reporting-and-tracking/" class="btn btn-primary"><< Chapter 11</a>
    </div>
    <div class="col" style="text-align: right">
      <a href="/" class="btn btn-primary">Home</a>
    </div>
  </div>
</div>