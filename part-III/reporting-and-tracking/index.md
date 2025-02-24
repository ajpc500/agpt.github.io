---
layout: default
title: Reporting and Tracking
tags: []
header_type       : "hero"
include_on_search : true
show_tags         : true
---


<div class="bs-component">
    <div class="progress">
        <div class="progress-bar progress-bar-striped progress-bar-animated" role="progressbar" aria-valuemin="0" aria-valuemax="100" style="width: 91.66%; background-color:#eb34e1"></div>
    </div>
</div>

## Introduction

In Part III of the book, we focus on organizing exercises and establishing a purple teaming function in your organization. In this first chapter we consider effective methods for reporting and tracking your emulation activities, whether that be via spreadsheet, ticketing system or a purpose-built platform like SRA's VECTR.

<hr>

## Chapter Content

This section provides reproductions of the key figures and code snippets seen in this chapter.

#### Ticketing Systems

##### Kanban Boards

<figure>
<img src="/assets/images/11/kanban-0.png" style="width: 100%" title="Figure 11-1"/>
<figcaption>Figure 11-1: A kanban board with test cases transitioning through states</figcaption>
</figure>


##### Ticket Comments and Attachments

<figure>
<img src="/assets/images/11/kanban-1.png" style="width: 75%" title="Figure 11-1"/>
<figcaption>Figure 11-1: A kanban board with test cases transitioning through states</figcaption>
</figure>


#### VECTR

##### Deployment

Commands to fetch and unarchive a VECTR release to the `/opt` directory.

```sh
ubuntu@agpt:~$ mkdir -p /opt/vectr
ubuntu@agpt:~$ cd /opt/vectr
ubuntu@agpt:/opt/vectr$ curl -L -O https://github.com/SecurityRiskAdvisors/VECTR/releases/download/ce-X.X.X/sra-vectr-runtime-X.X.X-ce.zip
ubuntu@agpt:/opt/vectr$ unzip sra-vectr-runtime-X.X.X-ce.zip
```

An example of VECTR's `.env` file.

```ini
# .env file
APP_NAME=VECTR
VECTR_HOSTNAME=localhost
VECTR_PORT=8081

# defaults to warn, debug useful for development
VECTR_CONTAINER_LOG_LEVEL=WARN

# PLEASE change this and store it in a safe place.  Encrypted data like passwords
# to integrate with external systems (like TAXII) use this key
VECTR_DATA_KEY=A_STRONG_PASSWORD

# JWT signing (JWS) and encryption (JWE) keys
# Do not use the same value for both signing and encryption!
# It is recommended to use at least 16 characters. You may use any printable unicode character
# PLEASE change these example values!
JWS_KEY=A_STRONG_PASSWORD
JWE_KEY= A_STRONG_PASSWORD

# This sets the name of your project.  Will show up in the name of your containers.
COMPOSE_PROJECT_NAME=vectr

# This is where the mongodb mounts.
VECTR_DATA_DIR=/var/data/

POSTGRES_PASSWORD=A_STRONG_PASSWORD
POSTGRES_USER=vectr
POSTGRES_DB=vectr
```

A command to launch VECTR and run it in the background, as well as the resulting output.

```sh
ubuntu@agpt:/opt/vectr$ sudo docker compose up -d

[+] Building 0.0s (0/0)                         docker:desktop-linux
[+] Running 7/7
 ✔ Container vectr-vectr-postgres-1       Started              0.0s 
 ✔ Container vectr-vectr-rta-redis-1      Started              0.0s 
 ✔ Container vectr-vectr-rta-webserver-1  Started              0.0s 
 ✔ Container vectr-vectr-tomcat-1         Started              0.0s 
 ✔ Container vectr-vectr-rta-builder-1    Started              0.0s 
 ✔ Container vectr-vectr-webui-1          Started              0.0s 
 ✔ Container vectr-vectr-caddy-gateway-1  Started              0.0s
```

##### Environments


<figure>
<img src="/assets/images/11/vectr-1.png" style="width: 75%" title="Figure 11-4"/>
<figcaption>Figure 11-4: The nested structure of VECTR environments</figcaption>
</figure>

##### Test Cases 

Red and blue data input areas in VECTR.

<div id="carouselExampleControls" class="carousel slide" style="width: auto" data-ride="carousel">
  <ol class="carousel-indicators">
    <li data-target="#carouselExampleIndicators" data-slide-to="0" class="active"></li>
    <li data-target="#carouselExampleIndicators" data-slide-to="1"></li>
  </ol>
  <div class="carousel-inner">
    <div class="carousel-item active">
      <figure>
        <img src="/assets/images/11/vectr-5.png" style="width: 100%" title="Figure 11-6"/>
        <figcaption>Figure 11-6: The red team data-input area for a test case in VECTR</figcaption>
      </figure>
      <br/><br/>
    </div>
    <div class="carousel-item">
      <figure>
        <img src="/assets/images/11/vectr-6.png" style="width: 100%" title="Figure 11-7"/>
        <figcaption>Figure 11-7: The blue team data-input area for a test case in VECTR</figcaption>
      </figure>
      <br/><br/>
    </div>
  </div>
  <a class="carousel-control-prev" href="#carouselExampleControls" role="button" data-slide="prev">
    <span class="carousel-control-prev-icon" aria-hidden="true"></span>
    <span class="sr-only">Previous</span>
  </a>
  <a class="carousel-control-next" href="#carouselExampleControls" role="button" data-slide="next">
    <span class="carousel-control-next-icon" aria-hidden="true"></span>
    <span class="sr-only">Next</span>
  </a>
</div>

<figure>
  <img src="/assets/images/11/vectr-7.png" style="width: 100%" title="Figure 11-8"/>
  <figcaption>Figure 11-8: An attack chain plotted based on VECTR test case input</figcaption>
</figure>


<hr>

## Resources

The following resources expand on topics covered in this chapter.
<br/>
<br/>


#### Choosing an Exercise Tracking Solution
<div class="row row-cols-1 row-cols-md-1">
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>Outflank's open-source RedELK project, highlighting the potential for red team log collection</h6>
                <p><i>"RedELK," accessed October 2, 2024</i></p>
                <a target="_blank" href="https://github.com/outflanknl/RedELK" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
</div>

#### Ticketing Systems
<div class="row row-cols-1 row-cols-md-1">
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>A Python library for interacting with JIRA via its REST APIs</h6>
                <p><i>"jira," accessed October 2, 2024</i></p>
                <a target="_blank" href="https://pypi.org/project/jira/" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
</div>

#### Spreadsheets
<div class="row row-cols-1 row-cols-md-1">
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>The scoring system for DeTT&CT, providing a means to objectively assess completeness and fidelity of logs and alerting</h6>
                <p><i>"scoring_table," accessed October 2, 2024</i></p>
                <a target="_blank" href="https://github.com/rabobank-cdc/DeTTECT/raw/master/scoring_table.xlsx" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
</div>

#### VECTR
<div class="row row-cols-1 row-cols-md-1">
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>The latest releases of VECTR can be found on GitHub</h6>
                <p><i>"Releases," accessed November 10, 2024</i></p>
                <a target="_blank" href="https://github.com/SecurityRiskAdvisors/VECTR/releases" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>VECTR has a GraphQL API to programmatically interact with assessments, campaigns and test cases. SRA provides an example application using this API</h6>
                <p><i>"vectr-tools," accessed November 10, 2024</i></p>
                <a target="_blank" href="https://github.com/SecurityRiskAdvisors/vectr-tools" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
    <div class="col mb-4">
        <div class="card">
            <div class="card-body">
                <h6>An example of a third-party tool that enables the automated import of email gateway testing into VECTR</h6>
                <p><i>"Importing delivr.to Results into VECTR," accessed October 2, 2024</i></p>
                <a target="_blank" href="https://docs.delivr.to/docs/advanced_usage/vectr_import.html" class="btn btn-primary" style="background-color:#eb34e1">Read More</a>
            </div>
        </div>
    </div>
</div>


<div class="container">
  <div class="row">
    <div class="col" style="text-align: left">
      <a href="/part-II/domain-compromise-with-mythic/" class="btn btn-primary"><< Chapter 10</a>
    </div>
    <div class="col" style="text-align: right">
      <a href="/part-III/implementing-a-purple-teaming-function/" class="btn btn-primary">Chapter 12 >></a>
    </div>
  </div>
</div>