Write-Host ""
Write-Host "01000001 01000111 01010000 01010100"
Write-Host "      _____ _____ _____ _____      "
Write-Host "     |  _  |   __|  _  |_   _|     "
Write-Host "     |     |  |  |   __| | |       "
Write-Host "     |__|__|_____|__|    |_|       "
Write-Host "                                   "
Write-Host "01000001 01000111 01010000 01010100"
Write-Host ""

Write-Host ""
Write-Host "[!] This script will download all 'A Guide to Purple Teaming' repos to your local filesystem, in the current directory."
Write-Host "[!] Make sure you have the git command line tool installed and an anti-virus exclusion for this directory."
Write-Host ""

$answer = Read-Host "Ready to download? (y/n): "
if ($answer -ne "y") {
    Write-Host "[!] Aborted."
    exit 0
}
Write-Host ""

# Fetch the list of repositories from the GitHub API
$repos = Invoke-RestMethod -Uri "https://api.github.com/orgs/aguidetopurpleteaming/repos?page=1&per_page=100" 

foreach ($repoObj in $repos) {
    $repo = $repoObj.clone_url
    $repo_name = $repoObj.name

    # Check if the repository folder already exists
    if (Test-Path $repo_name -PathType Container) {
        Write-Host "[-] Updating: $repo_name"
        Set-Location $repo_name
        git pull
        Set-Location ..
    }
    else {
        Write-Host "[-] Cloning: $repo_name"
        git clone $repo
    }

    Write-Host ""
}