curl "https://api.github.com/orgs/aguidetopurpleteaming/repos?page=1&per_page=100" | grep -e 'clone_url*' | cut -d \" -f 4 | while read -r repo; do
    repo_name=$(basename "${repo}" .git)
    echo "Checking: ${repo_name}"
    if [ -d "$repo_name" ]; then
        cd "$repo_name"
        git pull
        cd ..
    else
        git clone "${repo}"
    fi
done