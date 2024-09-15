echo ""
echo "01000001 01000111 01010000 01010100"
echo "      _____ _____ _____ _____      "
echo "     |  _  |   __|  _  |_   _|     "
echo "     |     |  |  |   __| | |       "
echo "     |__|__|_____|__|    |_|       "
echo "                                   "
echo "01000001 01000111 01010000 01010100"
echo ""

echo ""
echo "[!] This script will download all 'A Guide to Purple Teaming' repos to your local filesystem, in the current directory."
echo "[!] Make sure you have the git command line tool installed and an anti-virus exclusion for this directory."
echo ""

read -p "Ready to download? (y/n): " answer
if [ "$answer" != "y" ]; then
    echo "[!] Aborted."
    exit 0
fi
echo ""

curl "https://api.github.com/orgs/aguidetopurpleteaming/repos?page=1&per_page=100" | grep -e 'clone_url*' | cut -d \" -f 4 | while read -r repo; do
    repo_name=$(basename "${repo}" .git)
    echo ""
    echo "[-] Checking: ${repo_name}"
    if [ -d "$repo_name" ]; then
        cd "$repo_name"
        git pull
        cd ..
    else
        git clone "${repo}"
    fi
done