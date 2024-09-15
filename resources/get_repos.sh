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

echo "Ready to download? (y/n): " 
read -r answer </dev/tty
if [ "$answer" != "y" ]; then
    echo "[!] Aborted."
    exit 0
fi
echo ""

curl "https://api.github.com/orgs/aguidetopurpleteaming/repos?page=1&per_page=100" | grep -e 'clone_url*' | cut -d \" -f 4 | while read -r repo; do
    repo_name=$(basename "${repo}" .git)
    echo ""
    if [ -d "$repo_name" ]; then
        echo "[-] Updating: ${repo_name}"
        cd "$repo_name"
        git pull
        cd ..
    else
        echo "[-] Fetching: ${repo_name}"
        git clone "${repo}"
    fi
done