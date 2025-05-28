Required packages:

    pefile (pip install pefile)

    python-magic (pip install python-magic)

Set up the venv:
    python3 -m venv .venv

Activate venv before running the script
    source ./.venv/bin/activate

Run the script:
    python3 auto_unpacker.py samples

Install die:
    wget https://github.com/horsicq/DIE-engine/releases/download/3.10/die_3.10_Ubuntu_22.04_amd64.deb
    dpkg -i die_3.10_Ubuntu_22.04_amd64.deb

Create test files:

    mkdir samples

    touch samples/a samples/b samples/c