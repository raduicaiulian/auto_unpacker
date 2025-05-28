Required packages:

    pefile (pip install pefile)

    python-magic (pip install python-magic)

Set up the venv:
    python3 -m venv .venv

Activate venv before running the script
    source ./.venv/bin/activate

Run the script:
    python3 auto_unpacker.py samples

Compile yara:
    TO_DO
    NOTE: I compiled it myself because debian based distros come with an old version wich is unable to interpret yarahub rules

Create test files:

    mkdir samples

    touch samples/a samples/b samples/c