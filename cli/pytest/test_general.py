import pytest
import os
import sys
import glob
import requests
import subprocess
from pathlib import Path

repo = "https://oydid.ownyourdata.eu"

def test_repo():
    response = requests.get(repo + "/api-docs/index.html")
    assert response.status_code == 200

# doc: https://pypi.org/project/pytest-subprocess/
cwd = os.getcwd()
@pytest.mark.parametrize('input',  glob.glob(cwd+'/01_input/*.doc'))
def test_01_simple(fp, input):
    fp.allow_unregistered(True)
    with open(input) as f:
        content = f.read()
    with open(input.replace(".doc", ".cmd")) as f:
        command = f.read()
    with open(input.replace("_input/", "_output/")) as f:
        result = f.read()
    if len(content) > 0:
        command = "cat " + input + " | " + command
    process = subprocess.run(command, shell=True, capture_output=True, text=True)
    assert process.returncode == 0
    if len(result) > 0:
        assert process.stdout.strip() == result.strip()
