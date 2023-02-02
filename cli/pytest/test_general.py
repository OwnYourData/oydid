import pytest
import os
import sys
import glob
import requests
import subprocess
from pathlib import Path

# run in pytest/
# export OYDIDCMD='../oydid.rb'; pytest

service = "https://oydid-registrar.data-container.net"
oydidcmd = os.getenv('OYDIDCMD') or "oydid"
os.environ["OYDIDCMD"] = oydidcmd

def test_service():
    response = requests.get(service + "/version")
    assert response.status_code == 200

# test groups
# 01 - general tests for CLI
# 02 - uniresolver tests
# 03 - uniregistrar tests
# 04 - digest agility tests

# doc: https://pypi.org/project/pytest-subprocess/
cwd = os.getcwd()
@pytest.mark.parametrize('input',  glob.glob(cwd+'/01_input/*.doc'))
# def test_01_simple(input):
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
