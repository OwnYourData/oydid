import pytest
import os
import sys
import glob
import requests
import subprocess
from pathlib import Path

# run in pytest/
# export OYDIDCMD='../oydid.rb'; pytest

service = "https://did2.data-container.net"
oydidcmd = os.getenv('OYDIDCMD') or "oydid"
os.environ["OYDIDCMD"] = oydidcmd

def test_service():
    response = requests.get(service + "/version")
    assert response.status_code == 200
    response_body = response.json()
    assert response_body["service"] == "oydid repository"

cwd = os.getcwd()
@pytest.mark.parametrize('input',  sorted(glob.glob(cwd+'/04_input/*.doc')))
def test_04_digest_a(fp, input):
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
