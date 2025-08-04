#!/usr/bin/env python3
# Copyright 2024 Ubuntu
# See LICENSE file for licensing details.

import logging
import pathlib
import subprocess
import urllib.request

import jubilant

logger = logging.getLogger(__name__)

APP_NAME = "lego-operator"


def test_deploy_lego(juju: jubilant.Juju, charm_path: pathlib.Path):
    def workload_status(status: jubilant.Status) -> str:
        return status.apps[APP_NAME].units[f"{APP_NAME}/0"].workload_status.current

    config = {
        "email": "example@gmail.com",
        "server": "https://acme-staging-v02.api.letsencrypt.org/directory",
        "plugin": "namecheap",
    }
    juju.deploy(charm_path, app=APP_NAME, config=config)
    juju.wait(lambda status: workload_status(status) == "blocked")

    secret_data = {"namecheap-api-key": "key1", "namecheap-api-user": "me"}
    secret_uri = juju.add_secret("plugin-credentials", secret_data)
    juju.grant_secret(secret_uri, app=APP_NAME)
    juju.config(APP_NAME, {"plugin-config-secret-id": secret_uri.unique_identifier})
    juju.wait(lambda status: jubilant.all_active(status, APP_NAME))

    assert workload_status(juju.status()) == "active"
    juju.remove_application(APP_NAME)
    juju.remove_secret(secret_uri)


def test_deploy_functional(juju: jubilant.Juju, charm_path: pathlib.Path):
    microk8s_cmd = [
        "microk8s",
        "kubectl",
        "apply",
        "-f",
        "tests/integration/pebble.yaml",
    ]
    try:
        subprocess.check_output(microk8s_cmd)
    except subprocess.CalledProcessError:
        subprocess.check_output(["sudo", *microk8s_cmd])

    uri = juju.add_secret("plugin-config", {"httpreq-endpoint": "http://127.0.0.1:8080"})  # DNS
    config = {
        "email": "example@example.com",
        "plugin": "httpreq",
        "server": "https://pebble:14000/dir",  # ACME
        "plugin-config-secret-id": uri.unique_identifier,
    }
    juju.deploy(charm_path, config=config)
    juju.grant_secret(uri.unique_identifier, "lego")
    juju.deploy("tls-certificates-requirer", config={"common_name": "example.com"}, channel="edge")
    juju.wait(jubilant.all_active)

    # trust letsencrypt/pebble's self-signed-certificate
    # TODO: when lego supports receiving a certificate and vault bug is fixed, do that instead
    p = pathlib.Path("pebble-ca.pem")
    url = "https://raw.githubusercontent.com/letsencrypt/pebble/refs/heads/main/test/certs/pebble.minica.pem"
    urllib.request.urlretrieve(url, p)
    # TODO: set SSL_CERT_FILE via secret data instead
    juju.scp(p, "lego/0:/etc/ssl/certs/")
    juju.exec("c_rehash", "/etc/ssl/certs/", unit="lego/0")

    # deploy our challenge listener + dns resolver into the lego container
    juju.scp("tests/integration/server.py", "lego/0:/")
    juju.scp("tests/integration/requirements.txt", "lego/0:/")
    resolv_conf = """
search model.svc.cluster.local
nameserver 127.0.0.1
options ndots:5
""".strip()
    ssh_cmds = [
        "cd /",
        "curl -LsSf https://astral.sh/uv/install.sh | sh",
        "/root/.local/bin/uv venv",
        "/root/.local/bin/uv pip install -r requirements.txt",
        f"echo -e '{resolv_conf}' > /etc/resolv.conf",
    ]
    juju.ssh("lego/0", " && ".join(ssh_cmds))
    # juju.ssh uses subprocess with a ['list', 'of', 'args'], which mangles the quoting on our bash -c
    ssh_cmd = "cd / && bash -c 'source .venv/bin/activate && nohup python3 server.py > /server.log2 2>&1 & sleep 1'"
    try:
        subprocess.check_output(f'juju ssh lego/0 "{ssh_cmd}"', shell=True, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError as e:
        logging.error("stdout %s", e.stdout)
        logging.error("stderr %s", e.stderr)
        raise

    # request certificate
    juju.integrate("lego", "tls-certificates-requirer")
    # failure to acquire certificate doesn't show up in status, only in logs
    juju.wait(jubilant.all_active)
    # certificate fails to be acquired because pebble-challtestsrv doesn't appear to respond to anything
    # currently not verified in this test
