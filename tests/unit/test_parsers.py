"""
Unit tests for all H-SOC raw telemetry parsers.
"""

import pytest

from hsoc.ingest.parsers import (
    apache,
    cicflow,
    lanl_auth,
    linux_auth,
    wazuh_json,
    win_security,
)


def test_linux_auth_sshd_failure():
    line = "2026-10-25T14:02:10Z db-srv-01 sshd[1234]: Failed password for invalid user root from 203.0.113.15 port 44322 ssh2"
    result = linux_auth.parse(line)
    assert result["source_type"] == "linux_auth"
    assert result["host"] == "db-srv-01"
    assert result["user"] == "root"
    assert result["src_ip"] == "203.0.113.15"
    assert result["dst_port"] == 44322
    assert result["action"] == "ssh_login"
    assert result["outcome"] == "failure"


def test_linux_auth_sshd_success():
    line = "2026-10-25T14:02:15Z db-srv-01 sshd[1235]: Accepted password for alice from 192.168.56.40 port 44324 ssh2"
    result = linux_auth.parse(line)
    assert result["user"] == "alice"
    assert result["outcome"] == "success"
    assert result["src_ip"] == "192.168.56.40"


def test_linux_auth_sudo():
    line = "2026-10-25T14:05:00Z db-srv-01 sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/id"
    result = linux_auth.parse(line)
    assert result["user"] == "alice"
    assert result["action"] == "sudo_command"
    assert result["outcome"] == "success"
    assert result["features"]["command"] == "/usr/bin/id"


def test_linux_auth_invalid():
    with pytest.raises(ValueError):
        linux_auth.parse("completely invalid garbled line")


def test_win_security_json_logon():
    json_line = (
        '{"EventID": 4625, "TimeCreated": "2026-10-25T14:10:00Z", '
        '"Computer": "ws-01", "TargetUserName": "admin", "IpAddress": "203.0.113.20"}'
    )
    res = win_security.parse(json_line)
    assert res["source_type"] == "win_security"
    assert res["user"] == "admin"
    assert res["host"] == "ws-01"
    assert res["src_ip"] == "203.0.113.20"
    assert res["action"] == "win_logon"
    assert res["outcome"] == "failure"


def test_win_security_group_add():
    json_line = (
        '{"EventID": 4728, "TimeCreated": "2026-10-25T14:15:00Z", '
        '"Computer": "db-srv-01", "TargetUserName": "alice", "IpAddress": "-"}'
    )
    res = win_security.parse(json_line)
    assert res["action"] == "group_membership_add"
    assert res["outcome"] == "success"
    assert res["src_ip"] is None


def test_apache_parser_success():
    line = '192.168.56.40 - alice [25/Oct/2026:14:02:10 +0000] "GET /index.html HTTP/1.1" 200 450 "-" "Mozilla/5.0"'
    res = apache.parse(line)
    assert res["source_type"] == "apache"
    assert res["src_ip"] == "192.168.56.40"
    assert res["user"] == "alice"
    assert res["outcome"] == "success"
    assert res["features"]["status_code"] == 200
    assert res["features"]["path"] == "/index.html"


def test_apache_parser_401_failure():
    line = '203.0.113.15 - - [25/Oct/2026:14:02:10 +0000] "GET /admin HTTP/1.1" 401 250 "-" "curl/7.68.0"'
    res = apache.parse(line)
    assert res["src_ip"] == "203.0.113.15"
    assert res["user"] is None
    assert res["outcome"] == "failure"
    assert res["features"]["status_code"] == 401


def test_cicflow_parser():
    row = "2026-10-25T14:00:00+00:00,203.0.113.10,54321,192.168.56.20,80,TCP,0.05,1,0,PortScan"
    res = cicflow.parse(row)
    assert res["source_type"] == "flow"
    assert res["src_ip"] == "203.0.113.10"
    assert res["dst_ip"] == "192.168.56.20"
    assert res["dst_port"] == 80
    assert res["label"] == "PortScan"


def test_lanl_auth_parser():
    line = "100,alice@DOM,bob@DOM,COMP1,COMP2,Kerberos,Network,LogOn,Success"
    res = lanl_auth.parse(line)
    assert res["source_type"] == "lanl_auth"
    assert res["host"] == "COMP2"
    assert res["outcome"] == "success"
    assert res["features"]["auth_type"] == "Kerberos"


def test_wazuh_json_parser():
    alert = (
        '{"timestamp": "2026-10-25T14:20:00Z", "agent": {"name": "db-srv-01"}, '
        '"rule": {"id": "5710", "level": 10, "description": "sshd brute force attempt"}, '
        '"data": {"srcip": "203.0.113.5", "dstuser": "root"}}'
    )
    res = wazuh_json.parse(alert)
    assert res["source_type"] == "wazuh"
    assert res["host"] == "db-srv-01"
    assert res["src_ip"] == "203.0.113.5"
    assert res["user"] == "root"
    assert res["outcome"] == "failure"
