"""Tests for the enterprise context models + file loaders (clean-room)."""

from __future__ import annotations

import json

import pytest

from redeye.enterprise.loader import (
    EnterpriseError,
    build_enterprise_context,
    load_cmdb,
    load_controls,
    load_cve_feed,
)
from redeye.enterprise.models import (
    AssetCriticality,
    CmdbRecord,
    ControlRecord,
    CveRecord,
    EnterpriseContext,
)


def test_criticality_severity_boost():
    assert AssetCriticality.CROWN_JEWEL.severity_boost == 2
    assert AssetCriticality.HIGH.severity_boost == 1
    assert AssetCriticality.LOW.severity_boost == 0
    assert AssetCriticality.UNKNOWN.severity_boost == 0


def test_cmdb_record_defaults():
    rec = CmdbRecord(application_id="APP-1")
    assert rec.environment == "production"
    assert rec.criticality is AssetCriticality.UNKNOWN
    assert rec.repos == []
    assert rec.extra == {}


def test_context_cwe_lookups():
    ctx = EnterpriseContext(
        cves=[
            CveRecord(cve_id="CVE-2024-1", cwe="CWE-89"),
            CveRecord(cve_id="CVE-2024-2", cwe="CWE-79"),
        ],
        controls=[ControlRecord(control_id="ASVS-5.3.4", cwe=["CWE-89", "CWE-564"])],
    )
    hits = ctx.cves_for_cwe("cwe-89")  # case-insensitive
    assert len(hits) == 1 and hits[0].cve_id == "CVE-2024-1"
    assert ctx.cves_for_cwe(None) == []
    assert len(ctx.controls_for_cwe("CWE-89")) == 1
    assert ctx.controls_for_cwe("CWE-22") == []


def test_is_empty():
    assert EnterpriseContext().is_empty is True
    assert EnterpriseContext(cves=[CveRecord(cve_id="CVE-1")]).is_empty is False


def test_load_cmdb_json(tmp_path):
    p = tmp_path / "cmdb.json"
    p.write_text(
        json.dumps(
            [
                {
                    "application_id": "APP-1",
                    "name": "payments",
                    "criticality": "crown_jewel",
                    "repos": ["org/pay"],
                },
                {"application_id": "APP-2", "name": "blog", "criticality": "low"},
            ]
        )
    )
    cmdb = load_cmdb(p)
    assert set(cmdb) == {"APP-1", "APP-2"}
    assert cmdb["APP-1"].criticality is AssetCriticality.CROWN_JEWEL
    assert cmdb["APP-1"].repos == ["org/pay"]


def test_load_cve_feed_keyed(tmp_path):
    p = tmp_path / "cves.json"
    p.write_text(
        json.dumps({"cves": [{"cve_id": "CVE-2024-9", "cwe": "CWE-78", "components": ["bash"]}]})
    )
    feed = load_cve_feed(p)
    assert len(feed) == 1 and feed[0].cve_id == "CVE-2024-9"
    assert feed[0].components == ["bash"]


def test_build_context_selects_app(tmp_path):
    cmdb = tmp_path / "cmdb.json"
    cmdb.write_text(
        json.dumps(
            [
                {"application_id": "APP-1", "criticality": "high"},
                {"application_id": "APP-2", "criticality": "low"},
            ]
        )
    )
    ctx = build_enterprise_context(application_id="APP-1", cmdb_path=cmdb)
    assert ctx.cmdb is not None and ctx.cmdb.application_id == "APP-1"
    assert ctx.cmdb.criticality is AssetCriticality.HIGH


def test_build_context_single_row_no_appid(tmp_path):
    cmdb = tmp_path / "cmdb.json"
    cmdb.write_text(json.dumps([{"application_id": "ONLY", "criticality": "medium"}]))
    ctx = build_enterprise_context(cmdb_path=cmdb)
    assert ctx.cmdb is not None and ctx.cmdb.application_id == "ONLY"


def test_missing_file_raises():
    with pytest.raises(EnterpriseError):
        load_cmdb("/nonexistent/cmdb.json")


def test_malformed_record_raises(tmp_path):
    p = tmp_path / "controls.json"
    p.write_text(json.dumps([{"title": "missing control_id"}]))
    with pytest.raises(EnterpriseError):
        load_controls(p)
