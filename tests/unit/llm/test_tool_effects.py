"""The effect table and its fallback (W1.7)."""

import pytest

from core.llm import tool_effects
from core.llm.tool_effects import (
    DESTRUCTIVE,
    GATED,
    HEURISTIC_SOURCE,
    MANIFEST_SOURCE,
    READ_ONLY,
    RECORDS,
    WRITE,
    classify,
    effect_of,
    gated_ids,
    heuristic,
    is_gated,
)

pytestmark = pytest.mark.unit


def test_gated_is_write_and_destructive():
    assert GATED == {WRITE, DESTRUCTIVE}


@pytest.mark.parametrize(
    "name, effect",
    [
        ("mde_isolate", DESTRUCTIVE),
        ("microsoft-defender_mde_isolate", DESTRUCTIVE),
        ("cb_quarantine", DESTRUCTIVE),
        ("aad_disable_user", DESTRUCTIVE),
        ("pan_block_ip", DESTRUCTIVE),
        ("cf_waf_unblock_ip", DESTRUCTIVE),
        ("atomic-red-team_atomic_red_team_execute", DESTRUCTIVE),
        ("slack_send_alert", WRITE),
        ("cape-sandbox_cape_submit_file", WRITE),
        ("splunk-selfhosted_splunk_execute", READ_ONLY),
        ("splunk_splunk_execute", READ_ONLY),
        ("create_case", RECORDS),
        ("close_case", RECORDS),
        ("get_finding", READ_ONLY),
    ],
)
def test_the_table_classifies_by_name_and_by_flattened_name(name, effect):
    assert classify(name) == tool_effects.Effect(effect, MANIFEST_SOURCE)


@pytest.mark.parametrize(
    "name, effect",
    [
        # A destructive verb anywhere, whatever leads.
        ("crowdstrike_contain_host", DESTRUCTIVE),
        ("isolate_host", DESTRUCTIVE),
        ("get_and_delete_rule", DESTRUCTIVE),
        ("okta_revoke_session", DESTRUCTIVE),
        # A write verb.
        ("github_create_issue", WRITE),
        ("jira_update_ticket", WRITE),
        # A read verb in the first three tokens, and nothing that writes.
        ("virustotal_get_file_report", READ_ONLY),
        ("splunk_query", READ_ONLY),
        ("acme-edr_xdr_get_host", READ_ONLY),
        ("mde_get_isolation_status", READ_ONLY),
        ("jira_list_contained_hosts", READ_ONLY),
        # Words split on "-" and camelCase too, so a verb cannot hide (W0.10).
        ("get_hostAndIsolate", DESTRUCTIVE),
        ("list-users-delete", DESTRUCTIVE),
        ("acme_getHostThenWipe", DESTRUCTIVE),
        ("fetchAndUpdateTicket", WRITE),
        ("getUser", READ_ONLY),
        ("acme-edr_getHostStatus", READ_ONLY),
        # Only the leading verb reads: a read word further in is not the verb.
        ("shodan_search_host", READ_ONLY),
        ("acme_frobnicate_get", DESTRUCTIVE),
        ("acme_frobnicate_get_host", DESTRUCTIVE),
        ("foo_bar_baz_get", DESTRUCTIVE),
        # Moving data out is not a read, whatever follows.
        ("export_list_users", WRITE),
        ("acme_transfer_query_results", WRITE),
        # Says nothing: the restrictive end.
        ("acme_frobnicate", DESTRUCTIVE),
        ("vendor_tool", DESTRUCTIVE),
        ("", DESTRUCTIVE),
    ],
)
def test_the_fallback_errs_restrictive(name, effect):
    assert heuristic(name) == effect
    assert classify(name) == tool_effects.Effect(effect, HEURISTIC_SOURCE)


def test_gated_ids_keeps_order_and_drops_reads():
    names = ["get_finding", "pan_block_ip", "create_case", "slack_send_alert"]
    assert gated_ids(names) == ["pan_block_ip", "slack_send_alert"]
    assert is_gated("pan_block_ip") and not is_gated("create_case")


def test_effect_of_is_the_class_alone():
    assert effect_of("mde_isolate") == DESTRUCTIVE


def test_a_flattened_name_maps_back_to_its_server():
    assert tool_effects.server_for("palo-alto_pan_block_ip") == "palo-alto"
    assert tool_effects.server_for("pan_block_ip") is None


def test_the_mirror_check_reports_a_stale_file(tmp_path, monkeypatch):
    stale = tmp_path / "tool-effects.ts"
    stale.write_text("// old\n")
    monkeypatch.setattr(tool_effects, "MIRROR_PATH", stale)
    assert tool_effects.main([]) == 1
    assert tool_effects.main(["--write"]) == 0
    assert tool_effects.main([]) == 0
