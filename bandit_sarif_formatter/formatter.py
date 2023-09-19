# Copyright (c) Microsoft.  All Rights Reserved.
# Licensed under the MIT license. See LICENSE file in the project root for full license information.

# TODO: baselining (see json.py)
# TODO: Handle manager.agg_type (see json.py)
# TODO: Run pylint or any tool that detects Py2/Py3 differences.

import datetime
import json
import logging
import os
import pathlib
import sys
import urllib.parse as urlparse
import uuid

import sarif_om as om
from bandit.core import docs_utils
from jschema_to_python.to_json import to_json

LOG = logging.getLogger(__name__)

TS_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

SCRIPT_PATH = os.path.dirname(os.path.realpath(__file__))
CWE_DATA_FILE = os.path.join(SCRIPT_PATH, "CWE_4.12.json")
CWE_DATA_DICT = json.loads(open(CWE_DATA_FILE, "r").read())


def report(manager, fileobj, sev_level, conf_level, lines=-1):
    """Prints issues in SARIF format

    :param manager: the bandit manager object
    :param fileobj: The output file object, which may be sys.stdout
    :param sev_level: Filtering severity level
    :param conf_level: Filtering confidence level
    :param lines: Number of lines to report, -1 for all
    """

    run_uuid = uuid.uuid4()
    issues = manager.get_issue_list(sev_level=sev_level, conf_level=conf_level)
    results = []
    rules = {}
    rule_indices = {}
    for issue in issues:
        result = create_result(issue, rules, rule_indices, run_uuid)
        results.append(result)

    log = om.SarifLog(
        schema_uri="https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.4.json",
        version="2.1.0",
        runs=[
            om.Run(
                taxonomies=create_taxonomies_element(results, run_uuid),
                tool=om.Tool(
                    driver=om.ToolComponent(
                        name="Bandit",
                        supported_taxonomies=[{"name": "CWE", "guid": run_uuid}],
                    )
                ),
                invocations=[
                    om.Invocation(
                        end_time_utc=datetime.datetime.utcnow().strftime(TS_FORMAT),
                        execution_successful=True,
                    )
                ],
                properties={"metrics": manager.metrics.data},
            )
        ],
    )

    run = log.runs[0]
    invocation = run.invocations[0]

    skips = manager.get_skipped()
    add_skipped_file_notifications(skips, invocation)

    if run.results is None:
        run.results = []

    run.results += results

    if len(rules) > 0:
        run.tool.driver.rules = list(
            add_relationship_to_rules(rules, results, run_uuid).values()
        )  # TODO: Different in Python 2 (no "list")

    serializedLog = to_json(log)

    with fileobj:
        fileobj.write(serializedLog)

    if fileobj.name != sys.stdout.name:
        LOG.info("SARIF output written to file: %s", fileobj.name)


def add_skipped_file_notifications(skips, invocation):
    if skips is None or len(skips) == 0:
        return

    if invocation.tool_configuration_notifications is None:
        invocation.tool_configuration_notifications = []

    for skip in skips:
        (file_name, reason) = skip

        notification = om.Notification(
            level="error",
            message=om.Message(text=reason),
            locations=[
                om.Location(
                    physical_location=om.PhysicalLocation(
                        artifact_location=om.ArtifactLocation(uri=to_uri(file_name))
                    )
                )
            ],
        )

        invocation.tool_configuration_notifications.append(notification)


def find_in_cwe(cweid):
    cwe_finding = None
    for weakness in CWE_DATA_DICT["weaknesses"]:
        if weakness["cweid"] == cweid:
            cwe_finding = weakness
            break
    return cwe_finding


def create_taxa_element(cweid, run_uuid):
    return {
        "id": str(cweid),
        "guid": run_uuid,
        "toolComponent": {"name": "CWE", "guid": uuid.uuid4()},
    }


def extend_taxa_element(taxa):
    result = taxa.copy()
    cwe_finding = find_in_cwe(taxa["id"])
    result["name"] = cwe_finding["name"]
    result["shortDescription"] = {"text": cwe_finding["description"]}
    result["defaultConfiguration"] = {"level": cwe_finding["severity"]}
    return result


def create_taxonomies_element(results, run_uuid):
    return {
        "name": CWE_DATA_DICT["name"],
        "version": CWE_DATA_DICT["version"],
        "releaseDateUtc": CWE_DATA_DICT["date"],
        "guid": run_uuid,
        "informationUri": CWE_DATA_DICT["informationUri"],
        "downloadUri": CWE_DATA_DICT["downloadUri"],
        "organization": CWE_DATA_DICT["organization"],
        "shortDescription": {"text": CWE_DATA_DICT["shortDescription"]},
        "taxa": [extend_taxa_element(result.taxa) for result in results],
    }


def add_relationship_to_rules(rules, results, run_uuid):
    for rule in rules:
        for result in results:
            if result.rule_id == rule:
                rules[rule].relationships = {
                    "target": {
                        "id": result.taxa["id"],
                        "guid": run_uuid,
                        "toolComponent": {
                            "name": "CWE",
                            "guid": result.taxa["toolComponent"]["guid"],
                        },
                    },
                    "kinds": ["superset"],
                }
    return rules


def create_result(issue, rules, rule_indices, run_uuid):
    issue_dict = issue.as_dict()

    rule, rule_index = create_or_find_rule(issue_dict, rules, rule_indices)

    physical_location = om.PhysicalLocation(
        artifact_location=om.ArtifactLocation(uri=to_uri(issue_dict["filename"]))
    )

    add_region_and_context_region(
        physical_location, issue_dict["line_number"], issue_dict["code"]
    )

    return om.Result(
        rule_id=rule.id,
        rule_index=rule_index,
        message=om.Message(text=issue_dict["issue_text"]),
        level=level_from_severity(issue_dict["issue_severity"]),
        locations=[om.Location(physical_location=physical_location)],
        taxa=create_taxa_element(issue_dict["issue_cwe"]["id"], run_uuid),
        properties={
            "issue_confidence": issue_dict["issue_confidence"],
            "issue_severity": issue_dict["issue_severity"],
        },
    )


def level_from_severity(severity):
    if severity == "HIGH":
        return "error"
    elif severity == "MEDIUM":
        return "warning"
    elif severity == "LOW":
        return "note"
    else:
        return "warning"


def add_region_and_context_region(physical_location, line_number, code):
    first_line_number, snippet_lines = parse_code(code)
    snippet_line = snippet_lines[line_number - first_line_number]

    physical_location.region = om.Region(
        start_line=line_number, snippet=om.ArtifactContent(text=snippet_line)
    )

    physical_location.context_region = om.Region(
        start_line=first_line_number,
        end_line=first_line_number + len(snippet_lines) - 1,
        snippet=om.ArtifactContent(text="".join(snippet_lines)),
    )


def parse_code(code):
    code_lines = code.split("\n")

    # The last line from the split has nothing in it; it's an artifact of the
    # last "real" line ending in a newline. Unless, of course, it doesn't:
    last_line = code_lines[len(code_lines) - 1]

    last_real_line_ends_in_newline = False
    if len(last_line) == 0:
        code_lines.pop()
        last_real_line_ends_in_newline = True

    snippet_lines = []
    first = True
    for code_line in code_lines:
        number_and_snippet_line = code_line.split(" ", 1)
        if first:
            first_line_number = int(number_and_snippet_line[0])
            first = False

        snippet_line = number_and_snippet_line[1] + "\n"
        snippet_lines.append(snippet_line)

    if not last_real_line_ends_in_newline:
        last_line = snippet_lines[len(snippet_lines) - 1]
        snippet_lines[len(snippet_lines) - 1] = last_line[: len(last_line) - 1]

    return first_line_number, snippet_lines


def create_or_find_rule(issue_dict, rules, rule_indices):
    rule_id = issue_dict["test_id"]
    if rule_id in rules:
        return rules[rule_id], rule_indices[rule_id]

    rule = om.ReportingDescriptor(
        id=rule_id, name=issue_dict["test_name"], help_uri=docs_utils.get_url(rule_id)
    )

    index = len(rules)
    rules[rule_id] = rule
    rule_indices[rule_id] = index
    return rule, index


def to_uri(file_path):
    pure_path = pathlib.PurePath(file_path)
    if pure_path.is_absolute():
        return pure_path.as_uri()
    else:
        posix_path = pure_path.as_posix()  # Replace backslashes with slashes.
        return urlparse.quote(posix_path)  # %-encode special characters.
