# TODO: baselining (see json.py)
# TODO: Handle manager.agg_type (see json.py)
# TODO: Run pylint or any tool that detects Py2/Py3 differences.

import datetime
import json
import logging
import pathlib
import urllib.parse as urlparse
import sys

from bandit.core import docs_utils
import bandit_sarif_formatter.sarif_object_model as om

LOG = logging.getLogger(__name__)

TS_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

def report(manager, fileobj, sev_level, conf_level, lines=-1):
    '''''Prints issues in SARIF format

    :param manager: the bandit manager object
    :param fileobj: The output file object, which may be sys.stdout
    :param sev_level: Filtering severity level
    :param conf_level: Filtering confidence level
    :param lines: Number of lines to report, -1 for all
    '''
    log = om.SarifLog()

    run = om.Run()
    log.runs.append(run)

    driver = om.ToolComponent()
    driver.name = "Bandit"

    tool = om.Tool()
    tool.driver = driver

    run.tool = tool

    invocation = om.Invocation()
    run.invocations.append(invocation)

    invocation.endTimeUtc = datetime.datetime.utcnow().strftime(TS_FORMAT)
    invocation.executionSuccessful = True

    skips = manager.get_skipped()
    add_skipped_file_notifications(skips, invocation)

    issues = manager.get_issue_list(sev_level=sev_level,
                                    conf_level=conf_level)

    add_results(issues, run)

    run.properties = {
        "metrics": manager.metrics.data
    }

    log = del_none(log)
    serializedLog = toJSON(log)

    with fileobj:
        fileobj.write(serializedLog)

    if fileobj.name != sys.stdout.name:
        LOG.info("SARIF output written to file: %s", fileobj.name)

def add_skipped_file_notifications(skips, invocation):
    if skips is None or len(skips) == 0:
        return

    if invocation.toolConfigurationNotifications is None:
        invocation.toolConfigurationNotifications = []

    for skip in skips:
        (file_name, reason) = skip

        message = om.Message()
        message.text = reason

        artifactLocation = om.ArtifactLocation()
        artifactLocation.uri = to_uri(file_name)

        physicalLocation = om.PhysicalLocation()
        physicalLocation.artifactLocation = artifactLocation

        location = om.Location()
        location.physicalLocation = physicalLocation

        notification = om.Notification()
        notification.level = om.LEVEL_ERROR
        notification.message = message
        notification.locations = [location]

        invocation.toolConfigurationNotifications.append(notification)

def add_results(issues, run):
    if run.results is None:
        run.results = []

    rules = {}
    for issue in issues:
        result = create_result(issue, rules)
        run.results.append(result)

    if len(rules) > 0:
        run.tool.driver.rules = list(rules.values()) # TODO: Different in Python 2 (no "list")

def create_result(issue, rules):
    result = om.Result()
    issue_dict = issue.as_dict()

    result.ruleId = issue_dict["test_id"]

    result.level = level_from_severity(issue_dict["issue_severity"])

    message = om.Message()
    message.text = issue_dict["issue_text"]
    result.message = message

    artifactLocation = om.ArtifactLocation()
    artifactLocation.uri = to_uri(issue_dict["filename"])

    physicalLocation = om.PhysicalLocation()
    physicalLocation.artifactLocation = artifactLocation

    add_region_and_context_region(physicalLocation, issue_dict["line_number"], issue_dict["code"])

    rule = create_or_find_rule(issue_dict, rules)
    result.ruleId = rule.id
    result.ruleIndex = rule.index

    location = om.Location()
    location.physicalLocation = physicalLocation

    result.locations = [location]

    result.properties = {
        "issue_confidence": issue_dict["issue_confidence"],
        "issue_severity": issue_dict["issue_severity"]
    }

    return result

def level_from_severity(severity):
    if severity == "HIGH":
        return om.LEVEL_ERROR
    elif severity == "MEDIUM":
        return om.LEVEL_WARNING
    elif severity == "LOW":
        return om.LEVEL_NOTE
    else:
        return om.LEVEL_WARNING

def add_region_and_context_region(physicalLocation, line_number, code):
    region = om.Region()
    region.startLine = line_number

    first_line_number, snippet_lines = parse_code(code)
    snippet_line = snippet_lines[line_number - first_line_number]

    snippet = om.ArtifactContent()
    snippet.text = snippet_line
    region.snippet = snippet

    physicalLocation.region = region

    context_region = om.Region()
    context_region.startLine = first_line_number
    context_region.endLine = first_line_number + len(snippet_lines) - 1

    context_snippet = om.ArtifactContent()
    context_snippet.text = "".join(snippet_lines)
    context_region.snippet = context_snippet

    physicalLocation.contextRegion = context_region

def parse_code(code):
    code_lines = code.split('\n')

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

        snippet_line = number_and_snippet_line[1] + '\n'
        snippet_lines.append(snippet_line)

    if not last_real_line_ends_in_newline:
        last_line = snippet_lines[len(snippet_lines) - 1]
        snippet_lines[len(snippet_lines) - 1] = last_line[:len(last_line) - 1]

    return first_line_number, snippet_lines

def create_or_find_rule(issue_dict, rules):
    ruleId = issue_dict["test_id"]
    if ruleId in rules:
        return rules[ruleId]

    rule = om.ReportingDescriptor()
    rule.index = len(rules)
    rule.id = ruleId
    rule.name = issue_dict["test_name"]
    rule.helpUri = docs_utils.get_url(ruleId)
    rules[ruleId] = rule
    return rule

def to_uri(file_path):
    pure_path = pathlib.PurePath(file_path)
    if pure_path.is_absolute():
        return pure_path.as_uri()
    else:
        posix_path = pure_path.as_posix()  # Replace backslashes with slashes.
        return urlparse.quote(posix_path)  # %-encode special characters.

def del_none(obj):
    """
    Delete properties with the value ``None`` in an object, recursively, and
    return the modified object.

    Based on:
    https://stackoverflow.com/questions/4255400/exclude-empty-null-values-from-json-serialization
    https://stackoverflow.com/questions/1251692/how-to-enumerate-an-objects-properties-in-python
    """

    # Batch up the properties to remove, and remove them at the end, because we
    # can't alter the object's __dict__ while we're iterating over it.
    propertiesToRemove = []
    for property, value in vars(obj).items():
        if value is None:
            propertiesToRemove.append(property)
        elif hasattr(value, "__dict__"):
            del_none(value)
        elif isinstance(value, (list, tuple)):
            for item in value:
                del_none(item)

    for propertyToRemove in propertiesToRemove:
        del obj.__dict__[propertyToRemove]

    return obj

def toJSON(obj):
    return json.dumps(obj, indent=2, default=lambda x: getattr(x, '__dict__', str(x)))
