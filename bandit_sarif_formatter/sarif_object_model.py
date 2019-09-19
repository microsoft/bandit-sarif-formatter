# This file contains only those classes and properties of the SARIF object model
# that are needed by the Bandit SARIF formatter.

LEVEL_ERROR = "error"
LEVEL_WARNING = "warning"
LEVEL_NOTE = "note" # TODO: Is this right? Bandit has a "LOW" severity, but SARIF really doesn't. "note" in SARIF means "purely informational".

class SarifLog(object):
    def __init__(self):
        self.version = "2.1.0"
        self.__setattr__("$schema", "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.4.json")
        self.runs = []

class Run(object):
    def __init__(self):
        self.tool = None
        self.invocations = []
        self.results = []
        self.properties = None

class Tool(object):
    def __init__(self):
        self.driver = None

class ToolComponent(object):
    def __init__(self):
        self.name = None
        self.rules = None

class Invocation(object):
    def __init__(self):
        self.startTimeUtc = None
        self.endTimeUtc = None
        self.toolConfigurationNotifications = None
        self.executionSuccessful = None

class Notification(object):
    def __init__(self):
        self.level = None
        self.message = None
        self.locations = None

class Message(object):
    def __init__(self):
        self.text = None

class Location(object):
    def __init__(self):
        self.physicalLocation = None

class PhysicalLocation(object):
    def __init__(self):
        self.artifactLocation = None
        self.region = None
        self.contextRegion = None

class ArtifactLocation(object):
    def __init__(self):
        self.uri = None

class Region(object):
    def __init__(self):
        self.startLine = None
        self.endLine = None
        self.snippet = None

class ArtifactContent(object):
    def __init__(self):
        self.text = None

class Result(object):
    def __init__(self):
        self.ruleId = None
        self.ruleIndex = None
        self.level = None
        self.message = None
        self.locations = None
        self.properties = None

class ReportingDescriptor(object):
    def __init__(self):
        self.id = None
        self.index = None
        self.name = None
        self.helpUri = None
