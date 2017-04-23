#!/usr/bin/env python
"""Reference implementation of ThreatSpec in Python.

ThreatSpec is a tool for continuous threat modelling through code. This is
the Python reference implementation that can be used to parse Python source files
using the main script, but also source files from any language using the universal.py
script.

The output of this tool is an intermediate representation JSON file that can be parsed
by reporting or visualisation tools. These can be combined with other intermediate
representation JSON files, even from different languages, to create a Threat Model for
larger projects.

See https://threatspec.org for details.

Copyright (c) 2017 the ThreatSpec contributors

This software may be modified and distributed under the terms
of the MIT license.  See the LICENSE file for details.
"""

import time
import ast
import os
import re


def current_milli_time():
    """Calculate the current time in milliseconds"""
    return int(round(time.time() * 1000))


def is_identifier(text):
    """Check whether a string is an identifier.

    Args:
        text: A string to check

    Returns:
        Boolean of whether the string was an id.
    """
    return text.startswith("@")


def text_to_identifier(text):
    """Turn a text string into an identifier.

    Turn the provided string into an identifier, unless it already is one.

    Args:
        text: A string

    Returns:
        A string representing the identifier.  For example:
        "this is an example" would be turned into @this_is_an_example,
        but @another_example would just return as @another_example.
    """
    if text == "":
        return ""
    elif text.startswith("@"):
        return text
    else:
        return "@" + re.sub('-', '', "_".join(text.strip().split(" ")).lower())


def remove_excessive_space(text):
    """Remove exessive spacing.

    Remove all excessive spacing from the beginning, end and within a text string.

    Args:
        text: A string with excessive spaces.

    Returns:
        A string with fewer spaces.
    """
    return re.sub('\s+', ' ', text).strip()


class PTSSourceMeta(object):
    """A container for source code metadata.

    As ThreatSpec tags are found, the source file metadata is captured to provide
    context for those tags. This can be used to determine relationships between
    components when used with a callgraph, or it can be used to report on exactly
    where migitations, exposures etc. have been found in the code.

    Attributes:
        fname: A string containing the current source file's file name.
        lineno: An integer with the current line number.
        function: A string that represents the current class, function or module.
    """

    def __init__(self, fname="", lineno=0, function=""):
        """Initiate the PTSSourceMeta class."""
        self.fname = fname
        self.lineno = lineno
        self.function = function

    def export_to_json(self):
        """Return a JSON representation of this class."""
        rep = {
            "file": self.fname,
            "line": self.lineno,
            "function": self.function
        }
        return rep

    def __str__(self):
        """Return the string representation of this class."""
        return self.fname + "@" + str(self.lineno)


class PTSProperty(object):
    """An abstract parent class

    Used by anything that needs to store a name and description.

    Attributes:
        name: A string containing the property name.
        desc: An optional description of the property instance.
    """

    def __init__(self, name, desc=""):
        """Initiate the PTSProperty class."""
        self.name = name
        self.desc = desc

    def inner_rep(self):
        """Return the inner representation of this object."""
        rep = {"name": self.name}
        if len(self.desc) > 0:
            rep["description"] = self.desc
        return rep

    def export_to_json(self):
        """Return a JSON representation of this class."""
        return self.inner_rep()


class PTSBoundary(PTSProperty):
    """A ThreatSpec boundary.

    This is a property class that holds a trust boundary. In the intermediate
    JSON output files these are grouped together and can be shared between source
    files or even projects. For example:

        "boundaries": {
            "@auth": {
                "name": "Authentication / EC2"
            },
            "@external": {
                "name": "External"
            },

    Attributes are inherited from PTSProperty.
    """
    def __init__(self, name, desc=""):
        """Initiate the PTSBoundary class."""
        PTSProperty.__init__(self, name, desc)


class PTSComponent(PTSProperty):
    """A ThreatSpec component.

    This is a property class that holds a component which exists within
    a trust boundary (PTSBoundary). In the intermediate JSON output files
    these are grouped together and can be shared between source files or
    even projects. For example:

        "components": {
            "@auth": {
                "@session": {
                    "name": "Session API"
                }
            },
            "@external": {
                "@user": {
                    "name": "User"
                }
            },

    Attributes are inherited from PTSProperty.
    """
    def __init__(self, name, desc=""):
        """Initiate the PTSComponent class."""
        PTSProperty.__init__(self, name, desc)


class PTSThreat(PTSProperty):
    """A ThreatSpec threat.

    This is a property class that holds a threat. In the intermediate JSON
    output files these are grouped together and can be shared between source
    files or even projects. For example:

        "threats": {
            "@manipulation_of_data_in_transit": {
                "name": "manipulation of data in transit"
            },
            "@malicious_requests": {
                "name": "malicious requests"
            },

    Attributes are inherited from PTSProperty.
    """
    def __init__(self, name, desc=""):
        """Initiate teh PTSThreat class."""
        PTSProperty.__init__(self, name, desc)


# TODO - consider renaming Element to something more meaningful
class PTSElement(object):
    """A ThreatSpec element.

    An element in this case is anything that is tied to a threat and
    boundary / component combination. In the intermediate JSON files
    these for the exposures, mitigations etc. For example:

        "mitigations": {
            "@use_of_tls": [
                {
                    "refs": [],
                    "component": "@loadbalancers",
                    "source": {
                        "function": "universal",
                        "line": 32,
                        "file": "../report_dfd/example.py"
                    },
                    "mitigation": "use of TLS",
                    "threat": "@information_disclosure_in_transit",
                    "boundary": "@web"
                },

    Attributes:
        boundary: A boundary identifier string.
        component: A component identifier string.
        threat: A threat identifier string.
        refs: An optional array of references strings.
    """
    def __init__(self, boundary, component, threat, refs=[]):
        """Initialise the PTSElement class."""
        self.boundary = boundary
        self.component = component
        self.threat = threat
        self.refs = refs
        self.meta = None

    def export_to_json(self):
        """Return a JSON representation of this class."""
        if not self.meta:
            raise ValueError("metadata has not been set")
        source_meta = self.meta.export_to_json()
        rep = {
            "boundary": self.boundary,
            "component": self.component,
            "threat": self.threat,
            "refs": self.refs,
            "source": source_meta
        }
        return rep


class PTSReview(object):
    """Represents a @review tag.

    Review tags are slightly different to @mitigates and @exposes tags etc. because
    it isn't related to a threat, but is otherwise very similar.

    Attributes:
        boundary: A boundary identifier string.
        component: A component identifier string.
        review: A string containing the review statement.
        refs: An optional array of references strings.
    """

    def __init__(self, boundary, component, review, refs=[]):
        """Initialise the PTSReview class."""
        self.boundary = boundary
        self.component = component
        self.review = review
        self.refs = refs
        self.meta = None

    def export_to_json(self):
        """Return a JSON representation of this class."""
        if not self.meta:
            raise ValueError("metadata has not been set")
        source_meta = self.meta.export_to_json()
        rep = {
            "boundary": self.boundary,
            "component": self.component,
            "review": self.review,
            "refs": self.refs,
            "source": source_meta
        }
        return rep


class PTSTransfer(PTSElement):
    """Represents a @transfer tag.

    Attributes:
        boundary: Same as PTSElement.
        component: Same as PTSElement.
        threat: Same as PTSElement.
        transfer: A string representing the transfer of the threat.
        refs: Same as PTSElement.
    """

    def __init__(self, boundary, component, threat, transfer, refs=[]):
        """Initialise the PTSTransfer class."""
        PTSElement.__init__(self, boundary, component, threat, refs)
        self.transfer = transfer

    def export_to_json(self):
        """Return a JSON representation of this class."""
        rep = PTSElement.export_to_json(self)
        rep["transfer"] = self.transfer
        return rep


class PTSAcceptance(PTSElement):
    """Represents an @accepts tag.

    Attributes:
        boundary: Same as PTSElement.
        component: Same as PTSElement.
        threat: Same as PTSElement.
        acceptance: A string representing the acceptance of the threat.
        refs: Same as PTSElement.
    """

    def __init__(self, boundary, component, threat, acceptance, refs=[]):
        """Initialise the PTSAcceptance class."""
        PTSElement.__init__(self, boundary, component, threat, refs)
        self.acceptance = acceptance

    def export_to_json(self):
        """Return a JSON representation of this class."""
        rep = PTSElement.export_to_json(self)
        rep["acceptance"] = self.acceptance
        return rep


class PTSMitigation(PTSElement):
    """Represents a @mitigates tag.
    
    Attributes:
        boundary: Same as PTSElement.
        component: Same as PTSElement.
        threat: Same as PTSElement.
        mitigation: A string representing the mitigation of the threat.
        refs: Same as PTSElement.
    """

    def __init__(self, boundary, component, threat, mitigation, refs=[]):
        """Initialise the PTSMitigation class."""
        PTSElement.__init__(self, boundary, component, threat, refs)
        self.mitigation = mitigation

    def export_to_json(self):
        """Return a JSON representation of this class."""
        rep = PTSElement.export_to_json(self)
        rep["mitigation"] = self.mitigation
        return rep


class PTSExposure(PTSElement):
    """Represents a @exposes tag.
    
    Attributes:
        boundary: Same as PTSElement.
        component: Same as PTSElement.
        threat: Same as PTSElement.
        exposure: A string representing the exposure of the threat.
        refs: Same as PTSElement.
    """

    def __init__(self, boundary, component, threat, exposure, refs=[]):
        """Initialises the PTSExposure class."""
        PTSElement.__init__(self, boundary, component, threat, refs)
        self.exposure = exposure

    def export_to_json(self):
        """Return a JSON representation of this class."""
        rep = PTSElement.export_to_json(self)
        rep["exposure"] = self.exposure
        return rep


class PTSDfd(object):
    """Contains the Data Flow Diagram (DFD) tree structure.

    Data flow diagrams are a core part of threat modelling and ThreatSpec allows
    the creation of DFDs through code using @connects tags (and in future using
    language callgraphs). We basically store the connections (edges) between
    components plus a little bit of metadata.

    The structure is a series of nested dicts with the following hierarchy:

        source boundary -> source component -> destination boundary -> destination component -> details
    """

    def __init__(self):
        """Initialise the PTSDfd class."""
        self.tree = {}

    def export_to_json(self):
        """Return a JSON representation of this class."""
        rep = {}
        for source_boundary_id, source_obj in self.tree.iteritems():
            if source_boundary_id not in rep:
                rep[source_boundary_id] = {}
            for source_component_id, dest_obj in source_obj.iteritems():
                if source_component_id not in rep[source_boundary_id]:
                    rep[source_boundary_id][source_component_id] = {}
                for dest_boundary_id, dest_component_obj in dest_obj.iteritems():
                    if dest_boundary_id not in rep[source_boundary_id][source_component_id]:
                        rep[source_boundary_id][source_component_id][dest_boundary_id] = {}
                    for dest_component_id, edge_obj in dest_component_obj.iteritems():
                        rep[source_boundary_id][source_component_id][dest_boundary_id][dest_component_id] = {}
                        rep[source_boundary_id][source_component_id][dest_boundary_id][dest_component_id]['type'] = edge_obj['type']
                        rep[source_boundary_id][source_component_id][dest_boundary_id][dest_component_id]['function'] = edge_obj['meta'].function
                        rep[source_boundary_id][source_component_id][dest_boundary_id][dest_component_id]['fname'] = edge_obj['meta'].fname
                        rep[source_boundary_id][source_component_id][dest_boundary_id][dest_component_id]['lineno'] = edge_obj['meta'].lineno

        return rep

    def add_edge(self, edge):
        """Add an DFD edge to the tree."""

        if not edge.meta:
            raise ValueError("metadata has not been set")
        elif not isinstance(edge.meta, PTSSourceMeta):
            raise ValueError("metadata is of incorrect type")

        # TODO - consider a better representation of the data, e.g. something recursive
        if edge.source_boundary_id not in self.tree:
            self.tree[edge.source_boundary_id] = {}
        if edge.source_component_id not in self.tree[edge.source_boundary_id]:
            self.tree[edge.source_boundary_id][edge.source_component_id] = {}
        if edge.dest_boundary_id not in self.tree[edge.source_boundary_id][edge.source_component_id]:
            self.tree[edge.source_boundary_id][edge.source_component_id][edge.dest_boundary_id] = {}
        if edge.dest_component_id not in self.tree[edge.source_boundary_id][edge.source_component_id][edge.dest_boundary_id]:
            self.tree[edge.source_boundary_id][edge.source_component_id][edge.dest_boundary_id][edge.dest_component_id] = {
                'type': edge.connection_type,
                'meta': edge.meta
            }


class PTSDfdEdge(object):
    """Represents a DFD edge.

    An edge is a connection between two components, which are themselves contained within a trust boundary. The
    edges can be between components within a trust boudnary, or between boundaries. An edge can also be
    unidirectional or bidirectional.

    Attributes:
        source_boundary_id: Source boundary identifier string.
        source_component_id: Source component identifier string.
        dest_boundary_id: Destination boundary identifier string.
        dest_component_id: Destination component identifier string.
        connection_type: A string that represent the direction of the connection. Either PTSDfdEdge.UNI_DIRECTIONAL or PTSDfdEdge.BI_DIRECTIONAL.
        meta: A PTSSourceMeta object.
    """

    UNI_DIRECTIONAL = "uni"
    BI_DIRECTIONAL = "bi"

    def __init__(self, source_boundary_id, source_component_id, dest_boundary_id, dest_component_id, connection_type, meta):
        """Initialise the PTSDfdEdge class"""
        self.source_boundary_id = text_to_identifier(source_boundary_id)
        self.source_component_id = text_to_identifier(source_component_id)
        self.dest_boundary_id = text_to_identifier(dest_boundary_id)
        self.dest_component_id = text_to_identifier(dest_component_id)

        self.connection_type = connection_type
        self.meta = meta 


class PTSReference(object):
    """Represents a reference.

    References are used as pointers to documentation, bug tracking issues etc.

    Attributes:
        ref: A string representing a reference
    """
    def __init__(self, ref):
        """Initialise the PTSReference class"""
        self.ref = ref


class PyThreatspecReporter(object):
    """Represents the intermediate representation structure.

    This class abstracts the ultimate output of the parser, including all the metadata
    and ThreatSpec tags and elements.

    The exported JSON object should be valid as defined in the jsonschemea specification.

    The output JSON file can contain multiple projects and reports can be based on
    multiple intermediate output files for multiple projects, bringing multiple
    threat reports into a single large-scale threat report.

    Attributes:
        parser: A PyThreatspecParser object
        project: Project name string
    """

    def __init__(self, parser, project):
        """Initialise the PyThreatspecReporter class.

        Args:
            parser: A PyThreatspecParser instance.
            project: A string representing the current project name.

        Returns:
            A PyThreatspecReporter object.
        """
        self.parser = parser
        self.project = project

    def export_to_json(self):
        """Return a JSON representation of this class.

        For this class, the exported JSON is callled the intermediate representation file.
        This should be valid as per the specification and allows different projects from different
        languages to be merged into a single Threat Model.
        """
        data = {
            "specification": {
                "name": "ThreatSpec",
                "version": "0.1.0"
            },
            "document": {
                "created": self.parser.creation_time,
                "updated": self.parser.updated_time
            },
            "boundaries": {},
            "components": {},
            "threats": {},
            "dfd": {},
            "projects": {}
        }

        """Boundaries, components and threats are top-level and are shared across projects."""
        for boundary_id, boundary in self.parser.boundaries.iteritems():
            if boundary_id not in data["boundaries"]:
                data["boundaries"][boundary_id] = boundary.export_to_json()

        for boundary_id, component_obj in self.parser.components.iteritems():
            if boundary_id not in data["components"]:
                data["components"][boundary_id] = {}
            for component_id, component in component_obj.iteritems():
                if component_id not in data["components"][boundary_id]:
                    data["components"][boundary_id][component_id] = component.export_to_json()

        for threat_id, threat in self.parser.threats.iteritems():
            if threat_id not in data["threats"]:
                data["threats"][threat_id] = threat.export_to_json()

        """As is the DFD."""
        data["dfd"].update(self.parser.dfd.export_to_json())

        """Project-specific mitigations, exposures etc. are managed below."""
        project_details = {
            "mitigations": {},
            "exposures": {},
            "acceptances": {},
            "transfers": {},
            "reviews": {}
        }

        for review_id, reviews in self.parser.reviews.iteritems():
            if review_id not in project_details["reviews"]:
                project_details["reviews"][review_id] = []
            for review in reviews:
                project_details["reviews"][review_id].append(review.export_to_json())

        for mitigation_id, mitigations in self.parser.mitigations.iteritems():
            if mitigation_id not in project_details["mitigations"]:
                project_details["mitigations"][mitigation_id] = []
            for mitigation in mitigations:
                project_details["mitigations"][mitigation_id].append(mitigation.export_to_json())

        for exposure_id, exposures in self.parser.exposures.iteritems():
            if exposure_id not in project_details["exposures"]:
                project_details["exposures"][exposure_id] = []
            for exposure in exposures:
                project_details["exposures"][exposure_id].append(exposure.export_to_json())

        for acceptance_id, acceptances in self.parser.acceptances.iteritems():
            if acceptance_id not in project_details["acceptances"]:
                project_details["acceptances"][acceptance_id] = []
            for acceptance in acceptances:
                project_details["acceptances"][acceptance_id].append(acceptance.export_to_json())

        for transfer_id, transfers in self.parser.transfers.iteritems():
            if transfer_id not in project_details["transfers"]:
                project_details["transfers"][transfer_id] = []
            for transfer in transfers:
                project_details["transfers"][transfer_id].append(transfer.export_to_json())

        data["projects"][self.project] = project_details

        return data


class PyThreatspecParser(object):
    """The Python ThreatSpec parser class.

    This class is used to track the ThreatSpec data as source files are parsed, and also
    implements the functions used in parsing.
    """

    def __init__(self):
        """Initiates the PyThreatspecParser class"""
        thetime = current_milli_time()
        self.creation_time = thetime
        self.updated_time = thetime

        self.projects = {}
        self.reviews = {}
        self.mitigations = {}
        self.exposures = {}
        self.acceptances = {}
        self.transfers = {}
        self.tag_regex = r'^\s*(@(?:alias|describe|connects|review|mitigates|exposes|transfers|accepts)).*$'

        self.boundaries = {}
        self.components = {}
        self.threats = {}
        self.dfd = PTSDfd()

        self.alias_table = {}
        self.alias_table["boundary"] = self.add_boundary
        self.alias_table["component"] = self.add_component
        self.alias_table["threat"] = self.add_threat

        self.pclass_table = {}
        self.pclass_table["boundary"] = self.boundaries
        self.pclass_table["component"] = self.components
        self.pclass_table["threat"] = self.threats

        self.parse_table = {}
        self.parse_table["@alias"] = self._parse_alias
        self.parse_table["@describe"] = self._parse_describe
        self.parse_table["@connects"] = self._parse_connects
        self.parse_table["@review"] = self._parse_review
        self.parse_table["@mitigates"] = self._parse_mitigates
        self.parse_table["@exposes"] = self._parse_exposes
        self.parse_table["@transfers"] = self._parse_transfers
        self.parse_table["@accepts"] = self._parse_accepts

    def add_boundary(self, boundary, boundary_id=None):
        """Add a boundary.

        A boundary represents a separation of trust and encompasses one or more components.
        In ThreatSpec, boundaries and components a linked together when either defined using
        the @alias tag, or when using a threat tag, for example:

            @alias boundary @user to User
            @mitigations User:@session against session hijack with use of tokens

        Args:
            boundary: String representing a boundary id or name.
            boundary_id: An optional string containing a boundary identifier. If this is set, then boundary must contain a name and not an identifier.

        Returns
            A boundary identifier.
        """

        if boundary_id and is_identifier(boundary):
            raise ValueError("boundary_id has been set, but boundary contains an identifier")

        if not boundary_id and is_identifier(boundary):
            return boundary

        if not boundary_id:
            boundary_id = text_to_identifier(boundary)

        if boundary_id not in self.boundaries:
            self.boundaries[boundary_id] = PTSBoundary(boundary)
        return boundary_id

    def add_component(self, boundary_id, component, component_id=None):
        """Add a component.

        A component is a part of the system that does something or is in some way
        acted on. It exists inside a threat boundary and is generally connected to
        other components. It can be defined using an @alias tag, or when using a threat
        tag, for example:

            @alias component @user:@session to Web session
            @exposes @user:Session to information disclosure with lack of TLS

        Args:
            boundary_id: A boundary id string.
            component: A component id or name string.
            component_id: An optional string containing a component identifier. If this is set, then component must contain a name and not an identifier.

        Returns:
            A component identifier.
        """

        if component_id and is_identifier(component):
            raise ValueError("component_id has been set, but component contains an identifier")

        if not component_id and is_identifier(component):
            return component

        if not component_id:
            component_id = text_to_identifier(component)

        if boundary_id not in self.components:
            self.components[boundary_id] = {}
        if component_id not in self.components[boundary_id]:
            self.components[boundary_id][component_id] = PTSComponent(component)
        return component_id

    def add_threat(self, threat, threat_id=None):
        """Add a threat.

        A threat represents an potential attack against the system and can be defined
        using an @alias tag, or when using one of the threat tags. You can use the alias
        tag to group together threats into an attack library that can be shared between
        projects. For example:

            @alias threat @cwe_123_information_disclosure to CWE123 Information Disclosure
            @transfer @cwe_123_information_disclosure to @external:@user with acceptance of terms

        Args:
            threat: A threat id or name string.
            threat_id: An optional string containing a threat identifier. If this is set, then threat must contain a name and not an identifier.

        Returns:
            A threat identifier.
        """

        if threat_id and is_identifier(threat):
            raise ValueError("threat_id has been set, but threat contains an identifier")

        if not threat_id and is_identifier(threat):
            return threat

        if not threat_id:
            threat_id = text_to_identifier(threat)

        if threat_id not in self.threats:
            self.threats[threat_id] = PTSThreat(threat)
        return threat_id

    def _parse_alias(self, alias, meta):
        """Parse an alias string.

        Parse an @alias tag string using the defined regular expression and add the elements
        to the internal data structure. A boundary and threat string can simply provide the
        identifier and name string, for example:

            @alias boundary @external to External System
            @alias threat @cwe_123_information_disclosure to CWE123 Information Disclosure

        But a component alias must provide the boundary identifier as well as the component
        identifier, for example:

            @alias component @external:@user to User

        Args:
            alias: Alias string to parse.
            meta: PTSSourceMeta instance for the @alias line.

        Returns:
            Nothing.
        """
        # TODO add support for references in aliases. Useful for CWEs etc
        # TODO check multilines works
        match = re.findall(r'@alias (boundary|component|threat) @(\w+)\b(?::@(\w+)\b)? to (.*)', alias, re.M | re.I)
        if match:
            pclass = remove_excessive_space(match[0][0])
            if pclass == "component":
                boundary_id = text_to_identifier(remove_excessive_space(match[0][1]))
                alias_id = text_to_identifier(remove_excessive_space(match[0][2]))
                text = remove_excessive_space(match[0][3])
                self.alias_table[pclass](boundary_id, text, alias_id)
            else:
                alias_id = text_to_identifier(remove_excessive_space(match[0][1]))
                text = remove_excessive_space(match[0][3])
                self.alias_table[pclass](text, alias_id)
        else:
            raise ValueError("@alias line contains an invalid pattern {}".format(meta))


    def _parse_describe(self, describe, meta):
        """Parse a describe string.

        Parse a @describe tag string using the defined regular expression and add the elements
        to the internal data structure. A boundary and threat string can simply provide the
        identifier and name string, for example:

            @describe boundary @external as any external system.
            @describe threat @cwe_123_information_disclosure as any disclosure of private \
            or secret data.

        But a component alias must provide the boundary identifier as well as the component
        identifier, for example:

            @describe component @external:@user as the user account

        Args:
            describe: Describe string to parse.
            meta: PTSSourceMeta instance for the @describe line.

        Returns:
            Nothing.
        """

        match = re.findall(r'@describe (boundary|component|threat) @(\w+)\b(?::@(\w+)\b)? as (.*)', describe, re.M | re.I)
        if match:
            pclass = remove_excessive_space(match[0][0].lower())
            if pclass == "component":
                boundary_id = text_to_identifier(remove_excessive_space(match[0][1]))
                describe_id = text_to_identifier(remove_excessive_space(match[0][2]))
                text = remove_excessive_space(match[0][3])

                # TODO consider refactoring into a seperate add_description method
                if not boundary_id in self.pclass_table[pclass]:
                    raise ValueError("unknown boundary identifier {} in {}".format(boundary_id, meta))

                if not describe_id in self.pclass_table[pclass][boundary_id]:
                    raise ValueError("unknown {} identifier {} in {}".format(pclass, describe_id, meta))

                self.pclass_table[pclass][boundary_id][describe_id].desc = text
            else:
                boundary_id = None
                describe_id = text_to_identifier(remove_excessive_space(match[0][1]))
                text = remove_excessive_space(match[0][3])

                if not describe_id in self.pclass_table[pclass]:
                    raise ValueError("unknown {} identifier {} in {}".format(pclass, describe_id, meta))

                self.pclass_table[pclass][describe_id].desc = text
        else:
            raise ValueError("@describe line contains an invalid pattern: {}".format(meta))

    def _parse_connects(self, connects, meta):
        """Parse a connects string.

        Parse a @connects tag string using the defined regular expression and add the elements
        to the internal data structure.

        @connects can be used to connect components in the threat model in order to manually
        build a Data Flow Diagram (DFD).

        For example:

            @connects @external:@user to @web:@server

        Args:
            connects: Connects string to parse.
            meta: PTSSourceMeta instance for the @connects line.

        Returns:
            Nothing.
        """

        match = re.findall(r'@connects @(\w+):@(\w+) (to|with) @(\w+):@(\w+)', connects, re.M | re.I)
        if match:
            source_boundary_id = text_to_identifier(remove_excessive_space(match[0][0]))
            source_component_id = text_to_identifier(remove_excessive_space(match[0][1]))

            if remove_excessive_space(match[0][2]) == "to":
                connection_type = PTSDfdEdge.UNI_DIRECTIONAL
            else:
                connection_type = PTSDfdEdge.BI_DIRECTIONAL

            dest_boundary_id = text_to_identifier(remove_excessive_space(match[0][3]))
            dest_component_id = text_to_identifier(remove_excessive_space(match[0][4]))

            self.dfd.add_edge(PTSDfdEdge(source_boundary_id, source_component_id, dest_boundary_id, dest_component_id, connection_type, meta))
        else:
            raise ValueError("@connects line contains an invalid pattern: {}".format(meta))

    def _parse_review(self, review, meta):
        """Parse a review string.

        Parse a @review tag string using the defined regular expression and add the elements
        to the internal data structure.

        @review can be used to make a note for further review, for example when the source code isn't well understoood,
        or when the impact needs further consideration. It can also be used as part of a review of existing code as
        part of the threat modelling process.

        For example:

            @review @auth:@encryption Not sure what happens here, but it looks dangerous
            @review User:Session Need to check how we're storing session data

        Args:
            review: Review string to parse.
            meta: Not used, but follows same signature as other functions called by lookup
                 table.

        Returns:
            Nothing.
        """

        match = re.findall(r'@review (@?\w+):(@?\w+) (.*)', review, re.M | re.I)
        if match:
            boundary = remove_excessive_space(match[0][0])
            component = remove_excessive_space(match[0][1])
            text = remove_excessive_space(match[0][2])

            boundary_id = self.add_boundary(boundary)
            component_id = self.add_component(boundary_id, component)
            review_id = text_to_identifier(text)

            if review_id not in self.reviews:
                self.reviews[review_id] = []

            review = PTSReview(boundary_id, component_id, text, [])
            review.meta = meta
            self.reviews[review_id].append(review)
        else:
            raise ValueError("@review line contains an invalid pattern: {}".format(meta))

    def _parse_mitigates(self, mitigates, meta):
        """Parse a mitigates string.

        Parse a @mitigates tag string using the defined regular expression and add the elements
        to the internal data structure.

        @mitigates is used to record the fact that the related code mitigates the referened threat.

        For example:

            @mitigates @crypto:@hash against @cwe_123_insufficient_entropy with use of cryptographically random salt

        Args:
            mitigates: Mitigation string to parse.
            meta: PTSSourceMeta instance for the @mitigates line.

        Returns:
            Nothing.
        """
        match = re.findall(r'@mitigates (@?\w+):(@?\w+) against (.*?) with (.*)', mitigates, re.M | re.I)
        if match:
            boundary = remove_excessive_space(match[0][0])
            component = remove_excessive_space(match[0][1])
            threat = remove_excessive_space(match[0][2])
            mitigation_text = remove_excessive_space(match[0][3])

            boundary_id = self.add_boundary(boundary)
            component_id = self.add_component(boundary_id, component)
            threat_id = self.add_threat(threat)

            mitigation_id = text_to_identifier(mitigation_text)

            if mitigation_id not in self.mitigations:
                self.mitigations[mitigation_id] = []

            mitigation = PTSMitigation(boundary_id, component_id, threat_id, mitigation_text, [])
            mitigation.meta = meta 
            self.mitigations[mitigation_id].append(mitigation)
        else:
            raise ValueError("@mitigates line contains an invalid pattern: {}".format(meta))

    def _parse_exposes(self, exposes, meta):
        """Parse an exposes string.

        Parse a @exposes tag string using the defined regular expression and add the elements
        to the internal data structure.

        @exposes is used to record the fact that the related code exposes the referened threat.

        For example:

            @exposes @crypto:@hash to @cwe_123_insufficient_entropy with no salt used

        Args:
            exposes: Exposes string to parse.
            meta: PTSSourceMeta instance for the @exposes line.

        Returns:
            Nothing.
        """
        match = re.findall(r'@exposes (@?\w+):(@?\w+) to (.*?) with (.*)', exposes, re.M | re.I)
        if match:
            boundary = remove_excessive_space(match[0][0])
            component = remove_excessive_space(match[0][1])
            threat = remove_excessive_space(match[0][2])
            exposes_text = remove_excessive_space(match[0][3])

            boundary_id = self.add_boundary(boundary)
            component_id = self.add_component(boundary_id, component)
            threat_id = self.add_threat(threat)
            exposure_id = text_to_identifier(exposes_text)

            if exposure_id not in self.exposures:
                self.exposures[exposure_id] = []

            exposure = PTSExposure(boundary_id, component_id, threat_id, exposes_text, [])
            exposure.meta = meta 
            self.exposures[exposure_id].append(exposure)
        else:
            raise ValueError("@exposes line contains an invalid pattern: {}".format(meta))

    def _parse_transfers(self, transfers, meta):
        """Parse a transfers string.

        Parse a @transfers tag string using the defined regular expression and add the elements
        to the internal data structure.

        @transfers is used to record the fact that the related code transfers the referened threat to another component.

        For example:

            @transfers @cwe_319_cleartext_transmission to User:Browser with non-sensitive information

        Args:
            transfers: Transfers string to parse.
            meta: PTSSourceMeta instance for the @transfers line.

        Returns:
            Nothing.
        """
        match = re.findall(r'@transfers (.*) to (@?\w+):(@?\w+) with (.*)', transfers, re.M | re.I)
        if match:
            threat = remove_excessive_space(match[0][0])
            boundary = remove_excessive_space(match[0][1])
            component = remove_excessive_space(match[0][2])
            transfer_text = remove_excessive_space(match[0][3])

            boundary_id = self.add_boundary(boundary)
            component_id = self.add_component(boundary_id, component)
            threat_id = self.add_threat(threat)
            transfer_id = text_to_identifier(transfer_text)

            if transfer_id not in self.transfers:
                self.transfers[transfer_id] = []

            transfer = PTSTransfer(boundary_id, component_id, threat_id, transfer_text, [])
            transfer.meta = meta
            self.transfers[transfer_id].append(transfer)
        else:
            raise ValueError("@exposes line contains an invalid pattern: {}".format(meta))

    def _parse_accepts(self, accepts, meta):
        """Parse an accepts string.

        Parse a @accepts tag string using the defined regular expression and add the elements
        to the internal data structure.

        @accepts is used to record the fact that the related code accepts the referened threat as unmitigated.

        For example:

            @accepts arbitrary file writes to WebApp:FileSystem with limited filename restrictions

        Args:
            accepts: Accepts string to parse.
            meta: PTSSourceMeta instance for the @accepts line.

        Returns:
            Nothing.
        """
        match = re.findall(r'@accepts (.*) to (@?\w+):(@?\w+) with (.*)', accepts, re.M | re.I)
        if match:
            threat = remove_excessive_space(match[0][0])
            boundary = remove_excessive_space(match[0][1])
            component = remove_excessive_space(match[0][2])
            acceptance_text = remove_excessive_space(match[0][3])

            boundary_id = self.add_boundary(boundary)
            component_id = self.add_component(boundary_id, component)
            threat_id = self.add_threat(threat)
            accept_id = text_to_identifier(acceptance_text)

            if accept_id not in self.acceptances:
                self.acceptances[accept_id] = []

            accept = PTSAcceptance(boundary_id, component_id, threat_id, acceptance_text, [])
            accept.meta = meta
            self.acceptances[accept_id].append(accept)
        else:
            raise ValueError("@accepts line contains an invalid pattern: {}".format(meta))

    def _parse_comment(self, comment, meta):
        """Parse a comment line.

        This method is used to parse all comment lines, and if a ThreatSpec tag is found the relevant
        parser for that tag is called.

        Args:
            comment: Comment line string.
            meta: PTSSourceMeta instance for the comment line.

        Returns:
            Nothing.
        """

        if not comment:
            return

        for tag in re.findall(self.tag_regex, comment, re.M | re.I):  # multiline and ignore case
            self.parse_table[tag](comment, meta)

    def _parse_globals(self, module, filename):
        """Parse the global module.

        This method parses the global module in the AST in order to find the docstring.

        Args:
            module: The current Python module being parsed.
            filename: String containing the filename as given on the command line.

        Returns:
            Nothing.
        """
        self._parse_comment(ast.get_docstring(module), PTSSourceMeta(filename, 0, "module"))

    def _parse_classes(self, module, filename):
        """Parse classes.

        This method parses classes found in the AST in order to find the docstring.

        Args:
            module: The current Python module being parsed.
            filename: String containing the filename as given on the command line.

        Returns:
            Nothing.
        """

        class_definitions = [node for node in module.body if isinstance(node, ast.ClassDef)]
        for class_def in class_definitions:
            self._parse_comment(ast.get_docstring(class_def), PTSSourceMeta(filename, class_def.lineno, class_def.name))
            self._parse_methods(class_def, filename)

    def _parse_methods(self, classmodule, filename):
        """Parse the class methods.

        This method parses the methods for the given class object in order to find the docstring.

        Args:
            classmodule: The current Python class being parsed.
            filename: String containing the filename as given on the command line.

        Returns:
            Nothing.
        """
        for node in ast.iter_child_nodes(classmodule):
            if isinstance(node, ast.FunctionDef):
                self._parse_comment(ast.get_docstring(node), PTSSourceMeta(filename, node.lineno, node.name))

    def _parse_functions(self, module, filename):
        """Parse the global functions.

        This method parses global functions within the module in order to find the docstring.

        Args:
            module: The current Python module being parsed.
            filename: String containing the filename as given on the command line.

        Returns:
            Nothing.
        """

        function_definitions = [node for node in module.body if isinstance(node, ast.FunctionDef)]
        for func in function_definitions:
            self._parse_comment(ast.get_docstring(func), PTSSourceMeta(filename, func.lineno, func.name))

    def parse(self, filename):
        """Parse the source file.

        Parses the Python source file using the AST.

        Args:
            filename: String containing the filename as given on the command line.
        """
        ast_filename = os.path.splitext(filename)[0] + '.py'
        with open(ast_filename, 'r') as fd:
            file_contents = fd.read()
        module = ast.parse(file_contents)

        self._parse_globals(module, filename)
        self._parse_classes(module, filename)
        self._parse_functions(module, filename)

    def export(self):
        """Exports the internal data structures."""
        return self.boundaries, self.components, self.threats, self.mitigations, self.exposures, self.transfers, self.acceptances
