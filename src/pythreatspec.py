import sys
import json
from tokenize import *
import time
import io
import parser
import token
import ast
import os
import re

def current_milli_time():
    return int(round(time.time() * 1000))

def text_to_identifier(text):
    if text == "":
        return ""
    elif text[0:1] == "@":
        return text
    else:
        return "@" + re.sub('-', '', "_".join(text.strip().split(" ")).lower())

def remove_excessive_space(text):
    return re.sub('\s+',' ', text)

class PTSSourceTag(object):
    def __init__(self, fname, lineno, function):
        self.fname = fname
        self.lineno = lineno
        self.function = function

    def export_to_json(self, key):
        rep = {key : {
            "file" : self.fname,
            "line" : self.lineno,
            "function" : self.function
        }}
        return rep

    def __str__(self):
        return self.fname + "@" + str(self.lineno)

class PTSProperty(object):
    def __init__(self, name, desc):
        self.name = name
        self.desc = desc

    def inner_rep(self):
        rep = {"name": self.name}
        if len(self.desc) > 0:
            rep["description"] = self.desc
        return rep

    def export_to_json(self, key):
        rep = {key : self.inner_rep()}
        return rep

class PTSBoundary(PTSProperty):
    def __init__(self, name, desc = ""):
        PTSProperty.__init__(self, name, desc)

class PTSComponent(PTSProperty):
    def __init__(self, name, desc = ""):
        PTSProperty.__init__(self, name, desc)

class PTSThreat(PTSProperty):
    def __init__(self, name, desc = ""):
        PTSProperty.__init__(self, name, desc)

class PTSElement(object):
    def __init__(self, boundary, component, threat, refs):
        self.boundary = boundary
        self.component = component
        self.threat = threat
        self.refs = refs
        self.tag = None

    def export_to_json(self, key):
        source_tag = self.tag.export_to_json("source")
        rep = {key: {
                "boundary": self.boundary.name,
                "component": self.component.name,
                "threat": self.threat.name,
                "refs" : self.refs,
                "source" : source_tag
            }
        }
        return rep

class PTSTransfer(PTSElement):
    def __init__(self, boundary, component, threat, transfer, refs = []):
        PTSElement.__init__(self, boundary, component, threat, refs)
        self.transfer = transfer

    def export_to_json(self, key):
        rep = PTSElement.export_to_json(self, key)
        rep[key]["transfer"] = self.transfer
        return rep

class PTSAcceptance(PTSElement):
    def __init__(self, boundary, component, threat, acceptance, refs = []):
        PTSElement.__init__(self, boundary, component, threat, refs)
        self.acceptance = acceptance

    def export_to_json(self, key):
        rep = PTSElement.export_to_json(self, key)
        rep[key]["acceptance"] = self.acceptance
        return rep

class PTSMitigation(PTSElement):
    def __init__(self, boundary, component, threat, mitigation, refs = []):
        PTSElement.__init__(self, boundary, component, threat, refs)
        self.mitigation = mitigation

    def export_to_json(self, key):
        rep = PTSElement.export_to_json(self, key)
        rep[key]["mitigation"] = self.mitigation
        return rep

class PTSExposure(PTSElement):
    def __init__(self, boundary, component, threat, exposure, refs = []):
        PTSElement.__init__(self, boundary, component, threat, refs)
        self.exposure = exposure

    def export_to_json(self, key):
        print self.tag
        rep = PTSElement.export_to_json(self, key)
        rep[key]["exposure"] = self.exposure
        return rep

class PTSReference(object):
    def __init__(self, ref):
        self.ref = ref

class PyThreatspecReporter(object):
    def __init__(self, parser):
        pass # add functions for ToJson and the like

class PyThreatspecParser(object):
    def __init__(self):
        thetime = current_milli_time()
        self.creation_time = thetime
        self.updated_time = thetime

        self.projects = {}
        self.mitigations = {}
        self.exposures = {}
        self.acceptances = {}
        self.transfers = {}

        self.node_regex = r'^@(?:alias|describe|mitigates|exposes|transfers|accepts).*$'

        self.boundaries = {}
        self.components = {}
        self.threats = {}

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
        self.parse_table["@mitigates"] = self._parse_mitigates
        self.parse_table["@exposes"] = self._parse_exposes
        self.parse_table["@transfers"] = self._parse_transfers
        self.parse_table["@accepts"] = self._parse_accepts

    def add_boundary(self, text, tid = ""):
        if tid not in self.boundaries:
            self.boundaries[tid] = PTSBoundary(text)
        return self.boundaries[tid]

    def add_component(self, text, tid = ""):
        if tid not in self.components:
            self.components[tid] = PTSComponent(text)
        return self.components[tid]

    def add_threat(self, text, tid = ""):
        if tid not in self.threats:
            self.threats[tid] = PTSThreat(text)
        return self.threats[tid]

    def _parse_alias(self, alias, tag):
        alias = " ".join(alias)
        match = re.findall(r'(boundary|component|threat) @(\w+)\b to (\w+)\b', alias, re.M | re.I)
        if match:
            pclass = remove_excessive_space(match[0][0])
            alias = remove_excessive_space(match[0][1])
            text = remove_excessive_space(match[0][2])

            converted_id = text_to_identifier(alias)

            if converted_id == "":
                converted_id = text_to_identifier(text)
            if text != "":
                self.alias_table[pclass](text, converted_id)

    def _parse_describe(self, describe, tag):
        print "parsing an describe"
        describe = " ".join(describe)
        match = re.findall(r'(boundary|component|threat) @(\w+)\b as (.*)', describe, re.M | re.I)
        if match:
            pclass = remove_excessive_space(match[0][0].lower())
            tid = remove_excessive_space(match[0][1])
            text = remove_excessive_space(match[0][2])

            converted_id = text_to_identifier(tid)

            if converted_id not in self.pclass_table[pclass]:
                raise Exception("Error: %s not a valid %s property" % (tid, pclass))
            self.pclass_table[pclass][converted_id].desc = text

    def _parse_mitigates(self, mitigates, tag):
        mitigates = " ".join(mitigates).strip()
        print "parsing mitigates: %s" % (mitigates)
        match = re.findall(r'(@?\w+):(@?\w+) against (.*?) with (.*)', mitigates, re.M | re.I)
        if match:
            boundary = remove_excessive_space(match[0][0])
            component = remove_excessive_space(match[0][1])
            threat = remove_excessive_space(match[0][2])
            mitigation_text = remove_excessive_space(match[0][3])

            boundary_id = self.add_boundary(boundary)
            component_id = self.add_component(component)
            threat_id = self.add_threat(threat)
            mitigation_id = text_to_identifier(mitigation_text)

            if mitigation_id not in self.mitigations:
                self.mitigations[mitigation_id] = []

            mitigation = PTSMitigation(boundary_id, component_id, threat_id, mitigation_id, [])
            mitigation.tag = tag
            self.mitigations[mitigation_id].append(mitigation)
        else:
            raise Exception("Error parsing mitigation at %s: %s" % (tag, mitigates))

    def _parse_exposes(self, exposes, tag):
        print "parsing exposes"
        exposes = " ".join(exposes)
        match = re.findall(r'(@?\w+):(@?\w+) to (.*?) with (.*)', exposes, re.M | re.I)
        if match:
            boundary = remove_excessive_space(match[0][0])
            component = remove_excessive_space(match[0][1])
            threat = remove_excessive_space(match[0][2])
            exposes_text = remove_excessive_space(match[0][3])

            boundary_id = self.add_boundary(boundary)
            component_id = self.add_component(component)
            threat_id = self.add_threat(threat)
            exposure_id = text_to_identifier(exposes_text)

            if exposure_id not in self.exposures:
                self.exposures[exposure_id] = []

            exposure = PTSExposure(boundary_id, component_id, threat_id, exposure_id, [])
            exposure.tag = tag
            self.exposures[exposure_id].append(exposure)

    def _parse_transfers(self, transfers, tag):
        print "parsing transfers"
        transfer = " ".join(transfers)
        match = re.findall(r'(.*) to (@?\w+):(@?\w+) with (.*)', transfer, re.M | re.I)
        if match:
            threat = remove_excessive_space(match[0][0])
            boundary = remove_excessive_space(match[0][1])
            component = remove_excessive_space(match[0][2])
            transfer_text = remove_excessive_space(match[0][3])

            boundary_id = self.add_boundary(boundary)
            component_id = self.add_component(component)
            threat_id = self.add_threat(threat)
            transfer_id = text_to_identifier(transfer_text)

            if transfer_id not in self.transfers:
                self.transfers[transfer_id] = []

            transfer = PTSTransfer(boundary_id, component_id, threat_id, transfer_id, [])
            transfer.tag = tag
            self.transfers[transfer_id].append(transfer)

    def _parse_accepts(self, accepts, tag):
        print "parsing accepts"
        accept = " ".join(accepts)
        match = re.findall(r'(.*) to (@?\w+):(@?\w+) with (.*)', accept, re.M | re.I)
        if match:
            threat = remove_excessive_space(match[0][0])
            boundary = remove_excessive_space(match[0][1])
            component = remove_excessive_space(match[0][2])
            acceptance_text = remove_excessive_space(match[0][3])

            boundary_id = self.add_boundary(boundary)
            component_id = self.add_component(component)
            threat_id = self.add_threat(threat)
            accept_id = text_to_identifier(acceptance_text)

            if accept_id not in self.acceptances:
                self.acceptances[accept_id] = []

            accept = PTSAcceptance(boundary_id, component_id, threat_id, accept_id, [])
            accept.tag = tag
            self.acceptances[accept_id].append(accept)

    def _parse_comment(self, comment, tag):
        for match in re.findall(self.node_regex, comment, re.M | re.I): # multiline and ignore case
            splits = match.split(" ")
            self.parse_table[splits[0]](splits[1:], tag)

    def _parse_classes(self, module, filename):
        class_definitions = [node for node in module.body if isinstance(node, ast.ClassDef)]
        for class_def in class_definitions:
            self._parse_comment(ast.get_docstring(class_def), PTSSourceTag(filename, class_def.lineno, class_def.name))

    def _parse_methods(self, classmodule, filename):
        for node in ast.iter_child_nodes(class_def):
            if isinstance(node, ast.FunctionDef):
                self._parse_comment(ast.get_docstring(node), PTSSourceTag(filename, node.lineno, node.name))

    def _parse_functions(self, module, filename):
        function_definitions = [node for node in module.body if isinstance(node, ast.FunctionDef)]
        for func in function_definitions:
            self._parse_comment(ast.get_docstring(func), PTSSourceTag(filename, func.lineno, func.name))

    def parse(self, filename):
        ast_filename = os.path.splitext(filename)[0] + '.py'
        with open(ast_filename, 'r') as fd:
            file_contents = fd.read()
        module = ast.parse(file_contents)

        self._parse_classes(module, filename)
        self._parse_functions(module, filename)

    def export(self):
        return self.boundaries, self.components, self.threats, self.mitigations, self.exposures, self.transfers, self.acceptances
        # return None # TODO: invoke the exporter
        # return self.ts

def main(argv):
    parser = PyThreatspecParser()
    parser.parse(argv[0])

    b, c, t, m, e, tr, a  = parser.export()
    print "boundaries"
    for bb in b:
        print b[bb].export_to_json(bb)
    print "threats"
    for tt in t:
        print t[tt].export_to_json(tt)
    print "mitigations"
    for mm in m:
        print map(lambda e : e.export_to_json(mm), m[mm])
    print "exposures"
    for ee in e:
        print map(lambda x : x.export_to_json(ee), e[ee])
    print "transfers"
    for tt in tr:
        print map(lambda x : x.export_to_json(tt), tr[tt])
    print "acceptances"
    for aa in a:
        print map(lambda x : x.export_to_json(aa), a[aa])

if __name__ == "__main__":
    main(sys.argv[1:])
