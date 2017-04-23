from nose.tools import *
import json
import time
import ast
from pythreatspec.pythreatspec import *

class TestModuleFunctions:
    def test_current_milli_time(self):
        before = int(round(time.time() * 1000))
        t = current_milli_time()
        after = int(round(time.time() * 1000))
        assert isinstance(t, int)
        assert t >= before and t <= after

    def test_is_identifier(self):
        assert is_identifier("@an_id")
        assert not is_identifier("not an id")

    def test_text_to_identifier(self):
        assert text_to_identifier("") == ""
        assert text_to_identifier("@abc") == "@abc"
        assert text_to_identifier("a b c") == "@a_b_c"
        assert text_to_identifier(" a b c ") == "@a_b_c"
        assert text_to_identifier("a-b-c") == "@abc"
        #assert text_to_identifier("a/b+c") == "@abc"

    def test_remove_excessive_space(self):
        assert remove_excessive_space("a  b") == "a b"
        assert remove_excessive_space("  a  b c ") == "a b c"


class TestPTSSourceMeta:
    def test_ptssource_meta(self):
        meta = PTSSourceMeta(fname="abc", lineno=10, function="xyz")
        assert meta.fname == "abc"
        assert meta.lineno == 10
        assert meta.function == "xyz"

    def test_meta_export_to_json(self):
        meta = PTSSourceMeta(fname="abc", lineno=10, function="xyz")
        export = json.dumps(meta.export_to_json(), sort_keys=True)
        assert export == '{"file": "abc", "function": "xyz", "line": 10}'

    def test_ptssource_meta_str(self):
        meta = PTSSourceMeta(fname="abc", lineno=10, function="xyz")
        assert str(meta) == "abc@10"


class TestPTSProperty:
    def test_ptsproperty_no_desc(self):
        prop = PTSProperty("abc")
        assert prop.name == "abc"
        assert prop.desc == ""

    def test_ptsproperty_with_desc(self):
        prop = PTSProperty("abc", "xyz")
        assert prop.name == "abc"
        assert prop.desc == "xyz"

    def test_inner_rep_no_desc(self):
        prop = PTSProperty("abc")
        export = json.dumps(prop.inner_rep(), sort_keys=True)
        assert export == '{"name": "abc"}'

    def test_inner_rep_with_desc(self):
        prop = PTSProperty("abc", "xyz")
        export = json.dumps(prop.inner_rep(), sort_keys=True)
        assert export == '{"description": "xyz", "name": "abc"}'

    def test_export_to_json_no_desc(self):
        prop = PTSProperty("abc")
        export = json.dumps(prop.export_to_json(), sort_keys=True)
        assert export == '{"name": "abc"}'

    def test_export_to_json_with_desc(self):
        prop = PTSProperty("abc", "xyz")
        export = json.dumps(prop.export_to_json(), sort_keys=True)
        assert export == '{"description": "xyz", "name": "abc"}'


class TestPTSBoundary:
    def test_ptsboundary(self):
        boundary = PTSBoundary("abc", "xyz")
        assert boundary.name == "abc"
        assert boundary.desc == "xyz"


class TestPTSComponent:
    def test_ptscomponent(self):
        component = PTSComponent("abc", "xyz")
        assert component.name == "abc"
        assert component.desc == "xyz"


class TestPTSThreat:
    def test_ptsthreat(self):
        threat = PTSThreat("abc", "xyz")
        assert threat.name == "abc"
        assert threat.desc == "xyz"

class TestPTSElement:
    def test_ptselement_no_refs(self):
        element = PTSElement("@boundary","@component","@threat")
        assert element.boundary == "@boundary"
        assert element.component == "@component"
        assert element.threat == "@threat"
        assert element.refs == []
        assert element.meta == None

    def test_ptselement_with_refs(self):
        refs = ["abc","def"]
        element = PTSElement("@boundary","@component","@threat", refs)
        assert element.refs == refs

    @raises(ValueError)
    def test_export_to_json_no_meta(self):
        element = PTSElement("@boundary","@component","@threat")
        element.export_to_json()

    def test_export_to_json_with_meta(self):
        element = PTSElement("@boundary","@component","@threat")
        element.meta = PTSSourceMeta()
        export = json.dumps(element.export_to_json(), sort_keys=True)
        assert export == '{"boundary": "@boundary", "component": "@component", "refs": [], "source": {"file": "", "function": "", "line": 0}, "threat": "@threat"}'


class TestPTSReview:
    def test_ptsreview_no_refs(self):
        review = PTSReview("@boundary","@component","a review")
        assert review.boundary == "@boundary"
        assert review.component == "@component"
        assert review.review == "a review"
        assert review.refs == []
        assert review.meta == None

    def test_ptsreview_with_refs(self):
        refs = ["abc","def"]
        review = PTSReview("@boundary","@component","a review", refs)
        assert review.refs == refs

    @raises(ValueError)
    def test_ptsreview_export_to_json_no_meta(self):
        review = PTSReview("@boundary","@component","a review")
        review.export_to_json()

    def test_export_to_json_with_meta(self):
        review = PTSReview("@boundary","@component","a review")
        review.meta = PTSSourceMeta()
        export = json.dumps(review.export_to_json(), sort_keys=True)
        assert export == '{"boundary": "@boundary", "component": "@component", "refs": [], "review": "a review", "source": {"file": "", "function": "", "line": 0}}'


class TestPTSTransfer:
    def test_ptstransfer(self):
        transfer = PTSTransfer("@boundary","@component","@threat","transfer")
        assert transfer.boundary == "@boundary"
        assert transfer.component == "@component"
        assert transfer.threat == "@threat"
        assert transfer.transfer == "transfer"
        assert transfer.refs == []
        assert transfer.meta == None

    @raises(ValueError)
    def test_export_to_json_no_meta(self):
        transfer = PTSTransfer("@boundary","@component","@threat","transfer")
        transfer.export_to_json()

    def test_export_to_json_with_meta(self):
        transfer = PTSTransfer("@boundary","@component","@threat","transfer")
        transfer.meta = PTSSourceMeta()
        export = json.dumps(transfer.export_to_json(), sort_keys=True)
        assert export == '{"boundary": "@boundary", "component": "@component", "refs": [], "source": {"file": "", "function": "", "line": 0}, "threat": "@threat", "transfer": "transfer"}'


class TestPTSAcceptance:
    def test_ptsacceptance(self):
        acceptance = PTSAcceptance("@boundary","@component","@threat","acceptance")
        assert acceptance.boundary == "@boundary"
        assert acceptance.component == "@component"
        assert acceptance.threat == "@threat"
        assert acceptance.acceptance == "acceptance"
        assert acceptance.refs == []
        assert acceptance.meta == None

    @raises(ValueError)
    def test_export_to_json_no_meta(self):
        acceptance = PTSAcceptance("@boundary","@component","@threat","acceptance")
        acceptance.export_to_json()

    def test_export_to_json_with_meta(self):
        acceptance = PTSAcceptance("@boundary","@component","@threat","acceptance")
        acceptance.meta = PTSSourceMeta()
        export = json.dumps(acceptance.export_to_json(), sort_keys=True)
        assert export == '{"acceptance": "acceptance", "boundary": "@boundary", "component": "@component", "refs": [], "source": {"file": "", "function": "", "line": 0}, "threat": "@threat"}'


class TestPTSMitigation:
    def test_ptsmitigation(self):
        mitigation = PTSMitigation("@boundary","@component","@threat","mitigation")
        assert mitigation.boundary == "@boundary"
        assert mitigation.component == "@component"
        assert mitigation.threat == "@threat"
        assert mitigation.mitigation == "mitigation"
        assert mitigation.refs == []
        assert mitigation.meta == None

    @raises(ValueError)
    def test_export_to_json_no_meta(self):
        mitigation = PTSMitigation("@boundary","@component","@threat","mitigation")
        mitigation.export_to_json()

    def test_export_to_json_with_meta(self):
        mitigation = PTSMitigation("@boundary","@component","@threat","mitigation")
        mitigation.meta = PTSSourceMeta()
        export = json.dumps(mitigation.export_to_json(), sort_keys=True)
        assert export == '{"boundary": "@boundary", "component": "@component", "mitigation": "mitigation", "refs": [], "source": {"file": "", "function": "", "line": 0}, "threat": "@threat"}'

class TestPTSExposure:
    def test_ptsexposure(self):
        exposure = PTSExposure("@boundary","@component","@threat","exposure")
        assert exposure.boundary == "@boundary"
        assert exposure.component == "@component"
        assert exposure.threat == "@threat"
        assert exposure.exposure == "exposure"
        assert exposure.refs == []
        assert exposure.meta == None

    @raises(ValueError)
    def test_export_to_json_no_meta(self):
        exposure = PTSExposure("@boundary","@component","@threat","exposure")
        exposure.export_to_json()

    def test_export_to_json_with_meta(self):
        exposure = PTSExposure("@boundary","@component","@threat","exposure")
        exposure.meta = PTSSourceMeta()
        export = json.dumps(exposure.export_to_json(), sort_keys=True)
        assert export == '{"boundary": "@boundary", "component": "@component", "exposure": "exposure", "refs": [], "source": {"file": "", "function": "", "line": 0}, "threat": "@threat"}'


class TestPTSDfd:
    def test_ptsdfd(self):
        dfd = PTSDfd()
        assert dfd.tree == {}

    @raises(ValueError)
    def test_add_edge_no_meta(self):
        dfd = PTSDfd()
        edge = PTSDfdEdge(
            "@source_boundary",
            "@source_component",
            "@dest_boundary",
            "@dest_component",
            PTSDfdEdge.UNI_DIRECTIONAL,
            None
        )
        dfd.add_edge(edge)

    def test_add_edge_with_meta(self):
        dfd = PTSDfd()
        edge = PTSDfdEdge(
            "@source_boundary",
            "@source_component",
            "@dest_boundary",
            "@dest_component",
            PTSDfdEdge.UNI_DIRECTIONAL,
            PTSSourceMeta()
        )

        dfd.add_edge(edge)
        assert "@source_boundary" in dfd.tree
        assert "@source_component" in dfd.tree["@source_boundary"]
        assert "@dest_boundary" in dfd.tree["@source_boundary"]["@source_component"]
        assert "@dest_component" in dfd.tree["@source_boundary"]["@source_component"]["@dest_boundary"]
        assert dfd.tree["@source_boundary"]["@source_component"]["@dest_boundary"]["@dest_component"]["type"] == PTSDfdEdge.UNI_DIRECTIONAL
        assert isinstance(dfd.tree["@source_boundary"]["@source_component"]["@dest_boundary"]["@dest_component"]["meta"], PTSSourceMeta)

    def test_export_to_json(self):
        dfd = PTSDfd()
        edge = PTSDfdEdge(
            "@source_boundary",
            "@source_component",
            "@dest_boundary",
            "@dest_component",
            PTSDfdEdge.UNI_DIRECTIONAL,
            PTSSourceMeta()
        )
        dfd.add_edge(edge)
        export = json.dumps(dfd.export_to_json(), sort_keys=True)
        assert export == '{"@source_boundary": {"@source_component": {"@dest_boundary": {"@dest_component": {"fname": "", "function": "", "lineno": 0, "type": "uni"}}}}}'


class TestPTSDfdEdge:
    def test_ptsdfdedge(self):
        edge = PTSDfdEdge(
            "@source_boundary",
            "@source_component",
            "@dest_boundary",
            "@dest_component",
            PTSDfdEdge.UNI_DIRECTIONAL,
            None
        )

        assert edge.source_boundary_id == "@source_boundary"
        assert edge.source_component_id == "@source_component"
        assert edge.dest_boundary_id == "@dest_boundary"
        assert edge.dest_component_id == "@dest_component"
        assert edge.connection_type == PTSDfdEdge.UNI_DIRECTIONAL
        assert edge.meta == None

class TestPTSReference:
    def test_ptsreference(self):
        reference = PTSReference("reference")
        assert reference.ref == "reference"

class TestPyThreatspecReporter:
    def test_pythreatspecreporter(self):
        reporter = PyThreatspecReporter(None, "project")
        assert reporter.parser == None
        assert reporter.project == "project"

    def test_export_json_no_data(self):
        parser = PyThreatspecParser()
        parser.creation_time = 0
        parser.updated_time = 0

        reporter = PyThreatspecReporter(parser, "project")
        export = json.dumps(reporter.export_to_json(), sort_keys=True)
        assert export == '{"boundaries": {}, "components": {}, "dfd": {}, "document": {"created": 0, "updated": 0}, "projects": {"project": {"acceptances": {}, "exposures": {}, "mitigations": {}, "reviews": {}, "transfers": {}}}, "specification": {"name": "ThreatSpec", "version": "0.1.0"}, "threats": {}}'

class TestPyThreatspecParser:
    def test_pythreatspecparser(self):
        parser = PyThreatspecParser()
        assert parser.projects == {}

class TestParser:
    def setup(self):
        self.parser = PyThreatspecParser()

class TestAddBoundary(TestParser):
    def test_add_boundary_by_id(self):
        boundary_id = self.parser.add_boundary("@boundary")
        assert boundary_id == "@boundary"
        assert self.parser.boundaries == {}

    def test_add_boundary_by_name(self):
        boundary_id = self.parser.add_boundary("boundary")
        assert boundary_id == "@boundary"
        assert "@boundary" in self.parser.boundaries
        assert isinstance(self.parser.boundaries["@boundary"], PTSBoundary)
        assert self.parser.boundaries["@boundary"].name == "boundary"

    @raises(ValueError)
    def test_add_boundary_by_id_with_id(self):
        self.parser.add_boundary("@boundary", "@another_boundary")

    def test_add_boundary_by_name_with_id(self):
        boundary_id = self.parser.add_boundary("A boundary", "@boundary")
        assert boundary_id == "@boundary"
        assert "@boundary" in self.parser.boundaries
        assert isinstance(self.parser.boundaries["@boundary"], PTSBoundary)
        assert self.parser.boundaries["@boundary"].name == "A boundary"


class TestAddComponent(TestParser):
    def test_add_component_by_id(self):
        component_id = self.parser.add_component("@boundary", "@component")
        assert component_id == "@component"
        assert self.parser.components == {}

    def test_add_component_by_name(self):
        component_id = self.parser.add_component("@boundary", "component")
        assert component_id == "@component"
        assert "@boundary" in self.parser.components
        assert "@component" in self.parser.components["@boundary"]
        assert isinstance(self.parser.components["@boundary"]["@component"], PTSComponent)
        assert self.parser.components["@boundary"]["@component"].name == "component"

    @raises(ValueError)
    def test_add_component_by_id_with_id(self):
        self.parser.add_component("@boundary", "@component", "@another_component")

    def test_add_component_by_name_with_id(self):
        component_id = self.parser.add_component("@boundary", "A component", "@component")
        assert component_id == "@component"
        assert "@boundary" in self.parser.components
        assert "@component" in self.parser.components["@boundary"]
        assert isinstance(self.parser.components["@boundary"]["@component"], PTSComponent)
        assert self.parser.components["@boundary"]["@component"].name == "A component"


class TestAddThreat(TestParser):
    def test_add_threat_by_id(self):
        threat_id = self.parser.add_threat("@threat")
        assert threat_id == "@threat"
        assert self.parser.threats == {}

    def test_add_threat_by_name(self):
        threat_id = self.parser.add_threat("threat")
        assert threat_id == "@threat"
        assert "@threat" in self.parser.threats
        assert isinstance(self.parser.threats["@threat"], PTSThreat)
        assert self.parser.threats["@threat"].name == "threat"

    @raises(ValueError)
    def test_add_threat_by_id_with_id(self):
        self.parser.add_threat("@threat", "@another_threat")

    def test_add_threat_by_name_with_id(self):
        threat_id = self.parser.add_threat("A threat", "@threat")
        assert threat_id == "@threat"
        assert "@threat" in self.parser.threats
        assert isinstance(self.parser.threats["@threat"], PTSThreat)
        assert self.parser.threats["@threat"].name == "A threat"


class TestParseAlias(TestParser):
    @raises(ValueError)
    def test_parse_alias_invalid_pattern(self):
        self.parser._parse_alias("@alias badger likes to drink tea", PTSSourceMeta())

    def test_parse_alias_boundary(self):
        self.parser._parse_alias("@alias boundary @boundary to A boundary", PTSSourceMeta())
        assert "@boundary" in self.parser.boundaries
        assert isinstance(self.parser.boundaries["@boundary"], PTSBoundary)
        assert self.parser.boundaries["@boundary"].name == "A boundary"

    @nottest
    def test_parse_alias_boundary_multiline(self):
        self.parser._parse_alias("@alias boundary @boundary to A boundary\\\nwith multi lines", PTSSourceMeta())
        assert "@boundary" in self.parser.boundaries
        assert isinstance(self.parser.boundaries["@boundary"], PTSBoundary)
        assert self.parser.boundaries["@boundary"].name == "A boundary with multi lines"

    def test_parse_alias_component(self):
        self.parser._parse_alias("@alias component @boundary:@component to A component", PTSSourceMeta())
        assert "@boundary" in self.parser.components
        assert "@component" in self.parser.components["@boundary"]
        assert isinstance(self.parser.components["@boundary"]["@component"], PTSComponent)
        assert self.parser.components["@boundary"]["@component"].name == "A component"

    def test_parse_alias_threat(self):
        self.parser._parse_alias("@alias threat @threat to A threat", PTSSourceMeta())
        assert "@threat" in self.parser.threats
        assert isinstance(self.parser.threats["@threat"], PTSThreat)
        assert self.parser.threats["@threat"].name == "A threat"


class TestParseDescribe(TestParser):
    @raises(ValueError)
    def test_parse_describe_invalid_pattern(self):
        self.parser._parse_describe("@describe badger likes to drink tea", PTSSourceMeta())

    @raises(ValueError)
    def test_parse_describe_boundary_missing_boundary(self):
        self.parser._parse_describe("@describe boundary @boundary as a boundary", PTSSourceMeta())

    def test_parse_describe_boundary(self):
        self.parser.boundaries["@boundary"] = PTSBoundary("boundary")
        self.parser._parse_describe("@describe boundary @boundary as a boundary", PTSSourceMeta())
        assert self.parser.boundaries["@boundary"].desc == "a boundary"

    @raises(ValueError)
    def test_parse_describe_component_missing_boundary(self):
        self.parser._parse_describe("@describe component @boundary:@component as a component", PTSSourceMeta())

    @raises(ValueError)
    def test_parse_describe_missing_component(self):
        self.parser.components["@boundary"] = {}
        self.parser._parse_describe("@describe component @boundary:@component as a component", PTSSourceMeta())

    def test_parse_describe_component(self):
        self.parser.components["@boundary"] = {"@component": PTSComponent("component")}
        self.parser._parse_describe("@describe component @boundary:@component as a component", PTSSourceMeta())
        assert self.parser.components["@boundary"]["@component"].desc == "a component"

    @raises(ValueError)
    def test_parse_describe_threat_missing_threat(self):
        self.parser._parse_describe("@describe threat @threat as a threat", PTSSourceMeta())

    def test_parse_describe_threat(self):
        self.parser.threats["@threat"] = PTSThreat("threat")
        self.parser._parse_describe("@describe threat @threat as a threat", PTSSourceMeta())
        assert self.parser.threats["@threat"].desc == "a threat"


class TestParseConnects(TestParser):
    @raises(ValueError)
    def test_parse_connects_invalid_pattern(self):
        self.parser._parse_connects("@connects badger likes to drink tea", PTSSourceMeta())

    def test_parse_connects_to(self):
        self.parser._parse_connects("@connects @src_boundary:@src_component to @dst_boundary:@dst_component", PTSSourceMeta())
        assert "@src_boundary" in self.parser.dfd.tree
        assert "@src_component" in self.parser.dfd.tree["@src_boundary"]
        assert "@dst_boundary" in self.parser.dfd.tree["@src_boundary"]["@src_component"]
        assert "@dst_component" in self.parser.dfd.tree["@src_boundary"]["@src_component"]["@dst_boundary"]
        assert self.parser.dfd.tree["@src_boundary"]["@src_component"]["@dst_boundary"]["@dst_component"]["type"] == PTSDfdEdge.UNI_DIRECTIONAL

    def test_parse_connects_with(self):
        self.parser._parse_connects("@connects @src_boundary:@src_component with @dst_boundary:@dst_component", PTSSourceMeta())
        assert "@src_boundary" in self.parser.dfd.tree
        assert "@src_component" in self.parser.dfd.tree["@src_boundary"]
        assert "@dst_boundary" in self.parser.dfd.tree["@src_boundary"]["@src_component"]
        assert "@dst_component" in self.parser.dfd.tree["@src_boundary"]["@src_component"]["@dst_boundary"]
        assert self.parser.dfd.tree["@src_boundary"]["@src_component"]["@dst_boundary"]["@dst_component"]["type"] == PTSDfdEdge.BI_DIRECTIONAL


class TestParseReview(TestParser):
    @raises(ValueError)
    def test_parse_review_invalid_pattern(self):
        self.parser._parse_review("@review badger likes to drink tea", PTSSourceMeta())

    def test_parse_review_boundary_id(self):
        self.parser._parse_review("@review @boundary:@component a review", PTSSourceMeta())
        assert "@boundary" not in self.parser.boundaries
        assert "@a_review" in self.parser.reviews
        assert self.parser.reviews["@a_review"][0].review == "a review"

    def test_parse_review_boundary(self):
        self.parser._parse_review("@review boundary:@component a review", PTSSourceMeta())
        assert "@boundary" in self.parser.boundaries
        assert "@a_review" in self.parser.reviews
        assert self.parser.reviews["@a_review"][0].review == "a review"

    def test_parse_review_component_id(self):
        self.parser._parse_review("@review @boundary:@component a review", PTSSourceMeta())
        assert "@boundary" not in self.parser.components
        assert "@a_review" in self.parser.reviews
        assert self.parser.reviews["@a_review"][0].review == "a review"

    def test_parse_review_component(self):
        self.parser._parse_review("@review @boundary:component a review", PTSSourceMeta())
        assert "@boundary" in self.parser.components
        assert "@component" in self.parser.components["@boundary"]
        assert "@a_review" in self.parser.reviews
        assert self.parser.reviews["@a_review"][0].review == "a review"


class TestParseMitigates(TestParser):
    @raises(ValueError)
    def test_parse_mitigates_invalid_pattern(self):
        self.parser._parse_mitigates("@mitigates badger likes to drink tea", PTSSourceMeta())

    def test_parse_mitigates_boundary_id(self):
        self.parser._parse_mitigates("@mitigates @boundary:@component against threat with mitigation", PTSSourceMeta())
        assert "@boundary" not in self.parser.boundaries
        assert "@threat" in self.parser.threats
        assert self.parser.threats["@threat"].name == "threat"
        assert "@mitigation" in self.parser.mitigations
        assert self.parser.mitigations["@mitigation"][0].mitigation == "mitigation"

    def test_parse_mitigates_boundary(self):
        self.parser._parse_mitigates("@mitigates boundary:@component against threat with mitigation", PTSSourceMeta())
        assert "@boundary" in self.parser.boundaries
        assert "@threat" in self.parser.threats
        assert self.parser.threats["@threat"].name == "threat"
        assert "@mitigation" in self.parser.mitigations
        assert self.parser.mitigations["@mitigation"][0].mitigation == "mitigation"

    def test_parse_mitigates_component_id(self):
        self.parser._parse_mitigates("@mitigates @boundary:@component against threat with mitigation", PTSSourceMeta())
        assert "@boundary" not in self.parser.components
        assert "@threat" in self.parser.threats
        assert self.parser.threats["@threat"].name == "threat"
        assert "@mitigation" in self.parser.mitigations
        assert self.parser.mitigations["@mitigation"][0].mitigation == "mitigation"

    def test_parse_mitigates_component(self):
        self.parser._parse_mitigates("@mitigates @boundary:component against threat with mitigation", PTSSourceMeta())
        assert "@boundary" in self.parser.components
        assert "@component" in self.parser.components["@boundary"]
        assert "@threat" in self.parser.threats
        assert self.parser.threats["@threat"].name == "threat"
        assert "@mitigation" in self.parser.mitigations
        assert self.parser.mitigations["@mitigation"][0].mitigation == "mitigation"

class TestParseExposes(TestParser):
    @raises(ValueError)
    def test_parse_exposes_invalid_pattern(self):
        self.parser._parse_exposes("@exposes badger likes to drink tea", PTSSourceMeta())

    def test_parse_exposes_boundary_id(self):
        self.parser._parse_exposes("@exposes @boundary:@component to threat with exposure", PTSSourceMeta())
        assert "@boundary" not in self.parser.boundaries
        assert "@threat" in self.parser.threats
        assert self.parser.threats["@threat"].name == "threat"
        assert "@exposure" in self.parser.exposures
        assert self.parser.exposures["@exposure"][0].exposure == "exposure"

    def test_parse_exposes_boundary(self):
        self.parser._parse_exposes("@exposes boundary:@component to threat with exposure", PTSSourceMeta())
        assert "@boundary" in self.parser.boundaries
        assert "@threat" in self.parser.threats
        assert self.parser.threats["@threat"].name == "threat"
        assert "@exposure" in self.parser.exposures
        assert self.parser.exposures["@exposure"][0].exposure == "exposure"

    def test_parse_exposes_component_id(self):
        self.parser._parse_exposes("@exposes @boundary:@component to threat with exposure", PTSSourceMeta())
        assert "@boundary" not in self.parser.components
        assert "@threat" in self.parser.threats
        assert self.parser.threats["@threat"].name == "threat"
        assert "@exposure" in self.parser.exposures
        assert self.parser.exposures["@exposure"][0].exposure == "exposure"

    def test_parse_exposes_component(self):
        self.parser._parse_exposes("@exposes @boundary:component to threat with exposure", PTSSourceMeta())
        assert "@boundary" in self.parser.components
        assert "@component" in self.parser.components["@boundary"]
        assert "@threat" in self.parser.threats
        assert self.parser.threats["@threat"].name == "threat"
        assert "@exposure" in self.parser.exposures
        assert self.parser.exposures["@exposure"][0].exposure == "exposure"


class TestParseTransfers(TestParser):
    @raises(ValueError)
    def test_parse_transfers_invalid_pattern(self):
        self.parser._parse_transfers("@transfers badger likes to drink tea", PTSSourceMeta())

    def test_parse_transfers_boundary_id(self):
        self.parser._parse_transfers("@transfers threat to @boundary:@component with transfer", PTSSourceMeta())
        assert "@boundary" not in self.parser.boundaries
        assert "@threat" in self.parser.threats
        assert self.parser.threats["@threat"].name == "threat"
        assert "@transfer" in self.parser.transfers
        assert self.parser.transfers["@transfer"][0].transfer == "transfer"

    def test_parse_transfers_boundary(self):
        self.parser._parse_transfers("@transfers threat to boundary:@component with transfer", PTSSourceMeta())
        assert "@boundary" in self.parser.boundaries
        assert "@threat" in self.parser.threats
        assert self.parser.threats["@threat"].name == "threat"
        assert "@transfer" in self.parser.transfers
        assert self.parser.transfers["@transfer"][0].transfer == "transfer"

    def test_parse_transfers_component_id(self):
        self.parser._parse_transfers("@transfers threat to @boundary:@component with transfer", PTSSourceMeta())
        assert "@boundary" not in self.parser.components
        assert "@threat" in self.parser.threats
        assert self.parser.threats["@threat"].name == "threat"
        assert "@transfer" in self.parser.transfers
        assert self.parser.transfers["@transfer"][0].transfer == "transfer"

    def test_parse_transfers_component(self):
        self.parser._parse_transfers("@transfers threat to @boundary:component with transfer", PTSSourceMeta())
        assert "@boundary" in self.parser.components
        assert "@component" in self.parser.components["@boundary"]
        assert "@threat" in self.parser.threats
        assert self.parser.threats["@threat"].name == "threat"
        assert "@transfer" in self.parser.transfers
        assert self.parser.transfers["@transfer"][0].transfer == "transfer"


class TestParseAccepts(TestParser):
    @raises(ValueError)
    def test_parse_accepts_invalid_pattern(self):
        self.parser._parse_accepts("@accepts badger likes to drink tea", PTSSourceMeta())

    def test_parse_accepts_boundary_id(self):
        self.parser._parse_accepts("@accepts threat to @boundary:@component with acceptance", PTSSourceMeta())
        assert "@boundary" not in self.parser.boundaries
        assert "@threat" in self.parser.threats
        assert self.parser.threats["@threat"].name == "threat"
        assert "@acceptance" in self.parser.acceptances
        assert self.parser.acceptances["@acceptance"][0].acceptance == "acceptance"

    def test_parse_accepts_boundary(self):
        self.parser._parse_accepts("@accepts threat to boundary:@component with acceptance", PTSSourceMeta())
        assert "@boundary" in self.parser.boundaries
        assert "@threat" in self.parser.threats
        assert self.parser.threats["@threat"].name == "threat"
        assert "@acceptance" in self.parser.acceptances
        assert self.parser.acceptances["@acceptance"][0].acceptance == "acceptance"

    def test_parse_accepts_component_id(self):
        self.parser._parse_accepts("@accepts threat to @boundary:@component with acceptance", PTSSourceMeta())
        assert "@boundary" not in self.parser.components
        assert "@threat" in self.parser.threats
        assert self.parser.threats["@threat"].name == "threat"
        assert "@acceptance" in self.parser.acceptances
        assert self.parser.acceptances["@acceptance"][0].acceptance == "acceptance"

    def test_parse_accepts_component(self):
        self.parser._parse_accepts("@accepts threat to @boundary:component with acceptance", PTSSourceMeta())
        assert "@boundary" in self.parser.components
        assert "@component" in self.parser.components["@boundary"]
        assert "@threat" in self.parser.threats
        assert self.parser.threats["@threat"].name == "threat"
        assert "@acceptance" in self.parser.acceptances
        assert self.parser.acceptances["@acceptance"][0].acceptance == "acceptance"

class TestParseComment(TestParser):
    def test_parse_comment_alias(self):
        self.parser._parse_comment("@alias boundary @boundary to A boundary", PTSSourceMeta())
        assert self.parser.boundaries["@boundary"].name == "A boundary"
 
    def test_parse_comment_describe(self):
        self.parser.boundaries["@boundary"] = PTSBoundary("boundary")
        self.parser._parse_comment("@describe boundary @boundary as a boundary", PTSSourceMeta())
        assert self.parser.boundaries["@boundary"].desc == "a boundary"
 
    def test_parse_comment_connects(self):
        self.parser._parse_comment("@connects @src_boundary:@src_component to @dst_boundary:@dst_component", PTSSourceMeta())
        assert self.parser.dfd.tree["@src_boundary"]["@src_component"]["@dst_boundary"]["@dst_component"]["type"] == PTSDfdEdge.UNI_DIRECTIONAL
 
    def test_parse_comment_review(self):
        self.parser._parse_comment("@review @boundary:@component a review", PTSSourceMeta())
        assert self.parser.reviews["@a_review"][0].review == "a review"
 
    def test_parse_comment_mitigates(self):
        self.parser._parse_comment("@mitigates @boundary:@component against threat with mitigation", PTSSourceMeta())
        assert self.parser.mitigations["@mitigation"][0].mitigation == "mitigation"
 
    def test_parse_comment_exposes(self):
        self.parser._parse_comment("@exposes @boundary:@component to threat with exposure", PTSSourceMeta())
        assert self.parser.exposures["@exposure"][0].exposure == "exposure"
 
    def test_parse_comment_transfers(self):
        self.parser._parse_comment("@transfers threat to @boundary:@component with transfer", PTSSourceMeta())
        assert self.parser.transfers["@transfer"][0].transfer == "transfer"
 
    def test_parse_comment_accepts(self):
        self.parser._parse_comment("@accepts threat to @boundary:@component with acceptance", PTSSourceMeta())
        assert self.parser.acceptances["@acceptance"][0].acceptance == "acceptance"
 

class TestParseAst(TestParser):
    def test_parse_globals(self):
        source = '''
"""@alias boundary @boundary to A boundary"""
'''
        module = ast.parse(source)
        self.parser._parse_globals(module, "filename")
        assert self.parser.boundaries["@boundary"].name == "A boundary"

    def test_parse_classes(self):
        source = '''
class TestClass:
    """@alias boundary @boundary to A boundary"""
    def __init__(self):
        pass
'''
        module = ast.parse(source)
        self.parser._parse_classes(module, "filename")
        assert self.parser.boundaries["@boundary"].name == "A boundary"

    def test_parse_methods(self):
        source = '''
class TestClass:
    def a_method(self):
        """@alias boundary @boundary to A boundary"""
        pass
'''
        module = ast.parse(source)
        class_definitions = [node for node in module.body if isinstance(node, ast.ClassDef)]
        assert len(class_definitions) == 1
        self.parser._parse_methods(class_definitions[0], "filename")
        assert self.parser.boundaries["@boundary"].name == "A boundary"

    def test_parse_functions(self):
        source = '''
def a_global_function():
    """@alias boundary @boundary to A boundary"""
    pass
'''
        module = ast.parse(source)
        self.parser._parse_functions(module, "filename")
        assert self.parser.boundaries["@boundary"].name == "A boundary"
