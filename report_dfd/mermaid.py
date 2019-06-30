#!/usr/bin/env python

import sys
import json
import string
import random
from pprint import pprint

# http://stackoverflow.com/questions/7204805/dictionaries-of-dictionaries-merge
def merge(a, b, path=None):
    "merges b into a"
    if path is None: path = []
    for key in b:
        if key in a:
            if isinstance(a[key], dict) and isinstance(b[key], dict):
                merge(a[key], b[key], path + [str(key)])
            elif a[key] == b[key]:
                pass # same leaf value
            else:
                #raise Exception('Conflict at %s' % '.'.join(path + [str(key)]))
                a[key] = b[key]
        else:
            a[key] = b[key]
    return a

def strip_id(text):
    if text.startswith("@"):
        return text[1:]
    else:
        return text

def make_threat_gid(threat_id):
    return strip_id(threat_id)+'_'+''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(10))

def split_words(text, size = 40):
    words = text.split()
    new_words = []

    line = ""
    for word in words:
        
        t = " ".join([line, word])
        if len(t) > size:
            new_words.append(t)
            line = ""
        else:
            line = t

    if line != "":
        new_words.append(line)

    return "<br/>".join(new_words)

def merge_component_id(boundary_id, component_id):
    return "{}_{}".format(boundary_id, component_id)

data = {}
for filename in sys.argv[1:]:
	with open(filename) as fh:
		data = merge(data, json.load(fh))

mermaid = """graph LR
    classDef exposures fill:#e74c3c,stroke:#333,stroke-width:2px;
    classDef mitigations fill:#2ecc71,stroke:#333,stroke-width:2px;
    classDef transfers fill:#9b59b6,stroke:#333,stroke-width:2px;
    classDef acceptances fill:#f39c12,stroke:#333,stroke-width:2px;
    classDef reviews fill:#3498db,stroke:#333,stroke-width:2px;
"""

boundaries = {}
global_edges = []
threats = {
    "exposures": {},
    "mitigations": {},
    "transfers": {},
    "acceptances": {},
    "reviews": {}
}

for boundary_id, boundary in data["boundaries"].iteritems():
    boundary_id = strip_id(boundary_id)
    boundaries[boundary_id] = boundary
    boundaries[boundary_id]["components"] = {}

for boundary_id, component_obj in data["components"].iteritems():
    for component_id, component in component_obj.iteritems():
        boundary_id = strip_id(boundary_id)
        component_id = merge_component_id(boundary_id, strip_id(component_id))

        if boundary_id in boundaries:
            boundaries[boundary_id]["components"][component_id] = component["name"]

for source_boundary_id, source_obj in data["dfd"].iteritems():
    for source_component_id, dest_boundary_obj in source_obj.iteritems():
        for dest_boundary_id, dest_component_obj in dest_boundary_obj.iteritems():
            for dest_component_id, dest_obj in dest_component_obj.iteritems():

                source_boundary_id = strip_id(source_boundary_id)
                source_component_id = strip_id(source_component_id)
                dest_boundary_id = strip_id(dest_boundary_id)
                dest_component_id = strip_id(dest_component_id)

                source_id = merge_component_id(source_boundary_id, source_component_id)
                dest_id = merge_component_id(dest_boundary_id, dest_component_id)
                edge_type = dest_obj["type"]
                edge_name = dest_obj["name"]

                if source_boundary_id == dest_boundary_id:
                    if "edges" not in boundaries[source_boundary_id]:
                        boundaries[source_boundary_id]["edges"] = []
                    boundaries[source_boundary_id]["edges"].append((source_id, dest_id, edge_type, edge_name))
                else:
                    global_edges.append((source_id, dest_id, edge_type, edge_name))

text_map = {
    "exposures": "Exposed to",
    "mitigations": "Mitigated against",
    "transfers": "Transfers",
    "acceptances": "Accepts",
    "reviews": "Review"
}
description_key = {
    "exposures": "exposure",
    "mitigations": "mitigation",
    "transfers": "transfer",
    "acceptances": "acceptance"
}

for project_id, project in data["projects"].iteritems():
    for threat_type in ["exposures", "mitigations", "transfers", "acceptances"]:
        for threat_type_id, threat_type_obj in data["projects"][project_id][threat_type].iteritems():
            for obj in threat_type_obj:
                threat_id = obj["threat"]
                threat_text = data["threats"][threat_id]["name"]
                threat_gid = make_threat_gid(threat_id)

                if threat_gid not in threats[threat_type]:
                    threats[threat_type][threat_gid] = {
                        "text": split_words("{} {} with {}".format(text_map[threat_type], threat_text, obj[description_key[threat_type]])),
                        "components": []
                    }

                threats[threat_type][threat_gid]["components"].append(merge_component_id(strip_id(obj["boundary"]), strip_id(obj["component"])))

    for review_id, reviews in data["projects"][project_id]["reviews"].iteritems():
        for review in reviews:
            review_gid = make_threat_gid(review_id)

            if review_gid not in threats["reviews"]:
                threats["reviews"][review_gid] = {
                    "text": "{} {}".format(text_map["reviews"], review["review"]),
                    "components": []
                }

                threats["reviews"][review_gid]["components"].append(merge_component_id(strip_id(review["boundary"]), strip_id(review["component"])))

# Start adding to mermaid

for boundary_id, boundary in boundaries.iteritems():
    mermaid += "    subgraph {}\n".format(boundary["name"])

    for component_id, component in boundary["components"].iteritems():
        mermaid += "        {}(\"{}\")\n".format(component_id, component)

    if "edges" in boundary:
        for (source_id, dest_id, edge_type, edge_name) in boundary["edges"]:
            if edge_type == "uni":
                arrow = "-->"
            else:
                arrow = "---"

            if edge_name != "":
                arrow = "-- {} {}".format(edge_name, arrow)

            mermaid += "        {} {} {}\n".format(source_id, arrow, dest_id)

    mermaid += "    end\n\n"

for threat_type in ["exposures", "mitigations", "transfers", "acceptances", "reviews"]:
    for threat_type_id, threat_type_obj in threats[threat_type].iteritems():
        mermaid += "    {}>\"{}\"]\n".format(threat_type_id, threat_type_obj["text"])
        mermaid += "    class {} {}\n".format(threat_type_id, threat_type)

        for component_id in threat_type_obj["components"]:
            mermaid += "    {}-.-{}\n".format(threat_type_id, component_id)

mermaid += "\n"

for (source_id, dest_id, edge_type, edge_name) in global_edges:
    if edge_type == "uni":
        arrow = "==>"
    else:
        arrow = "==="

    if edge_name != "":
        arrow = "== {} {}".format(edge_name, arrow)

    mermaid += "    {} {} {}\n".format(source_id, arrow, dest_id)

print mermaid