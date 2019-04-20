#!/usr/bin/env python

import re
import sys
import xmltodict
import json
import time

def create_id(obj):
    identifier = obj["@ID"]
    name = obj["@Name"]

    name = re.sub(r'[^a-zA-Z0-9_ \-]', "", name)
    name = re.sub(r'[ \-]', "_", name)
    name = name.lower()

    return "@cwe_{}_{}".format(identifier, name)

def create_name(obj):
    return obj["@Name"]

def create_description(obj):
    if not "Description" in obj:
        return "No description available."

    description = obj["Description"]["Description_Summary"]
    description = re.sub(r'[^a-zA-Z0-9_ \-\;\:\.\,]', " ", description)
    description = re.sub(r' +', " ", description)

    if "Extended_Description" in obj["Description"] and obj["Description"]["Extended_Description"]:
        if isinstance(obj["Description"]["Extended_Description"]["Text"], list):
            extended_description = ".".join(obj["Description"]["Extended_Description"]["Text"])
        else:
            extended_description = obj["Description"]["Extended_Description"]["Text"]

        extended_description = re.sub(r'[^a-zA-Z0-9_ \-\;\:\.\,]', " ", extended_description)
        extended_description = re.sub(r' +', " ", extended_description)
        return description+" "+extended_description
    else:
        return description

def create_refs(obj):
    identifier = "CWE {}".format(obj["@ID"])
    url = "https://cwe.mitre.org/data/definitions/{}.html".format(obj["@ID"])
    return [identifier, url]

if len(sys.argv) != 2:
    print("Usage: cwe_to_threatspec.py CWE_XML_FILE")
    sys.exit(1)

filename = sys.argv[1]

print("Parsing CWE file {}".format(filename))
with open(filename) as fh:
    cwes = xmltodict.parse(fh.read())
"""
1   {
1   "threats": {
2     "@manipulation_of_data_in_transit": {
3       "name": "manipulation of data in transit"
4     },
5     "@malicious_requests": {
6       "name": "malicious requests"
7     },
8     "@information_disclosure_in_transit": {
9       "name": "information disclosure of data in transit"
10     },
11     "@data_loss": {
12       "name": "data loss"
13     },
14     "@authentication_bypass": {
15       "name": "authentication bypass"
16     },
17     "@unauthorized_internal_access": {
18       "name": "unauthorized internal access"
19     }
20   },
"""

threats = {}
for cwe in cwes["Weakness_Catalog"]["Weaknesses"]["Weakness"]:
    identifier = create_id(cwe)
    name = create_name(cwe)
    desc = create_description(cwe)
    refs = create_refs(cwe)

    threats[identifier] = {
        "name": name,
        "description": desc,
        "references": refs
    }

now = int(round(time.time() * 1000))
doc = {
    "specification": {
        "version": "0.1.0",
        "name": "ThreatSpec"
    },
    "document": {
        "created": now,
        "updated": now
    },
    "threats": threats
}

print("Writing library to cwe_library.threatspec.json")
with open("cwe_library.threatspec.json", "w") as fh:
    json.dump(doc, fh, indent=2)
