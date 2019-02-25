#!/usr/bin/env python

import re
import sys
import xmltodict
import json
import time
import collections
from pprint import pprint

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

def create_category_id(obj):
    name = create_category_name(obj)
    name = re.sub(r'[^a-zA-Z0-9_ \-]', "", name)
    name = re.sub(r'[ \-]', "_", name)
    name = name.lower()
    return "@{}".format(name)

def create_category_name(obj):
    if ":" in obj["@Name"]:
        return obj["@Name"].split(":")[1].strip()
    else:
        return obj["@Name"]

if len(sys.argv) != 2:
    print("Usage: cwe_to_threatspec.py CWE_XML_FILE")
    sys.exit(1)

filename = sys.argv[1]

print("Parsing CWE file {}".format(filename))
with open(filename) as fh:
    cwes = xmltodict.parse(fh.read())

threats = {}

spf_id = ""
spf_categories = {}
for view in cwes["Weakness_Catalog"]["Views"]["View"]:
    if view["@Name"] == "Software Fault Pattern (SFP) Clusters":
        spf_id = view["@ID"]
        for relationship in view["Relationships"]["Relationship"]:
            if relationship["Relationship_Target_Form"] == "Category" and relationship["Relationship_Nature"] == "HasMember":
                lookup_id = relationship["Relationship_Target_ID"]
                spf_categories[lookup_id] = ""

category_map = {}

for category in cwes["Weakness_Catalog"]["Categories"]["Category"]:
    category_id = create_category_id(category)
    category_name = create_category_name(category)

    identifier = category["@ID"]
    category_map[identifier] = {
        "id": category_id,
        "name": category_name
    }

    if identifier in spf_categories:
        # Top level categories
        spf_categories[identifier] = category_id
        threats[category_id] = {
            "name": category_name,
            "parent": "@sfp",
            "refs": [identifier]
        }

for category in cwes["Weakness_Catalog"]["Categories"]["Category"]:
    if "Relationships" in category:
        # Sub-categories
        relationship = category["Relationships"]["Relationship"]
        if not isinstance(relationship, collections.OrderedDict): 
            continue 
        if isinstance(relationship["Relationship_Views"]["Relationship_View_ID"], list):
            views = relationship["Relationship_Views"]["Relationship_View_ID"]
        else:
            views = [relationship["Relationship_Views"]["Relationship_View_ID"]]

        for view in views:
            if view["#text"] == spf_id:
                identifier = category["@ID"]
                category_id = category_map[identifier]["id"]
                category_name = category_map[identifier]["name"]
                parent_identifier = relationship["Relationship_Target_ID"]
                parent_id = category_map[parent_identifier]["id"]

                spf_categories[identifier] = category_id

                threats[category_id] = {
                    "name": category_name,
                    "parent": parent_id,
                    "refs": [identifier]
                }

for cwe in cwes["Weakness_Catalog"]["Weaknesses"]["Weakness"]:
    sfp_category_id = ""
    if "Relationships" in cwe and "Relationship" in cwe["Relationships"]:
        for relationship in cwe["Relationships"]["Relationship"]:
            if isinstance(relationship, collections.OrderedDict) and relationship["Relationship_Target_Form"] == "Category" and relationship["Relationship_Nature"] == "ChildOf" and relationship["Relationship_Target_ID"] in spf_categories:
                sfp_category_id = spf_categories[relationship["Relationship_Target_ID"]]
                break

    if not sfp_category_id:
        continue

    identifier = create_id(cwe)
    name = create_name(cwe)
    desc = create_description(cwe)
    refs = create_refs(cwe)
    parent = sfp_category_id

    threats[identifier] = {
        "name": name,
        "description": desc,
        "references": refs,
        "parent": parent
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

print("Writing library to sfp_library.threatspec.json")
with open("sfp_library.threatspec.json", "w") as fh:
    json.dump(doc, fh, indent=2)
