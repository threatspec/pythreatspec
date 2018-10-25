#!/usr/bin/env python

from cli.log import LoggingApp
import yaml
import json
import logging
from pythreatspec import pythreatspec as ts


class OpenapiParserApp(LoggingApp):

    def parse_field(self, key, data):
        field_type = key[13:]
        self.parser._parse_comment("@{} {}".format(field_type, data), ts.PTSSource())

    def parse_openapi(self, data):
        if isinstance(data, dict):
            for key in data.keys():
                if key.startswith("x-threatspec"):
                    self.parse_field(key, data[key])
                else:
                    self.parse_openapi(data[key]) 
        elif isinstance(data, list):
            for a in data:
                self.parse_openapi(a)

    def parse_file(self, filename):
        with open(filename, 'r') as fh:
            self.parse_openapi(yaml.load(fh))
        
        # Parse yaml or json files using pynaml
        # Recursively look for x-threatspec fields as children
        # Create a PTSSource object from parent
        # For each x-threatspec child
        # call self.parser._parse_comment()
        pass

    def main(self):
        self.log.level = logging.INFO

        if self.params.out:
            outfile = self.params.out
        else:
            outfile = "{}.threatspec.json".format(self.params.project)
        self.parser = ts.PyThreatspecParser()
        
        for f in self.params.files:
            self.log.info("Parsing file {}".format(f))
            self.parse_file(f)

        reporter = ts.PyThreatspecReporter(self.parser, self.params.project)
        self.log.info("Writing output to {}".format(outfile))

        with open(outfile, "w") as fh:
            json.dump(reporter.export_to_json(), fh, indent=2, separators=(',', ': '))

if __name__ == "__main__":
    app = OpenapiParserApp(
        name="openapi.py",
        description="ThreatSpec OpenAPI parser.",
        message_format='%(asctime)s %(levelname)s: %(message)s'
    )
    app.add_param("-p", "--project", default="default", help="project name (default: default)")
    app.add_param("-o", "--out", default=None, help="output file (default: PROJECT.threatspec.json)")
    app.add_param("files", action="append", help="openapi files to parse")
    app.run()
