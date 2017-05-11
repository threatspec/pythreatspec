#!/usr/bin/env python

import sys
import json
import re
import logging
from cli.log import LoggingApp
from pythreatspec import pythreatspec as ts

class UniversalParserApp(LoggingApp):
    def parse_file(self, filename):
        with open(filename) as fh:
            line_no = 0
            for line in fh.readlines():
                line = line.strip()
                self.parser._parse_comment(line, ts.PTSSource(filename, line_no, "universal_parser"))
                line_no += 1

    def main(self):
        self.log.level = logging.INFO
        if self.params.out:
            outfile = self.params.out
        else:
            outfile = "{}.threatspec.json".format(self.params.project)

        self.parser = ts.PyThreatspecParser()
        comments = ['//', '/*', '#', '"""', '\'\'\'']
        tags = ['alias','describe','connects','review','mitigates','exposes','transfers','accepts']
        self.parser.tag_regex = "^\s*(?:{})*\s*(@(?:{})).*$".format('|'.join(map(lambda c: re.escape(c), comments)), '|'.join(map(lambda t: re.escape(t), tags)))

        for f in self.params.files:
            self.log.info("Parsing file {}".format(f))
            self.parse_file(f)

        reporter = ts.PyThreatspecReporter(self.parser, self.params.project)
        from pprint import pprint

        self.log.info("Writing output to {}".format(outfile))
        with open(outfile, "w") as fh:
            json.dump(reporter.export_to_json(), fh, indent=2, separators=(',', ': '))

if __name__ == "__main__":
    app = UniversalParserApp(
        name="universal.py",
        description="ThreatSpec Universal Parser. Parse TreatSpec tags for any language.",
        message_format = '%(asctime)s %(levelname)s: %(message)s'
    )
    app.add_param("-p", "--project", default="default", help="project name (default: default)")
    app.add_param("-o", "--out", default=None, help="output file (default: PROJECT.threatspec.json)")
    app.add_param("files", action="append", help="source files to parse")
    app.run()
