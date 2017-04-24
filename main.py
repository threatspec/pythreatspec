#!/usr/bin/env python

import sys
import json
import logging
from cli.log import LoggingApp
from pythreatspec import pythreatspec as ts

class PythonParserApp(LoggingApp):
    def main(self):
        self.log.level = logging.INFO
        if self.params.out:
            outfile = self.params.out
        else:
            outfile = "{}.threatspec.json".format(self.params.project)

        parser = ts.PyThreatspecParser()
        for f in self.params.files:
            self.log.info("Parsing file {}".format(f))
            parser.parse(f)

        reporter = ts.PyThreatspecReporter(parser, self.params.project)
        self.log.info("Writing output to {}".format(outfile))
        with open(outfile, "w") as fh:
            json.dumps(fh, reporter.export_to_json(), indent=2, separators=(',', ': '))

if __name__ == "__main__":
    app = PythonParserApp(
        name="main.py",
        description="ThreatSpec Python Parser.",
        message_format = '%(asctime)s %(levelname)s: %(message)s',
    )
    app.add_param("-p", "--project", default="default", help="project name (default: default)")
    app.add_param("-o", "--out", default=None, help="output file (default: PROJECT.threatspec.json)")
    app.add_param("files", action="append", help="source files to parse")
    app.run()
