#!/usr/bin/env python

import jsonschema
import json
import sys
import logging
from cli.log import LoggingApp

class ValidatorApp(LoggingApp):
    def main(self):
        self.log.level = logging.INFO

        if self.params.relax >= 1:
            self.log.info("Using relaxed validation. Ignoring additionalProperties errors")
        if self.params.relax >= 2:
            self.log.info("Using very relaxed validation. Ignoring required errors")

        self.log.info("Loading schema file {}".format(self.params.schema))
        with open(self.params.schema) as fh:
            schema = json.load(fh)

        validator = jsonschema.Draft4Validator(schema)
        validation_error_count = 0
        for filename in self.params.files:
            self.log.info("Validating file {}".format(filename))
            with open(filename) as fh:
                data = json.load(fh)
            for error in sorted(validator.iter_errors(data), key=lambda e: e.path):
                if error.validator == "additionalProperties":
                    if self.params.relax >= 1:
                        self.log.info("Ignoring error: {}".format(error.message))
                    else:
                        self.log.warn(error.message)
                        validation_error_count += 1
                elif error.validator == "required":
                    if self.params.relax >= 2:
                        self.log.info("Ignoring error: {}".format(error.message))
                    else:
                        self.log.warn(error.message)
                        validation_error_count += 1
                else:
                    self.log.warn(error.message)
                    validation_error_count += 1

        if validation_error_count > 0:
            self.log.warn("%d problems found" % validation_error_count)
            sys.exit(1)
        else:
            self.log.info("All files validated successfully")

if __name__ == "__main__":
    app = ValidatorApp(
        name="validator.py",
        description="ThreatSpec Schema Validator",
        message_format = '%(asctime)s %(levelname)s: %(message)s'
    )
    app.add_param("-j", "--schema", default="schema.json", help="jsonschema file")
    app.add_param("-r", "--relax", default=0, action="count", help="relax the validation")
    app.add_param("files", action="append", help="files to validate")
    app.run()
