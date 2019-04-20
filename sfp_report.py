#!/usr/bin/env python

import sys
import json
import logging
from cli.log import LoggingApp
from pprint import pprint

class SfpReportApp(LoggingApp):
    def main(self):
        self.log.level = logging.INFO

        data = {}

        for filename in self.params.files:
            with open(filename) as fh:
                data.update(json.load(fh))

        sfp_map = {}
        for threat_id, threat in data["threats"].items():
            if "parent" in threat:
                if threat["parent"] not in sfp_map:
                    sfp_map[threat["parent"]] = {}
                sfp_map[threat["parent"]][threat_id] = threat

        for threat_id, threat in sfp_map["@sfp"].items():
            print(threat_id)
            for subthreat_id, subthreat in threat.items():
                print(("  %s" % subthreat_id))


        sys.exit(0)












        # this sucks


        if self.params.top:
            for category_id, category in sfp_data.items():
                print("%-30s %s" % (category["name"], category_id))
        elif self.params.list:
            for category_id, category in sfp_data.items():
                print("*******************************************************")
                print("* %s" % category["name"])
                print("*******************************************************\n")
                for threat_id, threat in category["children"].items():
                    if threat["children"]:
                        print("* %s" % threat["name"])
                        for subthreat_id, subthreat in threat["children"].items():
                            print("- %s\n  %s\n" % (subthreat["name"], subthreat_id))
                    else:
                        print("- %s\n  %s\n" % (threat["name"], threat_id))


if __name__ == "__main__":
    app = SfpReportApp(
        name="sfp_report.py",
        description="ThreatSpec Software Fault Pattern reporting",
        message_format = '%(asctime)s %(levelname)s: %(message)s'
    )
    app.add_param("--top", action="store_true", help="list top level categories")
    app.add_param("--list", action="store_true", help="list SFP threats")
    app.add_param("--report", action="store_true", help="run report")
    app.add_param("files", action="append", help="files to report")
    app.run()
