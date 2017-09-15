Reference implementation of ThreatSpec.

ThreatSpec is an open source project that aims to close the gap between development and security by bringing the threat modelling process further into the development process. This is achieved by having developers and security engineers write threat specifications alongside code, then dynamically generating reports and data-flow diagrams from the code.

For more information see https://threatspec.org and https://github.com/threatspec

# Installation

Optionally use virtualenv

    $ virtualenv venv
    $ source venv/bin/active

Install using setup.py

    $ python setup.py install

# Usage

## main.py

This is the Python-specific parser. Use it if you're able to annotate your docstrings with ThreatSpec tags as it will capture the source code context of your threat model information.

    $ ./main.py --help
		usage: main.py [-h] [-l LOGFILE] [-q] [-s] [-v] [-p PROJECT] [-o OUT] files

		ThreatSpec Python Parser.

		positional arguments:
			files                 source files to parse

		optional arguments:
			-h, --help            show this help message and exit
			-l LOGFILE, --logfile LOGFILE
														log to file (default: log to stdout)
			-q, --quiet           decrease the verbosity
			-s, --silent          only log warnings
			-v, --verbose         raise the verbosity
			-p PROJECT, --project PROJECT
														project name (default: default)
			-o OUT, --out OUT     output file (default: PROJECT.threatspec.json)

Example

    $ ./main.py -p simple_web examples/simple_web.py

## universal.py

This is a language agnostic universal parser. It will simply parse source code files line by line, looking for ThreatSpec tags. This can get you started quickly for languages that don't have specific parsers, but the universal parser doesn't (currently?) provide the context such as the class or function for where the threat model information occurs. For Python, use this where you cannot add ThreatSpec tags to docstrings.

    $ ./universal.py --help
    usage: universal.py [-h] [-l LOGFILE] [-q] [-s] [-v] [-p PROJECT] [-o OUT]
                        files

    ThreatSpec Universal Parser. Parse TreatSpec tags for any language.

    positional arguments:
      files                 source files to parse

    optional arguments:
      -h, --help            show this help message and exit
      -l LOGFILE, --logfile LOGFILE
                            log to file (default: log to stdout)
      -q, --quiet           decrease the verbosity
      -s, --silent          only log warnings
      -v, --verbose         raise the verbosity
      -p PROJECT, --project PROJECT
                            project name (default: default)
      -o OUT, --out OUT     output file (default: PROJECT.threatspec.json)

Example

    $ ./universal.py -p LAMP_Multi_AZ examples/LAMP_Multi_AZ.py
    2017-05-16T18:40:43 INFO: Parsing file examples/LAMP_Multi_AZ.py
    2017-05-16T18:40:43 INFO: Writing output to LAMP_Multi_AZ.threatspec.json

## validator.py

This tool will validate a threatspec json file against the latest schema () to ensure interoperatbility between different parsers and reporting tools.

    $ ./validator.py --help
    usage: validator.py [-h] [-l LOGFILE] [-q] [-s] [-v] [-j SCHEMA] [-r] files

    ThreatSpec Schema Validator

    positional arguments:
      files                 files to validate

    optional arguments:
      -h, --help            show this help message and exit
      -l LOGFILE, --logfile LOGFILE
                            log to file (default: log to stdout)
      -q, --quiet           decrease the verbosity
      -s, --silent          only log warnings
      -v, --verbose         raise the verbosity
      -j SCHEMA, --schema SCHEMA
                            jsonschema file
      -r, --relax           relax the validation

Example

    $ ./validator.py -j schema/schema.json LAMP_Multi_AZ.threatspec.json
    2017-05-16T18:43:15 INFO: Loading schema file schema/schema.json
    2017-05-16T18:43:15 INFO: Validating file LAMP_Multi_AZ.threatspec.json
    2017-05-16T18:43:15 INFO: All files validated successfully

## cwe_to_threatspec.py

This will take the CWE database XML file () and turn it into a ThreatSpec json file. The generated identifiers can then be used in the threat modelling process.

    $ ./cwe_to_threatspec.py
    Usage: cwe_to_threatspec.py CWE_XML_FILE

Example

    $ ./cwe_to_threatspec.py cwec_v2.10.xml
    Parsing CWE file cwec_v2.10.xml
    Writing library to cwe_library.threatspec.json

# Documentation

Documentation can be found on the Wiki here: https://github.com/threatspec/threatspec/wiki

# Contributing
