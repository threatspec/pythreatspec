#!/usr/bin/env bash

echo "Running universal parser for $1"
source ../venv/bin/activate
../universal.py -p "$1" ${1}_*.py
deactivate

echo "Running mermaid DFD reporting tool"
pushd ../../report_dfd
source venv/bin/activate
./mermaid.py ../pythreatspec/examples/cwe_library.threatspec.json "../pythreatspec/tutorial/${1}.threatspec.json" > "../pythreatspec/tutorial/${1}.mermaid"
deactivate
popd

echo "Generating PNG using mermaid"
mermaid -w 1871 "${1}.mermaid"

echo "You can now view ${1}.mermaid.png"
