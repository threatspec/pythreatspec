#!/usr/bin/env bash

if [ ${1: -14} == "_components.py" ]; then
  name=${1:0:16}
else
  name=$1
fi

echo "Running universal parser for $name"
source ../venv/bin/activate
../universal.py -p "$name" ${name}_*.py
deactivate

echo "Running mermaid DFD reporting tool"
pushd ../../report_dfd
source venv/bin/activate
./mermaid.py ../pythreatspec/examples/cwe_library.threatspec.json "../pythreatspec/tutorial/${name}.threatspec.json" > "../pythreatspec/tutorial/${name}.mermaid"
deactivate
popd

echo "Generating PNG using mermaid"
mermaid -w 1871 "${name}.mermaid"

echo "You can now view ${name}.mermaid.png"
