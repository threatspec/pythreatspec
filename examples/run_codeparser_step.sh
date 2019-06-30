#!/usr/bin/env bash

name=$1

#need to remove the virtualenv from the below block for Dockerfile to run.
echo "Running universal parser for $name"
source ../venv/bin/activate
../universal.py -p "$name" ${name}.go
deactivate

echo "Running mermaid DFD reporting tool"
pushd ../report_dfd
python ./mermaid.py ../examples/cwe_library.threatspec.json "../examples/${name}.threatspec.json" > "../examples/${name}.mermaid"
popd

echo "You can now view ${name}.mermaid"