import sys
from tokenize import *
import time
import io
import parser
import token
import ast
import os
import re

def current_milli_time():
    return int(round(time.time() * 1000))

# PTSNode_Alias = 1
#
# class PyThreatspecAliasNode():
#     def __init__(self, line):
#         pass

class PyThreatspecReporter(object):
    def __init__(self, parser):
        pass # add functions for ToJson and the like

class PyThreatspecParser(object):
    def __init__(self):
        thetime = current_milli_time()
        self.creation_time = thetime
        self.updated_time = thetime
        self.boundaries = []
        self.components = []
        self.threats = []
        self.projects = []

        self.node_regex = r'^@(?:alias|describe|mitigates|exposes|transfers|accepts).*$'

    def _parse_comment(self, comment):
        for match in re.findall(self.node_regex, comment, re.M | re.I): # multiline and ignore case
            # TODO
            print "parse here: %s" % (match)


    def _parse_classes(self, module):
        class_definitions = [node for node in module.body if isinstance(node, ast.ClassDef)]
        for class_def in class_definitions:
            # print class_def.name
            # print(ast.get_docstring(class_def))
            self._parse_comment(ast.get_docstring(class_def))

    def _parse_methods(self, classmodule):
        for node in ast.iter_child_nodes(class_def):
            if isinstance(node, ast.FunctionDef):
                # print "Method: %s" % (node.name)
                self._parse_comment(ast.get_docstring(node))

    def _parse_functions(self, module):
        function_definitions = [node for node in module.body if isinstance(node, ast.FunctionDef)]
        for func in function_definitions:
            # print(f.name)
            # print(ast.get_docstring(f))
            self._parse_comment(ast.get_docstring(func))

    def parse(self, filename):
        ast_filename = os.path.splitext(filename)[0] + '.py'
        with open(ast_filename, 'r') as fd:
            file_contents = fd.read()
        module = ast.parse(file_contents)

        self._parse_classes(module)
        self._parse_functions(module)

    def export(self):
        return None
        # return self.ts

def main(argv):
    parser = PyThreatspecParser()
    parser.parse(argv[0])
    print parser.export()

def test(argv):
    with open(argv[0], "r") as fh:
        g = generate_tokens(fh.readline)
        for toknum, tokval, lineno, colno, content in g:
            print toknum, tokval, token.tok_name[toknum]
            if toknum == COMMENT:
                print toknum, tokval

    # with open(argv[0], "r") as fh:
    #     print parser.compile(fh.read())

    ast_filename = os.path.splitext(argv[0])[0] + '.py'
    with open(ast_filename, 'r') as fd:
        file_contents = fd.read()
    module = ast.parse(file_contents)
    function_definitions = [node for node in module.body if isinstance(node, ast.FunctionDef)]
    print [f.name for f in function_definitions]
    for f in function_definitions:
        print('---')
        print(f.name)
        print('---')
        print(ast.get_docstring(f))

    class_definitions = [node for node in module.body if isinstance(node, ast.ClassDef)]
    method_definitions = []

    for class_def in class_definitions:
        print(ast.get_docstring(class_def))
        print class_def.name
        for node in ast.iter_child_nodes(class_def):
            print node
            if isinstance(node, ast.FunctionDef):
                print "Method: %s" % (node.name)

        # method_definitions.append([node for node in class_def if isinstance(node, ast.FunctionDef)])
        # print(ast.get_docstring(method_definitions[-1]))

if __name__ == "__main__":
    main(sys.argv[1:])
