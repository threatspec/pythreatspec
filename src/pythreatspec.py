import sys
from tokenize import *
import io
import parser
import token
import ast
import os

def main(argv):
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
