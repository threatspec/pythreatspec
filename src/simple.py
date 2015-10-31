from test import *
import os
import sys

class Page(object):
    def __init__(self, title, body):
        self.title = title
        self.body = body

    @mitigates("WebApp", "FileSystem", "unauthorized access", "strict file permissions")
    @exposes("WebApp", "FileSystem", "arbitrary file writes", "insufficient path validation")
    @sends("notification email", "WebApp", "App", "User", "Mail Client")
    def save(self):
        filename = self.title + ".txt"
        with open(filename, "r") as handle:
            handle.write(self.body)

@exposes("WebApp", "FileSystem", "arbitrary file reads", "insufficient path validation")
def loadPage(title):
    filename = title + ".txt"
    handle = open(filename, "r")
    data = handle.read()
    return Page(title, data)
