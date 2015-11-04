from pythreatspec import *
import os
import sys

class Page(object):
    def __init__(self, title):
        self.title = title
        self.data = None

    @mitigates("WebApp", "FileSystem", "unauthorized access", "strict file permissions")
    @exposes("WebApp", "FileSystem", "arbitrary file writes", "insufficient path validation")
    @sends("notification email", "WebApp", "App", "User", "Mail Client")
    def save(self):
        filename = self.title
        if self.data != None:
            with open(filename, "w") as handle:
                handle.write(self.body)

    @exposes("WebApp", "FileSystem", "arbitrary file reads", "insufficient path validation")
    def load(self):
        filename = self.title
        handle = open(filename, "r")
        data = handle.read()
        self.data = data

if __name__ == "__main__":
    page = Page("simple.py")
    page.load()
    # page.save()
