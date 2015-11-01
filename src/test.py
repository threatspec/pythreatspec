import json

_THREATSPEC_FILE = "code.threatspec"

class threatmodel(object):
    def __init__(self, filename):
        global _THREATSPEC_FILE
        _THREATSPEC_FILE = filename
        self.filename = filename

    def __call__(self, f):
        def wrapped_f(*args):
            f(*args)
        return wrapped_f

class mitigates(object):

    def __init__(self, boundary, component, threat, mitigation, ref = []):
        self.boundary = boundary
        self.component = component
        self.threat = threat
        self.mitigation = mitigation
        self.ref = ref

    def toJSON(self):
        data = [ { 'boundary': self.boundary, 'component': self.component, 'threat': self.threat, 'mitigation' : self.mitigation, 'ref' : self.ref } ]
        return json.dumps(data)

    def __call__(self, f):
        def wrapped_f(*args):
            f(*args)
        return wrapped_f

class transfers(object):
    def __init__(self, mitigation, threat, boundary, component, reason, ref = None):
        self.boundary = boundary
        self.component = component
        self.threat = threat
        self.mitigation = mitigation
        self.reason = reason
        self.ref = ref

    def __call__(self, f):
        # TODO: do stuff with the arguments
        def wrapped_f(*args):
            f(*args)
        return wrapped_f
    pass

class accepts(object):
    def __init__(self, threat, boundary, component, reason, ref = None):
        self.boundary = boundary
        self.component = component
        self.threat = threat
        self.reason = reason
        self.ref = ref

    def __call__(self, f):
        # TODO: do stuff with the arguments
        def wrapped_f(*args):
            f(*args)
        return wrapped_f
    pass

class exposes(object):
    def __init__(self, boundary, component, threat, exposure, ref = None):
        self.boundary = boundary
        self.component = component
        self.threat = threat
        self.exposure = exposure
        self.ref = ref

    def __call__(self, f):
        # TODO: do stuff with the arguments
        def wrapped_f(*args):
            f(*args)
        return wrapped_f
    pass

class sends(object):
    def __init__(self, message, srcboundary, srccomponent, dstboundary, dstcomponent):
        self.message = message
        self.srcboundary = srcboundary
        self.srccomponent = srccomponent
        self.dstboundary = dstboundary
        self.dstcomponent = dstcomponent

    def __call__(self, f):
        def wrapped_f(*args):
            f(*args)
        return wrapped_f

# TODO: write some test functions here that mimic the Go code
# TODO: what is a good form for the IR? I think a big JSON description is OK--a list of functions, where each one has some of these attributes, and functions reference one another
# the JSON output also contains a list of THREATS, EXPOSURES, REFERENCES, BOUNDARIES, and COMPONENTS
# could easily put this into a relational database too... and then the parser just builds on that database
# I'll start with the JSON output since it's easy to parse and move around
