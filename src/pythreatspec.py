import json
import inspect

# TODO: awful. fix this.
def name_to_key(name):
    return "@" + name

class ThreatSpecDatabase(object):
    def __init__(self, projectname = "", filename = "test.ts"):
        self.projectname = projectname
        self.filename = filename
        self.ts = {} # a large JSON object

        self.ts["metadata"] = {}
        self.ts["boundaries"] = {}
        self.ts["components"] = {}
        self.ts["threats"] = {}
        self.ts["projects"] = {}

    def __del__(self):
        print json.dumps(self.ts)

    def contains_project(self, project):
        return project in self.ts["projects"]

    def add_new_project(self, project):
        self.ts["projects"][project] = {}
        self.ts["projects"][project]["mitigations"] = {}
        self.ts["projects"][project]["exposures"] = {}
        self.ts["projects"][project]["transfers"] = {}
        self.ts["projects"][project]["acceptances"] = {}

    # TODO: generalize the code for "search and insert" below

    def add_mitigation(self, project, mitigation):
        key = name_to_key(mitigation.mitigation)
        self.ts["projects"][project]["mitigations"][key] = mitigation.toJSON()

    def search_for_boundary(self, new_boundary):
        found = False
        new_boundary_id = name_to_key(new_boundary.name)
        for boundary_id in self.ts["boundaries"]:
            if boundary_id == new_boundary_id:
                return True
        if not found:
            self.ts["boundaries"][new_boundary_id] = new_boundary.toJSON()
            return False

    def search_for_component(self, new_component):
        found = False
        new_component_id = name_to_key(new_component.name)
        for component_id in self.ts["components"]:
            if component_id == new_component_id:
                return True
        if not found:
            self.ts["components"][new_component_id] = new_component.toJSON()
            return False

    def search_for_sends(self, new_sends):
        pass

    def search_for_mitigates(self, new_mitigates):
        if not self.contains_project(self.projectname):
            self.add_new_project(self.projectname)
        self.add_mitigation(self.projectname, new_mitigates)

    def insert_boundary(self, new_boundary):
        print "insert_boundary %s" % (new_boundary.toJSON())
        self.search_for_boundary(new_boundary)

    def insert_component(self, new_component):
        print "insert_component %s" % (new_component.toJSON())
        self.search_for_component(new_component)

    def insert_mitigates(self, new_mitigates):
        print "insert_mitigates %s" % (new_mitigates.toJSON())
        self.search_for_mitigates(new_mitigates)
        pass

    def insert_sends(self, new_sends):
        print "insert_sends %s" % (new_sends.toJSON())
        self.search_for_sends(new_sends)

    def insert(self, entry):
        self.insert_boundary(boundary(entry.boundary))
        self.insert_component(component(entry.component))
        # self.insert_threat(entry.threat)

        if isinstance(entry, sends):
            self.insert_sends(entry)
        elif isinstance(entry, mitigates):
            self.insert_mitigates(entry)

db = ThreatSpecDatabase("ProjectA", "test.ts")

class threatmodel(object):
    def __init__(self, filename = "test.ts"):
        global db

    def __call__(self, f):
        def wrapped_f(*args):
            f(*args)
        return wrapped_f

class JSONEncoder(object):
    def toJSON(self):
        return json.loads(json.dumps(self, default=lambda o: o.__dict__, sort_keys=True))

class boundary(JSONEncoder):
    def __init__(self, name):
        self.name = name

class component(JSONEncoder):
    def __init__(self, name):
        self.name = name

class threat(JSONEncoder):
    def __init__(self, identifier, reference = ""):
        self.name = identifier
        self.reference = reference

class mitigates(JSONEncoder):
    def __init__(self, boundary_id, component_id, threat, mitigation, ref = []):
        self.boundary = boundary_id
        self.component = component_id
        self.threat = threat
        self.mitigation = mitigation
        self.ref = ref

    def __call__(self, f):
        callerframerecord = inspect.stack()[1]
        frame = callerframerecord[0] # second one on the stack
        info = inspect.getframeinfo(frame)

        self.source = {"function":f.__name__, "file": info.filename, "line": info.lineno}

        global db
        db.insert(self)

        def wrapped_f(*args):
            f(*args)

        return wrapped_f

class transfers(JSONEncoder):

    tid = 0
    def __init__(self, mitigation, threat, boundary_id, component_id, reason, ref = None):
        self.boundary = boundary_id
        self.component = component_id
        self.threat = threat
        self.mitigation = mitigation
        self.reason = reason
        self.ref = ref
        self.id = transfers.tid
        transfers.tid += 1

    def __call__(self, f):
        # global db
        # match = db.search(where('type') == 'transfers')
        # if len(match) == 0:
        #     data = self.toJSON()
        #     db.insert(data)

        def wrapped_f(*args):
            f(*args)
        return wrapped_f
    pass

class accepts(JSONEncoder):

    aid = 0
    def __init__(self, threat, boundary_id, component_id, reason, ref = None):
        self.boundary = boundary_id
        self.component = component_id
        self.threat = threat
        self.reason = reason
        self.ref = ref
        self.id = accepts.aid
        accepts.aid += 1

    def __call__(self, f):
        # global db
        # match = db.search(where('type') == 'accepts')
        # if len(match) == 0:
        #     data = self.toJSON()
        #     db.insert(data)

        def wrapped_f(*args):
            f(*args)
        return wrapped_f
    pass

class exposes(JSONEncoder):

    eid = 0
    def __init__(self, boundary_id, component_id, threat, exposure, ref = None):
        self.boundary = boundary_id
        self.component = component_id
        self.threat = threat
        self.exposure = exposure
        self.ref = ref
        self.id = exposes.eid
        exposes.eid += 1

    def __call__(self, f):
        # global db
        # match = db.search(where('type') == 'exposes')
        # if len(match) == 0:
        #     data = self.toJSON()
        #     db.insert(data)

        def wrapped_f(*args):
            f(*args)
        return wrapped_f
    pass

class sends(JSONEncoder):

    sid = 0
    def __init__(self, message, srcboundary, srccomponent, dstboundary, dstcomponent):
        self.message = message
        self.srcboundary = srcboundary
        self.srccomponent = srccomponent
        self.dstboundary = dstboundary
        self.dstcomponent = dstcomponent
        self.id = sends.sid
        sends.sid += 1

    # def boundaries(self):
    #     boundaries = [self.srcboundary, self.dstboundary]
    #     for b in boundaries:
    #         yield b

    def __call__(self, f):
        global db
        db.insert(self)
        # match = db.search(where('type') == 'sends')
        # if len(match) == 0:
        #     data = self.toJSON()
        #     db.insert(data)

        def wrapped_f(*args):
            f(*args)
        return wrapped_f
