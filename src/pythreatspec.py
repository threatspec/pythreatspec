import json

db = ThreatSpecDatabase("test.ts")

class ThreatSpecDatabase(object):
    def __init__(self, projectname = "", filename = "test.ts"):
        self.filename = test.ts
        self.ts = {} # a large JSON object

    # TODO: generalize the code below

    def search_for_boundary(self, new_boundary):
        for group in self.ts["boundaries"]:
            if group == self.projectname:
                found = False
                for boundary_id in self.ts["boundaries"][group]:
                    if boundary_id == new_boundary.id:
                        found = True
                        break
                if not found:
                    self.ts["boundaries"][group][new_boundary.id] = new_boundary.toJSON()
                    break

    def search_for_component(self, new_component):
        for group in self.ts["components"]:
            if group == self.projectname:
                found = False
                for component_id in self.ts["boundaries"][group]:
                    if component_id == new_component.id:
                        found = True
                        break
                if not found:
                    self.ts["components"][group][component_id.id] = new_component.toJSON()
                    break

    def insert_boundary(self, boundary):
        pass
        # match = db.search(where('type') == 'mitigates')
        # if len(match) == 0:
        #     data = self.toJSON()
        #     db.insert(data)

    def insert(self, entry):
        if isinstance(entry, boundary):
            self.insert_boundary(entry)
        else:
            pass

class threatmodel(object):
    def __init__(self, filename = "test.ts"):
        global db
        db = TinyDB(filename)

    def __call__(self, f):
        def wrapped_f(*args):
            f(*args)
        return wrapped_f

class JSONEncoder(object):
    def toJSON(self):
        return json.loads(json.dumps(self, default=lambda o: o.__dict__, sort_keys=True))

class mitigates(JSONEncoder):

    mid = 0

    def __init__(self, boundary, component, threat, mitigation, ref = []):
        self.boundary = boundary
        self.component = component
        self.threat = threat
        self.mitigation = mitigation
        self.ref = ref
        self.mid = mitigates.mid
        self.type = "mitigates"
        mitigates.mid += 1

    def __call__(self, f):
        global db
        match = db.search(where('type') == 'mitigates')
        if len(match) == 0:
            data = self.toJSON()
            db.insert(data)

        def wrapped_f(*args):
            f(*args)
        return wrapped_f

class transfers(JSONEncoder):

    tid = 0

    def __init__(self, mitigation, threat, boundary, component, reason, ref = None):
        self.boundary = boundary
        self.component = component
        self.threat = threat
        self.mitigation = mitigation
        self.reason = reason
        self.ref = ref
        self.type = "transfers"
        self.tid = transfers.tid
        transfers.tid += 1

    def __call__(self, f):
        global db
        match = db.search(where('type') == 'transfers')
        if len(match) == 0:
            data = self.toJSON()
            db.insert(data)

        def wrapped_f(*args):
            f(*args)
        return wrapped_f
    pass

class accepts(JSONEncoder):

    aid = 0

    def __init__(self, threat, boundary, component, reason, ref = None):
        self.boundary = boundary
        self.component = component
        self.threat = threat
        self.reason = reason
        self.ref = ref
        self.type = "accepts"
        self.aid = accepts.aid
        accepts.aid += 1

    def __call__(self, f):
        global db
        match = db.search(where('type') == 'accepts')
        if len(match) == 0:
            data = self.toJSON()
            db.insert(data)

        def wrapped_f(*args):
            f(*args)
        return wrapped_f
    pass

class exposes(JSONEncoder):

    eid = 0

    def __init__(self, boundary, component, threat, exposure, ref = None):
        self.boundary = boundary
        self.component = component
        self.threat = threat
        self.exposure = exposure
        self.ref = ref
        self.type = "exposes"
        self.eid = exposes.eid
        exposes.eid += 1

    def __call__(self, f):
        global db
        match = db.search(where('type') == 'exposes')
        if len(match) == 0:
            data = self.toJSON()
            db.insert(data)

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
        self.type = "sends"
        self.sid = sends.sid
        sends.sid += 1

    def __call__(self, f):
        global db
        match = db.search(where('type') == 'sends')
        if len(match) == 0:
            data = self.toJSON()
            db.insert(data)

        def wrapped_f(*args):
            f(*args)
        return wrapped_f
