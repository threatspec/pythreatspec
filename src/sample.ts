{
    "boundaries": {
        "Project A": {
            "0": {
                "name": "WebApp"
            },
            "1": {
                "name": "User"
            }
        }
    },
    "components": {
        "Project A": {
            "0": {
                "name": "FileSystem"
            },
            "1": {
                "name": "MailClient"
            },
            "2": {
                "name": "App"
            }
        }
    },
    "models": {
        "Project A": {
            "exposes": {
                "0": {
                    "boundary": 0,
                    "component": 0,
                    "exposure": "insufficient path validation",
                    "ref": [],
                    "threat": "@cwe_xxx_yyy"
                }
            },
            "sends": {
                "0": {
                    "dstboundary": 1,
                    "dstcomponent": 1,
                    "message": "notification email",
                    "srcboundary": 0,
                    "srccomponent": 2
                }
            },
            "mitigates": {
                "0": {
                    "boundary": 0,
                    "component": 0,
                    "mitigation": "strict file permissions",
                    "ref": [],
                    "threat": "@cwe_xxx_zzz"
                }
            }
        },
        "Project B": {}
    },
    "threats": {
        "@cwe_xxx_yyy": "XXX YYY",
        "@cwe_xxx_zzz": "XXX ZZZ"
    }
}
