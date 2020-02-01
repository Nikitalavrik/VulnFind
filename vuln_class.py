
class   Vuln:
    def __init__(self, name, url=None, cve=None, cve_url=None,
                            exploit=None, tp=None, verf=None):
        self.name = name
        self.cve = cve
        self.type = tp
        self.verf = verf
        self.url = url
        self.cve_url = cve_url
        self.exploit = exploit