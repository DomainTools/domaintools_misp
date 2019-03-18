from __future__ import absolute_import, unicode_literals, print_function, division
import sys
import logging
from domaintools_misp import base

logger = logging.getLogger(__name__)

class dt_misp_module_iris_import(base.dt_misp_module_base):
    def __init__(self, debug = False):
        self.module_info = {
            'version': '1.8.9',
            'author': 'DomainTools, LLC',
            'description': 'The DomainTools Iris Import module imports domains based on an Iris search hash.',
            'module-type': ['import']
        }
        self.module = {
            'name': 'DomainTools-Iris-Import'
        }
        self.results_limit = 500
        base.dt_misp_module_base.__init__(self)
        self.misp_attributes['input'] = ['data']

        if debug:
            self.log = logging.getLogger('DomainTools Iris Import')
            self.log.setLevel(logging.DEBUG)
            self.ch = logging.StreamHandler(sys.stdout)
            self.ch.setLevel(logging.DEBUG)
            self.formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            self.ch.setFormatter(self.formatter)
            self.log.addHandler(self.ch)
            self.debug = True

    def introspection(self):
        return {'inputSource': ['paste']}

    def version(self):
        self.module_info['config'] = self.module_config
        return self.module_info

    def handler(self, q=False):
        if not q:
            return q

        return self.process_request(q)