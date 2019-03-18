from __future__ import absolute_import, unicode_literals, print_function, division
import sys
import logging
from domaintools_misp import base

logger = logging.getLogger(__name__)

class dt_misp_module_iris_analyze(base.dt_misp_module_base):

    def __init__(self, debug = False):
        self.module_info = {
            'version': '1.8.9',
            'author': 'DomainTools, LLC',
            'description': 'The DomainTools Iris Analyze module is Optimized for MISP hover-actions, but can also be used for expansions. It provides to do.',
            'module-type': ['hover']
        }
        self.module = {
            'name': 'DomainTools-Iris-Analyze'
        }
        base.dt_misp_module_base.__init__(self)
        self.misp_attributes['input'] = ['domain']

    def handler(self, q=False):
        if not q:
            return q

        return self.process_request(q)

    def introspection(self):
        return self.misp_attributes

    def version(self):
        self.module_info['config'] = self.module_config
        return self.module_info