"""Python installation definition for misp"""
import os
import re
from setuptools import setup

PACKAGE = 'domaintools_misp'
PACKAGE_PATH = os.path.join(os.path.dirname(__file__), PACKAGE)

with open(os.path.join(PACKAGE_PATH, '__init__.py')) as package_file:
    version_match = re.search(r'''^__version__\s*=\s*['"]([^'"]*)['"]''', package_file.read(), re.M)
    if version_match:
        VERSION = version_match.group(1)
    else:
        raise RuntimeError('No __version__ specified in {}'.format(package_file.name))

setup(name=PACKAGE,
      version=VERSION,
      description='The DomainTools MISP library',
      author='DomainTools',
      author_email='support@domaintools.com',
      url='http://www.domaintools.com/',
      install_requires=['tldextract',
        'python-dateutil',
        'aiohttp',
        'domaintools_api'],
      packages=[PACKAGE])
