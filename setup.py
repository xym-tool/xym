import os
from setuptools import setup

def read(fname):
	return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(
  name = 'xym',
  version = '0.2',
  description = ('A tool to extract YANG modules from IETF RFCs and Drafts'),
  long_description=read('README.md'),
  packages = ['xym'],
  scripts = ['bin/xym'],
  author = 'Jan Medved',
  author_email = 'jmedved@cisco.com',
  license = 'New-style BSD',
  url = 'https://github.com/cmoberg/xym',
  install_requires = ['requests>=2.6'],
  include_package_data = True,
  keywords = ['yang', 'extraction'],
  classifiers = [],
)
