import os
import versioneer
from setuptools import setup

def read(fname):
	return open(os.path.join(os.path.dirname(__file__), fname)).read()

#parse requirements
req_lines = [line.strip() for line in open("requirements.txt").readlines()]
install_reqs = list(filter(None, req_lines))

setup(
  version=versioneer.get_version(),
  cmdclass=versioneer.get_cmdclass(),
  name='xym',
  description = ('A tool to fetch and extract YANG modules from IETF RFCs and Drafts'),
  long_description="xym is a simple tool for fetching and extracting YANG modules from IETF RFCs and drafts as local files and from URLs.",
  packages=['xym'],
  scripts=['bin/xym'],
  author='Jan Medved',
  author_email='jmedved@cisco.com',
  license='New-style BSD',
  url='https://github.com/xym-tool/xym',
  install_requires=install_reqs,
  include_package_data=True,
  keywords=['yang', 'extraction'],
  classifiers=[],
)
