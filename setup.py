#!/usr/bin/env python
"""setup.py"""

import sys

from setuptools import setup, find_namespace_packages
from subprocess import check_output
from os.path import isdir

if isdir("../.git") or isdir(".git"): # debian source tarballs don't contain .git
    version_cmd = "git describe --tags --always --long"
    version = check_output(version_cmd.split(" ")).decode().strip()
    print("Working on git version {}".format(version))
    # enforce https://www.python.org/dev/peps/pep-0440
    items = version[1:].split('-')
    if len(items) == 3:
        version = '{}+{}'.format(items[0], items[2][1:])
    print("--> PEP-0440 version will be {}".format(version))
else:
    version = "undefined"

if {'pytest', 'test', 'ptr'}.intersection(sys.argv):
    pytestRunner = ['pytest-runner']
else:
    pytestRunner = []

setup(name='support-diagnostics',
      version=version,
      description='Support Diagnostics.',
      long_description='''Analyze live Untangle system and produce report.''',
      author='Untangle.',
      author_email='cblaise@untangle.com',
      url='https://untangle.com',
      scripts=['bin/support-diagnostics'],
      packages=(
          find_namespace_packages()
      ),
      install_requires=['urllib3'],
      license='GPL',
      setup_requires=pytestRunner,
      tests_require=[
        "pytest",
        "pytest-cov"
      ],
      #      test_suite='',
      #      cmdclass={'test': PyTest},
      classifiers=[
          'Development Status :: 5 - Production/Stable',
          'License :: OSI Approved :: General Public License v2 (GPL-2)',
          'Environment :: Console',
          'Operating System :: POSIX',
          'Intended Audience :: Developers',
          'Programming Language :: Python :: 3',
          'Programming Language :: Python :: 3.6',
          'Programming Language :: Python :: 3.7',
          'Programming Language :: Python :: 3.8',
          'Programming Language :: Python :: 3.9'
      ])
