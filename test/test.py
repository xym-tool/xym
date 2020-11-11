#!/usr/bin/env python

#
# Let's try and integrate some unittest tests
#

import glob
import os
import unittest

from xym import xym

class TestCase_base(unittest.TestCase):
    def setUp(self):
        for y in glob.glob('*.yang'):
            os.remove(y)
    def tearDown(self):
        for y in glob.glob('*.yang'):
            os.remove(y)
            
class TestCase_default(TestCase_base):
    def runTest(self):
        """Run a test that is the equivalent of:

        xym.py test-file.txt
        """
        extracted_modules = xym.xym('resources/test-file.txt', './', './', strict=False, strict_examples=False,
                                    debug_level=0)
        self.assertTrue(len(extracted_modules)==5)
        module_check = ['example-no-error.yang', 'ex-error.yang', 'ex-no-error.yang', 'example-error.yang', 'test-valid.yang']
        for y in module_check:
            self.assertTrue(y in extracted_modules)

    
class TestCase_strict(TestCase_base):
    def runTest(self):
        """Run a test that is the equivalent of:

        xym.py --strict test-file.txt
        """
        extracted_modules = xym.xym('resources/test-file.txt', './', './', strict=True, strict_examples=False,
                                    debug_level=0)
        self.assertTrue(len(extracted_modules)==3)
        module_check = ['ex-no-error.yang', 'example-error.yang', 'test-valid.yang']
        for y in module_check:
            self.assertTrue(y in extracted_modules)


class TestCase_strict_examples(TestCase_base):
    def runTest(self):
        """Run a test that is the equivalent of:

        xym.py --strict --strict-examples test-file.txt
        """
        extracted_modules = xym.xym('resources/test-file.txt', './', './', strict=True, strict_examples=True,
                                    debug_level=0)
        self.assertTrue(len(extracted_modules)==1)
        module_check = ['example-no-error.yang']
        for y in module_check:
            self.assertTrue(y in extracted_modules)


class TestCase_codeBegins_noFile(TestCase_base):
    def runTest(self):
        """Run a test that is the equivalent of:

        xym.py --strict --strict-examples test-file.txt
        """
        print('startig test')
        extracted_modules = xym.xym('resources/test-file-no-file-after-code-begins', './', './', strict=True,
                                    strict_examples=False, debug_level=0, force_revision_regexp=True)
        print(extracted_modules)
        self.assertTrue(len(extracted_modules)==1)
        module_check = ['ietf-netconf-partial-lock@2009-10-19.yang']
        for y in module_check:
            self.assertTrue(y in extracted_modules)


class TestCase_codeBegins_fileWithSymbol(TestCase_base):
    def runTest(self):
        """Run a test that is the equivalent of:

        xym.py --strict --strict-examples test-file.txt
        """
        extracted_modules = xym.xym('resources/test-file-with-symbol', './', './', strict=True, strict_examples=False,
                                    debug_level=0, force_revision_regexp=True)
        self.assertTrue(len(extracted_modules)==1)
        module_check = ['ietf-netconf-notifications@2012-02-06.yang']
        for y in module_check:
            self.assertTrue(y in extracted_modules)