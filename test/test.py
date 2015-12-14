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
        extracted_modules = xym.xym('test-file.txt', './', './', False, False, 0)
        self.assertTrue(len(extracted_modules)==5)
        module_check = ['example-no-error.yang', 'ex-error.yang', 'ex-no-error.yang', 'example-error.yang', 'test-valid.yang']
        for y in module_check:
            self.assertTrue(y in extracted_modules)

    
class TestCase_strict(TestCase_base):
    def runTest(self):
        """Run a test that is the equivalent of:

        xym.py --strict test-file.txt
        """
        extracted_modules = xym.xym('test-file.txt', './', './', True, False, 0)
        self.assertTrue(len(extracted_modules)==3)
        module_check = ['ex-no-error.yang', 'example-error.yang', 'test-valid.yang']
        for y in module_check:
            self.assertTrue(y in extracted_modules)

class TestCase_strict_examples(TestCase_base):
    def runTest(self):
        """Run a test that is the equivalent of:

        xym.py --strict --strict-examples test-file.txt
        """
        extracted_modules = xym.xym('test-file.txt', './', './', True, True, 0)
        self.assertTrue(len(extracted_modules)==1)
        module_check = ['example-no-error.yang']
        for y in module_check:
            self.assertTrue(y in extracted_modules)

