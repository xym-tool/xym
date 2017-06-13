#!/usr/bin/env python
from __future__ import print_function  # Must be at the beginning of the file
import argparse
from collections import Counter
import os.path
import os
import sys
import re
import requests
from requests.packages.urllib3 import disable_warnings

__author__ = 'jmedved@cisco.com, calle@tail-f.com, bclaise@cisco.com, einarnn@gmail.com'
__copyright__ = "Copyright(c) 2015, 2016, 2017 Cisco Systems, Inc."
__license__ = "New-style BSD"
__email__ = "jmedved@cisco.com"
__version__ = "0.3.2"

if sys.version_info < (2, 7, 9):
    disable_warnings()


def hexdump(src, length=16, sep='.'):
    """
    Hexdump function by sbz and 7h3rAm on Github:
    (https://gist.github.com/7h3rAm/5603718).
    :param src: Source, the string to be shown in hexadecimal format
    :param length: Number of hex characters to print in one row
    :param sep: Unprintable characters representation
    :return:
    """
    filtr = ''.join([(len(repr(chr(x))) == 3) and chr(x) or sep for x in range(256)])
    lines = []
    for c in xrange(0, len(src), length):
        chars = src[c:c+length]
        hexstring = ' '.join(["%02x" % ord(x) for x in chars])
        if len(hexstring) > 24:
            hexstring = "%s %s" % (hexstring[:24], hexstring[24:])
        printable = ''.join(["%s" % ((ord(x) <= 127 and filtr[ord(x)]) or sep) for x in chars])
        lines.append("     %02x:  %-*s  |%s|\n" % (c, length*3, hexstring, printable))
    print(''.join(lines))


def finalize_model(input_model):
    """
    Extracts string from the model data. This function is always the last
    stage in the model post-processing pipeline.
    :param input_model: Model to be processed
    :return: list of strings, ready to be written to a module file
    """
    finalized_output = []
    for mline in input_model:
        finalized_output.append(mline[0])
    return finalized_output


class YangModuleExtractor:
    """
    Extract YANG modules from IETF RFC or draft text string.
    """
    MODULE_STATEMENT = re.compile('''^[ \t]*(sub)?module +(["'])?([-A-Za-z0-9]*(@[0-9-]*)?)(["'])? *\{.*$''')
    PAGE_TAG = re.compile('.*\[Page [0-9]*\].*')
    CODE_ENDS_TAG = re.compile('^[ \t]*<CODE ENDS>.*$')
    CODE_BEGINS_TAG = re.compile('^[ \t]*<CODE BEGINS>( *file( +"(.*)")?)?.*$')
    EXAMPLE_TAG = re.compile('^(example-)')

    def __init__(self, src_id, dst_dir, strict=True, strict_examples=True, add_line_refs=False, debug_level=0):
        """
        Initializes class-global variables.
        :param src_id: text string containing the draft or RFC text from which YANG
                      module(s) are to be extracted
        :param dst_dir: Directory where to put the extracted YANG module(s)
        :param strict: Mode - if 'True', enforce <CODE BEGINS> / <CODE ENDS>;
                       if 'False', just look for 'module <name> {' and '}'
        :param strict_examples: Only output valid examples when in strict mode
        :param debug_level: If > 0 print some debug statements to the console
        :return:
        """
        self.src_id = src_id
        self.dst_dir = dst_dir
        self.strict = strict
        self.strict_examples = strict_examples
        self.add_line_refs = add_line_refs
        self.debug_level = debug_level
        self.max_line_len = 0
        self.extracted_models = []

    def warning(self, s):
        """
        Prints out a warning message to stderr.
        :param s: The warning string to print
        :return: None
        """
        print("   WARNING: '%s', %s" % (self.src_id, s), file=sys.stderr)

    def error(self, s):
        """
        Prints out an error message to stderr.
        :param s: The error string to print
        :return: None
        """
        print("   ERROR: '%s', %s" % (self.src_id, s), file=sys.stderr)

    def get_extracted_models(self):
        return self.extracted_models

    def remove_leading_spaces(self, input_model):
        """
        This function is a part of the model  post-processing pipeline. It
        removes leading spaces from an extracted module; depending on the
        formatting of the draft/rfc text, may have multiple spaces prepended
        to each line. The function also determines the length of the longest
        line in the module - this value can be used by later stages of the
        model post-processing pipeline.
        :param input_model: The yang model to be processed
        :return: YANG model lines with leading spaces removed
        """
        leading_spaces = 1024
        output_model = []
        for mline in input_model:
            line = mline[0]
            if line.rstrip(' \r\n') != '':
                leading_spaces = min(leading_spaces, len(line) - len(line.lstrip(' ')))
                output_model.append([line[leading_spaces:], mline[1]])

                line_len = len(line[leading_spaces:])
                if line_len > self.max_line_len:
                    self.max_line_len = line_len
            else:
                output_model.append(['\n', mline[1]])
        return output_model

    def add_line_references(self, input_model):
        """
        This function is a part of the model post-processing pipeline. For
        each line in the module, it adds a reference to the line number in
        the original draft/RFC from where the module line was extracted.
        :param input_model: The yang model to be processed
        :return: Modified yang model, where line numbers from the RFC/Draft
                 text file are added as comments at the end of each line in
                 the modified model
        """
        output_model = []
        for ln in input_model:
            line_len = len(ln[0])
            line_ref = ('// %4d' % ln[1]).rjust((self.max_line_len - line_len + 7), ' ')
            new_line = '%s %s\n' % (ln[0].rstrip(' \r\n\t\f'), line_ref)
            output_model.append([new_line, ln[1]])
        return output_model

    def remove_extra_empty_lines(self, input_model):
        """
        Removes superfluous newlines from a YANG model that was extracted
        from a draft or RFC text. Newlines are removed whenever 2 or more
        consecutive empty lines are found in the model. This function is a
        part of the model post-processing pipeline.
        :param input_model: The yang model to be processed
        :return: YANG model with superfluous newlines removed
        """
        ncnt = 0
        output_model = []
        for ln in input_model:
            if ln[0].strip(' \n\r') is '':
                if ncnt is 0:
                    output_model.append(ln)
                elif self.debug_level > 1:
                        self.debug_print_strip_msg(ln[1] - 1, ln[0])
                ncnt += 1
            else:
                output_model.append(ln)
                ncnt = 0
        if self.debug_level > 0:
            print('   Removed %d empty lines' % (len(input_model) - len(output_model)))
        return output_model

    def post_process_model(self, input_model, add_line_refs):
        """
        This function defines the order and execution logic for actions
        that are performed in the model post-processing pipeline.
        :param input_model: The yang model to be processed in the pipeline
        :param add_line_refs: Flag that controls whether line number
            references should be added to the model.
        :return: List of strings that constitute the final yang model to
            be written to its module file.
        """
        intermediate_model = self.remove_leading_spaces(input_model)
        intermediate_model = self.remove_extra_empty_lines(intermediate_model)
        if add_line_refs:
            intermediate_model = self.add_line_references(intermediate_model)
        return finalize_model(intermediate_model)

    def write_model_to_file(self, mdl, fn):
        """
        Write a YANG model that was extracted from a source identifier
        (URL or source .txt file) to a .yang destination file
        :param mdl: YANG model, as a list of lines
        :param fn: Name of the YANG model file
        :return:
        """
        # Write the model to file
        output = ''.join(self.post_process_model(mdl, self.add_line_refs))
        if fn:
            fqfn = self.dst_dir + '/' + fn
            if os.path.isfile(fqfn):
                self.error("File '%s' exists" % fqfn)
                return
            with open(fqfn, 'w') as of:
                of.write(output)
                of.close()
                self.extracted_models.append(fn)
        else:
            self.error("Output file name can not be determined; YANG file not created")

    def debug_print_line(self, i, level, line):
        """
        Debug print of the currently parsed line
        :param i: The line number of the line that is being currently parsed
        :param level: Parser level
        :param line: the line that is currently being parsed
        :return: None
        """
        if self.debug_level == 2:
            print("Line %d (%d): '%s'" % (i + 1, level, line.rstrip(' \r\n\t\f')))
        if self.debug_level > 2:
            print("Line %d (%d):" % (i + 1, level))
            hexdump(line)

    def debug_print_strip_msg(self, i, line):
        """
        Debug print indicating that an empty line is being skipped
        :param i: The line number of the line that is being currently parsed
        :param line: the parsed line
        :return: None
        """
        if self.debug_level == 2:
            print("     Stripping Line %d: '%s'" % (i + 1, line.rstrip(' \r\n\t\f')))
        elif self.debug_level >2:
            print("     Stripping Line %d:" % (i + 1))
            hexdump(line)

    def strip_empty_lines_forward(self, content, i):
        """
        Skip over empty lines
        :param content: parsed text
        :param i: current parsed line
        :return: number of skipped lined
        """
        while i < len(content):
            line = content[i].strip(' \r\n\t\f')
            if line != '':
                break
            self.debug_print_strip_msg(i, content[i])
            i += 1  # Strip an empty line
        return i

    def strip_empty_lines_backward(self, model, max_lines_to_strip):
        """
        Strips empty lines preceding the line that is currently being parsed. This
        fucntion is called when the parser encounters a Footer.
        :param model: lines that were added to the model up to this point
        :param line_num: the number of teh line being parsed
        :param max_lines_to_strip: max number of lines to strip from the model
        :return: None
        """
        for l in range(0, max_lines_to_strip):
            if model[-1][0].strip(' \r\n\t\f') != '':
                return
            self.debug_print_strip_msg(model[-1][1] - 1, model[-1][0])
            model.pop()

    def extract_yang_model(self, content):
        """
        Extracts one or more YANG models from an RFC or draft text string in
        which the models are specified. The function skips over page
        formatting (Page Headers and Footers) and performs basic YANG module
        syntax checking. In strict mode, the function also enforces the
        <CODE BEGINS> / <CODE ENDS> tags - a model is not extracted unless
        the tags are present.
        :return: None
        """
        model = []
        output_file = None
        in_model = False
        example_match = False
        i = 0
        level = 0
        quotes = 0
        while i < len(content):
            line = content[i]

            # Try to match '<CODE ENDS>'
            if self.CODE_ENDS_TAG.match(line):
                if in_model is False:
                    self.warning("Line %d: misplaced <CODE ENDS>" % i)
                in_model = False

            if "\"" in line:
                if line.count("\"") % 2 == 0:
                    quotes = 0
                else:
                    if quotes == 1:
                        quotes = 0
                    else:
                        quotes = 1

            # Try to match '(sub)module <module_name> {'
            match = self.MODULE_STATEMENT.match(line)
            if match:
                # We're already parsing a module
                if quotes == 0:
                    if level > 0:
                        self.error("Line %d - 'module' statement within another module" % i)
                        return

                # Check if we should enforce <CODE BEGINS> / <CODE ENDS>
                # if we do enforce, we ignore models  not enclosed in <CODE BEGINS> / <CODE ENDS>
                if match.groups()[1] or match.groups()[4]:
                    self.warning('Line %d - Module name should not be enclosed in quotes' % i)

                # do the module name checking, etc.
                example_match = self.EXAMPLE_TAG.match(match.groups()[2])
                if in_model is True:
                    if example_match:
                        self.error("Line %d - Yang module '%s' with <CODE BEGINS> and starting with 'example-'" %
                                   (i, match.groups()[2]))
                else:
                    if not example_match:
                        self.error("Line %d - Yang module '%s' with no <CODE BEGINS> and not starting with 'example-'" %
                                   (i, match.groups()[2]))

                # now decide if we're allowed to set the level
                # (i.e. signal that we're in a module) to 1 and if
                # we're allowed to output the module at all with the
                # strict examples flag
                # if self.strict is True:
                #     if in_model is True:
                #         level = 1
                # else:
                #     level = 1

                # always set the level to 1; we decide whether or not
                # to output at the end
                if quotes == 0:
                    level = 1
                if not output_file and level == 1 and quotes == 0:
                    print("\nExtracting '%s'" % match.groups()[2])
                    output_file = '%s.yang' % match.groups()[2].strip('"\'')
                    if self.debug_level > 0:
                        print('   Getting YANG file name from module name: %s' % output_file)

            if level > 0:
                self.debug_print_line(i, level, content[i])
                # Try to match the Footer ('[Page <page_num>]')
                # If match found, skip over page headers and footers
                if self.PAGE_TAG.match(line):
                    self.strip_empty_lines_backward(model, 3)
                    self.debug_print_strip_msg(i, content[i])
                    i += 1        # Strip the
                    # Strip empty lines between the Footer and the next page Header
                    i = self.strip_empty_lines_forward(content, i)
                    if i < len(content):
                        self.debug_print_strip_msg(i, content[i])
                        i += 1      # Strip the next page Header
                    else:
                        self.error("<End of File> - EOF encountered while parsing the model")
                        return
                    # Strip empty lines between the page Header and real content on the page
                    i = self.strip_empty_lines_forward(content, i) - 1
                    if i >= len(content):
                        self.error("<End of File> - EOF encountered while parsing the model")
                        return
                else:
                    model.append([line, i + 1])
                    counter = Counter(line)
                    if quotes == 0:
                        if "\"" in line and "}" in line:
                            if line.index("}") > line.index("\""):
                                level += (counter['{'] - counter['}'])
                        else:
                            level += (counter['{'] - counter['}'])
                    if level == 1:
                        if self.strict:
                            if self.strict_examples:
                                if example_match and not in_model:
                                    self.write_model_to_file(model, output_file)
                            elif in_model:
                                self.write_model_to_file(model, output_file)
                        else:
                            self.write_model_to_file(model, output_file)
                        self.max_line_len = 0
                        model = []
                        output_file = None
                        level = 0

            # Try to match '<CODE BEGINS>'
            match = self.CODE_BEGINS_TAG.match(line)
            if match:
                # Found the beginning of the YANG module code section; make sure we're not parsing a model already
                if level > 0:
                    self.error("Line %d - <CODE BEGINS> within a model" % i)
                    return
                if in_model is True:
                    self.error("Line %d - Misplaced <CODE BEGINS> or missing <CODE ENDS>" % i)
                in_model = True
                mg = match.groups()
                # Get the YANG module's file name
                if mg[2]:
                    print("\nExtracting '%s'" % match.groups()[2])
                    output_file = mg[2].strip()
                else:
                    if mg[0] and mg[1] is None:
                        self.error('Line %d - Missing file name in <CODE BEGINS>' % i)
                    else:
                        self.error("Line %d - Yang file not specified in <CODE BEGINS>" % i)
            i += 1
        if level > 0:
            self.error("<End of File> - EOF encountered while parsing the model")
            return
        if in_model is True:
            self.error("Line %d - Missing <CODE ENDS>" % i)


def xym(source_id, srcdir, dstdir, strict=False, strict_examples=False, debug_level=0, add_line_refs=False):
    """
    Extracts YANG model from an IETF RFC or draft text file.
    This is the main (external) API entry for the module.
    :param add_line_refs:
    :param source_id: identifier (file name or URL) of a draft or RFC file containing
           one or more YANG models
    :param srcdir: If source_id points to a file, the optional parameter identifies
           the directory where the file is located
    :param dstdir: Directory where to put the extracted YANG models
    :param strict: Strict syntax enforcement
    :param strict_examples: Only output valid examples when in strict mode
    :param debug_level: Determines how much debug output is printed to the console
    :return: None
    """
    url = re.compile(r'^(?:http|ftp)s?://'  # http:// or https://
                     r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain
                     r'localhost|'  # localhost...
                     r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
                     r'(?::\d+)?'  # optional port
                     r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    rqst_hdrs = {'Accept': 'text/plain', 'Accept-Charset': 'utf-8'}

    ye = YangModuleExtractor(source_id, dstdir, strict, strict_examples, add_line_refs, debug_level)
    is_url = url.match(source_id)
    if is_url:
        r = requests.get(source_id, headers=rqst_hdrs)
        if r.status_code == 200:
            content = r.text.encode('utf8').splitlines(True)
            ye.extract_yang_model(content)
        else:
            print("Failed to fetch file from URL '%s', error '%d'" % (source_id, r.status_code), file=sys.stderr)
    else:
        try:
            with open(os.path.join(srcdir, source_id)) as sf:
                ye.extract_yang_model(sf.readlines())
        except IOError as ioe:
            print(ioe)
    return ye.get_extracted_models()


if __name__ == "__main__":
    """
    Command line utility / test
    """
    parser = argparse.ArgumentParser(description="Extracts one or more yang "
                                     "models from an IETF RFC/draft text file")
    parser.add_argument("source",
                        help="The URL or file name of the RFC/draft text from "
                             "which to get the model")
    parser.add_argument("--srcdir", default='.',
                        help="Optional: directory where to find the source "
                             "text; default is './'")
    parser.add_argument("--dstdir", default='.',
                        help="Optional: directory where to put the extracted "
                             "yang module(s); default is './'")
    parser.add_argument("--strict", action='store_true', default=False,
                        help="Optional flag that determines syntax enforcement; "
                             "If set to 'True', the <CODE BEGINS> / <CODE ENDS> "
                             "tags are required; default is 'False'")
    parser.add_argument("--strict-examples", action='store_true', default=False,
                        help="Only output valid examples when in strict mode")
    parser.add_argument("--debug", type=int, default=0,
                        help="Optional: debug level - determines the amount of "
                             "debug information printed to console; default is 0 (no "
                             "debug info printed). Debug level 2 prints every parsed "
                             "line from the original Draft/RFC text. Debug level 3 "
                             "hexdumps every parsed line. ")
    parser.add_argument("--add-line-refs", action='store_true', default=False,
                        help="Optional: if present, comments are added to each "
                             "line in the extracted yang module that contain "
                             "the reference to the line number in the "
                             "original RFC/Draft text file from which the "
                             "line was extracted.")
    args = parser.parse_args()

    extracted_models = xym(args.source,
                           args.srcdir,
                           args.dstdir,
                           args.strict,
                           args.strict_examples,
                           args.debug,
                           args.add_line_refs)
    if len(extracted_models) > 0:
        if args.strict:
            print("\nCreated the following models that conform to the strict guidelines::")
        else:
            print("\nCreated the following models::")
        for em in extracted_models:
            print('%s : %s ' % (em, args.source))
        print('')
    else:
        print('\nNo models created.\n')
