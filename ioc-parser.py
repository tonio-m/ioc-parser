#!/usr/bin/env python

###################################################################################################
#
# Copyright (c) 2015, Armin Buescher (armin.buescher@googlemail.com)
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
###################################################################################################
#
# File:             ioc-parser.py
# Description:      IOC Parser is a tool to extract indicators of compromise from security reports
#                   in PDF format.
# Usage:            ioc-parser.py [-h] [-p INI] [-f FORMAT] PDF
# Req.:             PyPDF2 (https://github.com/mstamy2/PyPDF2)
# Author:           Armin Buescher (@armbues)
# Contributors:     Angelo Dell'Aera (@angelodellaera)
# Thanks to:        Jose Ramon Palanco
#                   Koen Van Impe (@cudeso)
#
###################################################################################################
#
# 05/18/15 - Palo Alto Networks AutoFocus output format added by Christopher Clark
#            cclark@paloaltonetworks.com - https://github.com/Xen0ph0n/
#
###################################################################################################
import os
import sys
import fnmatch
import argparse
import re
from io import StringIO

try:
    import configparser as ConfigParser
except ImportError:
    import ConfigParser

# Import optional third-party libraries
IMPORTS = []
try:
    from PyPDF2 import PdfFileReader

    IMPORTS.append("pypdf2")
except ImportError:
    pass
try:
    from pdfminer.pdfpage import PDFPage
    from pdfminer.pdfinterp import PDFResourceManager
    from pdfminer.converter import TextConverter
    from pdfminer.pdfinterp import PDFPageInterpreter
    from pdfminer.layout import LAParams

    IMPORTS.append("pdfminer")
except ImportError:
    pass
try:
    from bs4 import BeautifulSoup

    IMPORTS.append("beautifulsoup")
except ImportError:
    pass
try:
    import requests

    IMPORTS.append("requests")
except ImportError:
    pass

# Import additional project source files
import output
from whitelist import WhiteList


class IOC_Parser(object):
    patterns = {}

    def __init__(
        self,
        patterns_ini,
        input_format="pdf",
        output_format="csv",
        dedup=False,
        library="pypdf2",
    ):
        basedir = os.path.dirname(os.path.abspath(__file__))
        self.load_patterns(patterns_ini)
        self.whitelist = WhiteList(basedir)
        self.handler = output.getHandler(output_format)
        self.dedup = dedup

        self.ext_filter = "*." + input_format
        parser_format = "parse_" + input_format
        try:
            self.parser_func = getattr(self, parser_format)
        except AttributeError:
            e = "Selected parser format is not supported: %s" % (input_format)
            raise NotImplementedError(e)

        self.library = library
        if input_format == "pdf":
            if library not in IMPORTS:
                e = "Selected PDF parser library not found: %s" % (library)
                raise ImportError(e)
        elif input_format == "html":
            if "beautifulsoup" not in IMPORTS:
                e = "HTML parser library not found: BeautifulSoup"
                raise ImportError(e)

    def load_patterns(self, fpath):
        config = ConfigParser.ConfigParser()
        with open(fpath) as f:
            config.read_file(f)

        for ind_type in config.sections():
            try:
                ind_pattern = config.get(ind_type, "pattern")
            except:
                continue

            if ind_pattern:
                ind_regex = re.compile(ind_pattern)
                self.patterns[ind_type] = ind_regex

    def is_whitelisted(self, ind_match, ind_type):
        for w in self.whitelist[ind_type]:
            if w.findall(ind_match):
                return True

        return False

    def parse_page(self, fpath, data, page_num):
        for ind_type, ind_regex in list(self.patterns.items()):
            matches = ind_regex.findall(data)

            for ind_match in matches:
                if isinstance(ind_match, tuple):
                    ind_match = ind_match[0]

                if self.is_whitelisted(ind_match, ind_type):
                    continue

                if self.dedup:
                    if (ind_type, ind_match) in self.dedup_store:
                        continue

                    self.dedup_store.add((ind_type, ind_match))

                self.handler.print_match(fpath, page_num, ind_type, ind_match)

    def parse_pdf_pypdf2(self, f, fpath):
        try:
            pdf = PdfFileReader(f, strict=False)

            if self.dedup:
                self.dedup_store = set()

            self.handler.print_header(fpath)
            page_num = 0
            for page in pdf.pages:
                page_num += 1

                data = page.extractText()

                self.parse_page(fpath, data, page_num)
            self.handler.print_footer(fpath)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as e:
            self.handler.print_error(fpath, e)

    def parse_pdf_pdfminer(self, f, fpath):
        try:
            laparams = LAParams()
            laparams.all_texts = True
            rsrcmgr = PDFResourceManager()
            pagenos = set()

            if self.dedup:
                self.dedup_store = set()

            self.handler.print_header(fpath)
            page_num = 0
            for page in PDFPage.get_pages(f, pagenos, check_extractable=True):
                page_num += 1

                retstr = StringIO()
                device = TextConverter(rsrcmgr, retstr, laparams=laparams)
                interpreter = PDFPageInterpreter(rsrcmgr, device)
                interpreter.process_page(page)
                data = retstr.getvalue()
                retstr.close()

                self.parse_page(fpath, data, page_num)
            self.handler.print_footer(fpath)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as e:
            self.handler.print_error(fpath, e)

    def parse_pdf(self, f, fpath):
        parser_format = "parse_pdf_" + self.library
        try:
            self.parser_func = getattr(self, parser_format)
        except AttributeError:
            e = "Selected PDF parser library is not supported: %s" % (self.library)
            raise NotImplementedError(e)

        self.parser_func(f, fpath)

    def parse_txt(self, f, fpath):
        try:
            if self.dedup:
                self.dedup_store = set()

            data = f.read()
            self.handler.print_header(fpath)
            self.parse_page(fpath, data, 1)
            self.handler.print_footer(fpath)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as e:
            self.handler.print_error(fpath, e)

    def parse_html(self, f, fpath):
        try:
            if self.dedup:
                self.dedup_store = set()

            data = f.read()
            soup = BeautifulSoup(data)
            html = soup.findAll(text=True)

            text = ""
            for elem in html:
                if elem.parent.name in [
                    "style",
                    "script",
                    "[document]",
                    "head",
                    "title",
                ]:
                    continue
                elif re.match("<!--.*-->", str(elem)):
                    continue
                else:
                    text += str(elem)

            self.handler.print_header(fpath)
            self.parse_page(fpath, text, 1)
            self.handler.print_footer(fpath)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as e:
            self.handler.print_error(fpath, e)

    def parse(self, path):
        try:
            if path.startswith("http://") or path.startswith("https://"):
                if "requests" not in IMPORTS:
                    e = "HTTP library not found: requests"
                    raise ImportError(e)
                headers = {"User-Agent": "Mozilla/5.0 Gecko Firefox"}
                r = requests.get(path, headers=headers)
                r.raise_for_status()
                f = StringIO(r.content)
                self.parser_func(f, path)
                return
            elif os.path.isfile(path):
                with open(path, "rb") as f:
                    self.parser_func(f, path)
                return
            elif os.path.isdir(path):
                for walk_root, walk_dirs, walk_files in os.walk(path):
                    for walk_file in fnmatch.filter(walk_files, self.ext_filter):
                        fpath = os.path.join(walk_root, walk_file)
                        with open(fpath, "rb") as f:
                            self.parser_func(f, fpath)
                return

            e = "File path is not a file, directory or URL: %s" % (path)
            raise IOError(e)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as e:
            self.handler.print_error(path, e)


if __name__ == "__main__":
    argparser = argparse.ArgumentParser()
    argparser.add_argument(
        "PATH", action="store", help="File/directory/URL to report(s)"
    )
    argparser.add_argument(
        "-p",
        dest="INI",
        default=os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "patterns.ini"
        ),
        help="Pattern file",
    )
    argparser.add_argument(
        "-i", dest="INPUT_FORMAT", default="pdf", help="Input format (pdf/txt)"
    )
    argparser.add_argument(
        "-o", dest="OUTPUT_FORMAT", default="csv", help="Output format (csv/json/yara)"
    )
    argparser.add_argument(
        "-d",
        dest="DEDUP",
        action="store_true",
        default=False,
        help="Deduplicate matches",
    )
    argparser.add_argument(
        "-l",
        dest="LIB",
        default="pdfminer",
        help="PDF parsing library (pypdf2/pdfminer)",
    )

    args = argparser.parse_args()

    parser = IOC_Parser(
        args.INI, args.INPUT_FORMAT, args.OUTPUT_FORMAT, args.DEDUP, args.LIB
    )
    parser.parse(args.PATH)
