## Register in RB as class: reviewboard.scmtools.piccolo.PiccoloTool
##
## from reviewboard.scmtools import piccolo
## reviewboard.scmtools.piccolo.PiccoloTool
##
## TODO replace DebugPrint with logging
## TODO GENERIC add default template option for description so that when a review is created from web interface it is prepopuldated with a form to fill in (to add the stuff we want, like bug release notes) - this way the regular reviewboard model can be used (note psuite negates the need for this but this is still useful IMHO)
## TODO GENERIC add support for deleted files (note svn patches do not show this information) - i.e. show the file is to be deleted. I currently show it as a comment (which then shows the lines to be lost which is an ok'ish workaround)
## TODO add piccolo to reviewboard/scmtools/fixtures/initial_data.json THIS NO LONGER EXISTS, add to test fixtures?
## TODO add piccolo tests to test suite
## TODO diffs and file names in emails - 
##      http://reviews.review-board.org/r/579/ 
##      http://reviews.review-board.org/r/596/ 
##      also related to http://reviews.review-board.org/r/598/
## TODO raw diffs code review/clean up?
##      http://reviews.review-board.org/r/579/
##      http://reviews.review-board.org/r/598/
## TODO remove the prints.... (for diffs)
## TODO seem to have a bunh of stuff not implemented (rasise not implemented errors) but I'm not sure they ever get called!

"""
Big issues (ignoring not implement yet stuff)

*   piccolo path/tree is in filename. Piccolo path then gets used for
    file name in temp diff (when patch exe is spawned)!!! (spaces-n-all)
    Could shove path in info element I suppose.....
    To see this feed a "bad" diff, e.g. one that has converted tabs to spaces
    Not sure if "horrible" filename gets used in a sucessful patch
    (I think it always get used, see diffutils.py patch()
"""

# FIXME these have to go; logging or simply just remove?
DebugPrint=False
#DebugPrint=True

import sys
import re
import io

from reviewboard.diffviewer.parser import DiffParser, DiffParserError, ParsedDiffFile
from reviewboard.scmtools.core import SCMTool, HEAD, PRE_CREATION
from reviewboard.scmtools.errors import FileNotFoundError, SCMError

from reviewboard.scmtools import pypiccolo

# Piccolo constants to compare with
PICCOLO_BINARY_FILES_TEXT="Can't diff binary file."
PICCOLO_DELETEDMISSING_FILES_TEXT=": local file missing - can't diff" ## example: "utils.dlst": local file missing - can't diff

# Reviewboard Output constants
PICCOLO_DIFF_SEPERATOR='\n' ## Suggestion from AlexH, could be '' if no seperator
PICCOLO_FILE_DELETED_TEXT = '0a1\n> /*** NOTE Reviewer - THIS FILE HAS BEEN DELETED NOTE ***/' # Uses words from pygments.CodeTagFilter so they show up in red (only works for recognised source code files)
PICCOLO_DIFF_INSERT = b'>'
PICCOLO_DIFF_DELETE = b'<'



def parse_piccolo_url(url):
    """Parse URL of form:
        server:[port][/piccolo_lib]

    Port is an integer
    """
    url = url.strip()
    u = url.split('/')
    server_port = u[0]
    try:
        piccolo_lib = u[1]
    except IndexError:
        piccolo_lib = None

    u = server_port.split(':')
    server = u[0]
    try:
        port = int(u[1])  # Expect port to be an integer if specfied
    except IndexError:
        port = None
    except ValueError:
        # not an integer, silently ignore
        port = None

    if not server:
        server = None

    if not piccolo_lib:
        piccolo_lib = None

    return (server, port, piccolo_lib)

#local_parse_piccolo_url = pypiccolo.picparse.parse_piccolo_url
local_parse_piccolo_url = parse_piccolo_url

class PiccoloTool(SCMTool):
    name = 'Piccolo'
    scmtool_id = 'piccolo'
    diffs_use_absolute_paths = True
    supports_ticket_auth = False
    supports_pending_changesets = False
    prefers_mirror_path = False

    field_help_text = {
        'path': (
            'set to "SERVER:PORT[/LIBRARY]" '
            'where SERVER is the Piccolo server and PORT is the port'
            ' and optionally add the library'
        )
    }

    def get_parser(self, data):
        return PiccoloDiffParser(data)

    def get_fields(self):
        return ['diff_path']

    def get_file(self, path, revision=None,base_commit_id=None,context=None):
        this_function_name = sys._getframe().f_code.co_name
        if DebugPrint:  print ('CMCDEBUG PiccoloTool.%s()' % this_function_name)
        if DebugPrint:  print ('CMCDEBUG args %r' % ((path, revision,base_commit_id,context),))
        if DebugPrint:  print ('CMCDEBUG args %r' % ((path, revision,base_commit_id,context),))
        server, port, piccolo_lib = local_parse_piccolo_url(self.repository.path)
        p = pypiccolo.Piccolo(servername=server, serverport=port, piccolo_lib=piccolo_lib)
        fileptr = io.BytesIO()
        picpath, picname = path.split()
        if DebugPrint:  print ('CMCDEBUG path,name %r' % ((picpath, picname),))
        x=None
        try:
            x = p.get(picpath, picname, revision, fileptr=fileptr)
        except pypiccolo.NotImplemented as ex_info:
            raise SCMError('pypiccolo.NotImplemented ' + str(ex_info))
        if DebugPrint:  print ('CMCDEBUG x %r' % ((x, ),))
        filecontents = fileptr.getvalue()
        if DebugPrint:  print ('CMCDEBUG filecontents %r' % ((filecontents, ),))
        if DebugPrint:  print ('CMCDEBUG ')
        if DebugPrint:  print ('CMCDEBUG ')
        if DebugPrint:  print ('CMCDEBUG filecontents %r' % ((filecontents[0:300], ),))
        if DebugPrint:  print ('CMCDEBUG x %r' % ((x, ),))
        return filecontents

    def parse_diff_revision(self, filename, revision, moved=False,
                  copied=False, *args, **kwargs):
        if revision == "0":
            # New file (p reserve -a) found
            revision = PRE_CREATION
        return filename, revision

    def get_diffs_use_absolute_paths(self):
        return True
        return False

    def get_changeset(self, changesetid):
        this_function_name = sys._getframe().f_code.co_name
        raise SCMError('piccolo.NotImplemented ' + this_function_name)

    def get_pending_changesets(self, userid):
        this_function_name = sys._getframe().f_code.co_name
        raise SCMError('piccolo.NotImplemented ' + this_function_name)

    def get_filenames_in_revision(self, revision):
        this_function_name = sys._getframe().f_code.co_name
        raise SCMError('piccolo.NotImplemented ' + this_function_name)

    def get_repository_info(self):
        # FIXME do something with self.repository - looks like need to return a dict?
        this_function_name = sys._getframe().f_code.co_name
        raise SCMError('piccolo.NotImplemented ' + this_function_name)


class PiccoloDiffParser(DiffParser):
    """Based off PerforceDiffParser
    """
    SPECIAL_REGEX = re.compile(r"""^=== (\S*) (\S*) rev (\d+)(?:\ (.+))? ====$""") ## Requires new piccolo 2.2.1alpha+ with mode support, TODO add named groups?

    def __init__(self, data):
        DiffParser.__init__(self, data)
        #super(PiccoloDiffParser, self).__init__(self, data) ## not possible

    def parse_diff_header(self, linenum, info):
        """Expects output from picclo client version 2.2.1alpha; or later (binary, new/deleted files)
        """
        if DebugPrint:  print ('CMCDEBUG pic.parse_diff_header() %r' % ((linenum, info,), ))
        linestr = str(self.lines[linenum],'utf-8')
        m = self.SPECIAL_REGEX.match(linestr)
        if m:
            pic_tree = m.group(1)
            pic_filename = m.group(2)
            pic_version = m.group(3)
            pic_mode = m.group(4) ## 
            if pic_mode and pic_mode=='add':
                ## TODO FIXME This ideally would be in parse_diff_revision() BUT but not sure how to do this other than concating mode with rev
                # Problem with this (irrespective of where this is done) is that version number is lost if file was deleted and this change is re-adding it (assume 0 on create patch).
                pic_version = PRE_CREATION # TODO One idea is to have rev + add and then parser can do precreate and maybe retain same output that p rcompare gives on patch download?
            #pic_version = int(pic_version)
            if DebugPrint:  print ('CMCDEBUG pic.parse_diff_header() %r' % ((pic_tree, pic_filename, pic_version ), ))
            
            ## FIXME include pic tree/path!! i.e. pic_tree
            info['origFile'], info['origInfo'] = '%s %s' % (pic_tree, pic_filename), pic_version
            info['newFile'], info['newInfo'] = '%s %s' % (pic_tree, pic_filename), '(working copy)'
            if DebugPrint:  print ('CMCDEBUG %r' % (info, ))
            linenum += 1
            
            if linenum < len(self.lines):
                linestr = str(self.lines[linenum],'utf-8')
                ## binary check
                if linestr == PICCOLO_BINARY_FILES_TEXT:
                    # Roger's newbinary check, client version 2.2.0
                    info['binary'] = True
                    linenum += 1
                elif linestr.startswith('Binary files '):
                    # now check for old piccolo binaries, these clients ran the diff which then failed with a diff binary file error
                    # Classic diff for binary (i.e. Unix client and server side "rcompare -s" diff)
                    info['binary'] = True
                    linenum += 1
                else:
                    # Now check for Windows (fc/cmp) diff text markers
                    try:
                        tmplist = linestr.split(' ')
                        if tmplist[2] == 'differ:' and tmplist[0][0] not in '0123456789':
                            info['binary'] = True
                            linenum += 1
                    except IndexError:
                        pass
            
                ## deleted file check
                ## NOTE relies upon developer issueing "p reserve -d filename ; rm -f filename"
                ## if the delete is not issued shows up as no diff
                ## alternative is to "echo ""> filename" to truncate it (or "echo. > filename" under windows
                ## Ideally use Piccolo client version 2.2.1alpha and later
                if not info.get('binary'): # TODO is None or not....?
                    if linestr.endswith(PICCOLO_DELETEDMISSING_FILES_TEXT):
                        # new is missing (so assume deleted) check, client version 2.2.1alpha; (2.2.2)
                        self.lines[linenum] = PICCOLO_FILE_DELETED_TEXT
                        # TODO check if newer versions of ReviewBoard know about deleted files
                        # As we injected text, do NOT increment linenum
                    elif linestr.startswith("diff: Can't open file ") or linestr.split(' ')[2:] == ['No', 'such', 'file', 'or', 'directory']:
                        # older client check
                        # windows style; >>diff: Can't open file "do_case.50": The system cannot find the file specified.
                        # Unix style;    >>diff: builddocunix.txt: No such file or directory
                        # NOTE normally this error goes to stderr NOT stdout BUT post-review picks this up
                        # Inject deleted text, not pretty but least worst thing to do and is clear
                        self.lines[linenum] = PICCOLO_FILE_DELETED_TEXT
                        # As we injected text, do NOT increment linenum

        return linenum
        ## below is probably wrong, probably need to add plain diff detection code :-(
        print ('WTF are we doing here!!')
        return super(PiccoloDiffParser, self).parse_diff_header(linenum, info)

# TODO - see if this can be fixed up, although seems to be optional.
# 
#    def parse_change_header(self, linenum):
#        """Parses part of the diff beginning at the specified line number, trying
#        to find a diff header.
#        """
#        info = {}
#        file = None
#        start = linenum
#        #linenum = self.parse_special_header(linenum, info) ### this maybe the one to implement
#        if DebugPrint:  print ('CMCDEBUG %r' % (info, ))
#        linenum = self.parse_diff_header(linenum, info)
#
#        # If we have enough information to represent a header, build the
#        # file to return.
#        if 'origFile' in info and 'newFile' in info and \
#           'origInfo' in info and 'newInfo' in info:
#            file = ParsedDiffFile(parsed_diff_change=self.parsed_diff_change)
#            file.binary   = info.get('binary', False)
# TODO these are piccolo filenames and RB doesn't like them!
#            file.orig_filename = info.get('origFile')
#            file.new_filename  = info.get('newFile')
#            file.orig_file_details = info.get('origInfo')
#            file.new_file_details  = info.get('newInfo')
#            file.data = ""
#
#        return linenum, file
    
    def parse_diff_line(self, linenum, info):
        line = self.lines[linenum]

        this_function_name = sys._getframe().f_code.co_name
        if info.origFile is not None and info.newFile is not None:
            if line.startswith(PICCOLO_DIFF_DELETE):
                info.delete_count += 1
            elif line.startswith(PICCOLO_DIFF_INSERT):
                info.insert_count += 1

        info.append_data(line)
        info.append_data(b'\n')

        return linenum + 1

    def raw_diff(self, diffset):
        """Probably not a good fit for this class but this is quick to hack in! 
        Maybe this belongs in reviewrequest? The reason for doing it here is
        that we can subclass this (and we have to for diff parsing) and return
        the expected format.
        Given a diffset returns a raw diff - hopefully in the form that the diff parser consumes
        """
        def pic_regen_diff(filediff):
            """basically a replacement for ternary oprator in THIS specific context
            python 2.5 introduced the ternary BUT 2.4 and earlier do NOT have it.
            """
            headstr=[]
            source_revision = filediff.source_revision
            if source_revision == PRE_CREATION:
                # Ensure consistent piccolo diff format
                source_revision = '0'
            # Piccolo does NOT support non-ASCII characters in filename/paths
            # ReviewBoard (sensibly) stores filenames as Unicode strings,
            # later on these Unicodes strings are concatenated with the diffs
            # (byte strings), the byte strings are promoted to Unicode and if
            # there are non-ASCII characters conversion to Unicode (assuming
            # ASCII encoding) fails. Forcing filenames to byte string avoids
            # this problem. NOTE Python 3.0 is likely to need extra work/code
            # here.
            # NOTE: emails will be MISSING (inline) diff content if non-ASCII
            # characters are found and the encoding is not valid UTF-8
            # emails are sent in utf8 and so the inline text would be invalid
            tmpstr = PICCOLO_DIFF_SEPERATOR + '=== %s rev %s ====\n' % (filediff.source_file, source_revision)
            headstr.append(tmpstr.encode('utf-8'))
            if filediff.binary:
                ### output piccolo client version 2.2.0 binary files marker text
                tmpstr=PICCOLO_BINARY_FILES_TEXT+'\n'
                headstr.append(tmpstr.encode('utf-8'))
            else:
                headstr.append(filediff.diff)
            return b''.join(headstr)
        data = b''.join([pic_regen_diff(filediff) for filediff in diffset.files.all()])
        return data

