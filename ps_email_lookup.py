'''
    Author: Ruben Kluge

'''

import volatility.obj as obj
import volatility.utils as utils
from volatility.renderers import TreeGrid

import volatility.plugins.linux.common as linux_common
import volatility.plugins.linux.pslist as linux_pslist

import re

from BreachAPI import BreachAPI



class ps_email_lookup(linux_common.AbstractLinuxCommand):
    ''' 
        This plugin searches processes for email addresses. 
        Then it tries to determine the age of the email by matching it against
        the HaveIBeenPwned service. This will return the oldest breach date,
        and in how many breaches this has been found.

    '''
    def __init__(self, config, *args, **kwargs):
        linux_common.AbstractLinuxCommand.__init__(self, config, *args, **kwargs)
        
        # optional: specify dump directory if you want to dump all the processes to a file (debugging purposes)
        self._config.add_option('DUMP-DIR', short_option = 'D', default = None, help = 'Output directory', action = 'store', type = 'str')

        # optional: specify a process to look for. If none specified, it will search all the processes!
        # highly recommend to use this!
        self._config.add_option('PID', short_option = 'p', default = None,
                          help = 'Operate on these Process IDs (comma-separated)',
                          action = 'store', type = 'str')

        self.api = BreachAPI()


    def binaryToString(self, content):
        #print all elements that have at least 4 characters
        contentMatch = re.findall("[^\x00-\x1F\x7F-\xFF]{4,}", content)
        flatten = " ".join(str(x) for x in contentMatch)
        return flatten


    def emailSearch(self, rawStrings):
        # Regex pattern to grab substring emails from a string
        # Copyright: https://www.tutorialspoint.com/python/python_extract_emails_from_text.htm
        pattern = r"[a-z0-9\.\-+_]+@[a-z0-9\.\-+_]+\.[a-z]+"
        return re.findall(pattern, rawStrings)

    '''
    @Deprecated
    def render_text(self, outfd, data):
        for item in data:
            task = item['task']
            emails = item['emails']

            outfd.write("PID - Email - date - Breach Count\n")

            for email in emails:
                address, date, breaches = self.api.lookupBreachAPI(email)
                outfd.write("{!s} - {!s} - {!s} - {!s} \n".format(str(task.pid), address, date, breaches))
    '''

    def generator(self, data):
        for item in data:
            task = item['task']
            emails = item['emails']

            for email in emails:
                address, date, breaches = self.api.lookupBreachAPI(email)

                yield (0, [
                    int(task.pid),
                    str(address),
                    str(date),
                    int(breaches)
                ])

    def unified_output(self, data):
        tree = [
            ("PID", int),
            ("E-mail", str),
            ("Date", str),
            ("Breaches", int)
            ]
        return TreeGrid(tree, self.generator(data))


    def calculate(self):
        # Should contain the options for one e-mail
        out = []

        tasks = linux_pslist.linux_pslist(self._config).calculate()

        for task in tasks:
            if not task.mm:
                continue
            # Get the dump for the process    
            content = task.get_elf(task.mm.start_code)

            #print all elements that have at least 4 characters
            string_contents = self.binaryToString(content)
            emails = self.emailSearch(string_contents)

            # If dump directory is specified, we should dump all the tasks to the directory
            if self._config.DUMP_DIR:
                linux_common.write_elf_file(self._config.DUMP_DIR, task, task.mm.start_code)

            #proc_contents = task.get_elf(task.get_process_address_space())
            out.append({"task": task, "emails": emails})

    
        #Returns a tuple of (task, content)
        return out



'''
file_path = linux_common.write_elf_file(self._config.DUMP_DIR, task, task.mm.start_code)



def write_elf_file(dump_dir, task, elf_addr):
    file_name = re.sub("[./\\\]", "", str(task.comm))

    file_path = os.path.join(dump_dir, "%s.%d.%#8x" % (file_name, task.pid, elf_addr))

    file_contents = task.get_elf(elf_addr)

    fd = open(file_path, "wb")
    fd.write(file_contents)
    fd.close()       

    return file_path 


From this we learn that task contains get_elf(elf_addr) func!
'''