# Volatility
# Copyright (C) 2007-2013 Volatility Foundation
#
# This file is part of Volatility.
#
# Volatility is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# Volatility is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Volatility.  If not, see <http://www.gnu.org/licenses/>.
#

import volatility.plugins.malware.malfind as malfind
import volatility.plugins.linux.pslist as pslist
import volatility.plugins.linux.common as linux_common
import volatility.utils as utils
import volatility.debug as debug
import re


png_end1 = ["00", "00", "00", "00", "45", "49", "44", "4e", "42", "ae", "82", "60"]
png_end2 = ["00", "00", "49", "00", "4e", "45", "ae", "44", "60", "42", "00", "82"]
png_end3 = ["00", "00", "49", "00", "4e", "45", "ae", "44", "60", "42", "72", "82", "7a", "65", "6f", "7a"]


try:
    import yara
    has_yara = True
except ImportError:
    has_yara = False

class VmaYaraScanner(malfind.BaseYaraScanner):
    """A scanner over all memory regions of a process."""

    def __init__(self, task = None, **kwargs):
        """Scan the process address space through the VMAs.

        Args:
          task: The task_struct object for this task.
        """
        self.task = task
        malfind.BaseYaraScanner.__init__(self, address_space = task.get_process_address_space(), **kwargs)

    def scan(self, offset = 0, maxlen = None):
        for vma in self.task.get_proc_maps():
            for match in malfind.BaseYaraScanner.scan(self, vma.vm_start, vma.vm_end - vma.vm_start):
                yield match

class linux_imagescan(malfind.YaraScan):
    """A shell in the Linux memory image"""

    @staticmethod
    def is_valid_profile(profile):
        return profile.metadata.get('os', 'Unknown').lower() == 'linux'

    def filter_tasks(self):
        tasks = pslist.linux_pslist(self._config).calculate()
        if self._config.PID is not None:
            try:
                pidlist = [int(p) for p in self._config.PID.split(',')]
            except ValueError:
                debug.error("Invalid PID {0}".format(self._config.PID))

            pids = [t for t in tasks if t.pid in pidlist]
            if len(pids) == 0:
                debug.error("Cannot find PID {0}. If its terminated or unlinked, use psscan and then supply --offset=OFFSET".format(self._config.PID))
            return pids

        if self._config.NAME is not None:
            try:
                name_re = re.compile(self._config.NAME, re.I)
            except re.error:
                debug.error("Invalid name {0}".format(self._config.NAME))

            names = [t for t in tasks if name_re.search(str(t.comm))]
            if len(names) == 0:
                debug.error("Cannot find name {0}. If its terminated or unlinked, use psscan and then supply --offset=OFFSET".format(self._config.NAME))
            return names

        return tasks

    def extract_img(self, task, address, hit, scanner):
        x = 0
        limit = 0
        found = False
        while x < 20000000 and found == False:
            buf = scanner.address_space.zread(address + x, 1000)
            idx = 0
            while idx < 990 and found == False:
                end = buf[idx : idx + 10]
                end_hex = ["{:02x}".format(ord(c)) for c in end]
                if end_hex == png_end1 or end_hex == png_end2 or end_hex == png_end3:
                    limit = address + x + idx + 12
                    if end_hex == png_end3: limit += 4
                    found = True
                idx += 1
            x += 900

        image_data = scanner.address_space.zread(address, limit)
        a = open("test.png", "wb")
        a.write(image_data)
        a.close()

    def calculate(self):

        ## we need this module imported
        if not has_yara:
            debug.error("Please install Yara from https://plusvic.github.io/yara/")

        ## leveraged from the windows yarascan plugin
        rules = yara.compile(
                sources = {
                    'a' : 'rule png {strings: $a = {89 50 4E 47 0D 0A 1A 0A} condition: $a}',
                    'a1': 'rule pngend1 {strings: $a1 = {49 45 4E 44 AE 42 60 82} condition: $a1}',
                    'b' : 'rule gif {strings: $b = {47 49 46 38 ( 39 61 | 37 61 )} condition: $b}'
                    })

        ## set the linux plugin address spaces
        linux_common.set_plugin_members(self)

        tasks = self.filter_tasks()
        for task in tasks:
            scanner = VmaYaraScanner(task = task, rules = rules)
            for hit, address in scanner.scan():
                #self.extract_img(task, address, hit, scanner)
                yield (task, address, hit,
                            scanner.address_space.zread(address - self._config.REVERSE, self._config.SIZE))

    def render_text(self, outfd, data):
        for task, address, hit, buf in data:
            if task:
                outfd.write("Task: {0} pid {1} rule {2} addr {3:#x}\n".format(
                    task.comm, task.pid, hit.rule, address))
            else:
                outfd.write("[kernel] rule {0} addr {1:#x}\n".format(hit.rule, address))

            outfd.write("".join(["{0:#010x}  {1:<48}  {2}\n".format(
                address + o, h, ''.join(c)) for o, h, c in utils.Hexdump(buf)]))
