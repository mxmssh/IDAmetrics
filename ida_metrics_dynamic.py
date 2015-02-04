'''
ida_metrics_dynamic plugin ver 0.1

Copyright (c) 2015, Maksim Shudrak (mxmssh@gmail.com)
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer. 
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

The views and conclusions contained in the software and documentation are those
of the authors and should not be interpreted as representing official policies, 
either expressed or implied, of the FreeBSD Project.
'''

''' 
IDA plugin for dynamic metrics collection.
Supported:
    1. Code coverage evaluation
    2. Lines of code executed
    3. BBLs executed
    4. Calls executed

    TODO: Script usage description

'''

import idc
import idaapi
import idautils
import sqlite3
from sets import Set
from idaapi import *
from ida_metrics_static import GetInstructionType

class Metrics_function_dynamic:
    def __init__(self, function_ea):
        self.function_ea = function_ea
        self.loc_executed_count = 0
        self.bbls_executed_count = 0
        self.bbls_boundaries_executed = dict()
        self.calls_executed_count = 0
        self.code_coverage = 0.0

class Metrics_dynamic:
    def __init__(self):
        self.image_base = 0
        self.code_coverage_total = 0.0
        self.loc_executed_total = 0
        self.bbls_executed_total = 0
        self.functions_executed_total = 0
        self.calls_executed_total = 0
        self.functions = dict()
        # i#12 Add Henry&Cafura evaluation after code execution

    def get_basic_dynamic_metrics(self, c, metrics_static):
        
        instr_executed = list()
        instr_executed_dict = dict()
        for r in c:
            if r[0] == 0:
                self.loc_executed_total += 1
                continue
            # set color for traced instructions
            idc.SetColor(r[0] + self.image_base, idc.CIC_ITEM, 0xB8FF94)
            instr_executed.append(r[1]+self.image_base)
        for instr in instr_executed:
            instr_executed_dict[instr] = instr_executed_dict.get(instr, 0) + 1
        # Here we have only first instructions of the basic block, call instructions
        # and instructions after call
        for instr in instr_executed:
            function_name = idc.GetFunctionName(instr)
            if function_name == "":
                # i#11 We need special algorithm instead of GetFunctionName in "red"
                # zones.
                print "Unknown"
                raise Exception ("Unknown function name")
            if self.functions.get(function_name, None) == None:
                function_dynamic = Metrics_function_dynamic(function_name)
            else:
                function_dynamic = self.functions[function_name]

            bbls_dict = metrics_static.functions[function_name].bbls_boundaries
            for bbl_key, bbl in bbls_dict.items():
                if hex(instr) in bbl and bbl[0] not in function_dynamic.bbls_boundaries_executed:
                    function_dynamic.bbls_boundaries_executed[bbl[0]] = bbl
            self.functions[function_name] = function_dynamic

        for name,function in self.functions.items():
            function.bbls_executed_count = len(function.bbls_boundaries_executed)
            for bbl_key, bbl in function.bbls_boundaries_executed.items():
                function.loc_executed_count += len(bbl)
                for instr in bbl:
                    if GetInstructionType(int(instr,16)) == CALL_INSTRUCTION:
                        function.calls_executed_count += 1
                    idc.SetColor(int(instr, 16), idc.CIC_ITEM, 0xB8FF94)
            function.code_coverage = float(function.loc_executed_count)/metrics_static.functions[name].loc_count
            
            self.loc_executed_total += function.loc_executed_count
            self.bbls_executed_total += function.bbls_executed_count
            self.calls_executed_total += function.calls_executed_count
        
        self.functions_executed_total = len(self.functions)
        self.code_coverage_total = float(self.loc_executed_total)/metrics_static.total_loc_count
    
    def load_db(self, fname):
        from_file = sqlite3.connect(fname)
        return from_file

    def get_dynamic_metrics(self, dbname):
        db = self.load_db(dbname)
        self.image_base = idaapi.get_imagebase();    
        c = db.cursor()
        query = 'select i.prev_address, i.cur_address from trace i'
        c.execute(query)

        # i#10 ida_metrics_static script needs refactoring b/c we don't need to
        # collect all metrics here.
        metrics_static = Metrics()
        metrics_static.start_analysis()
        self.get_basic_dynamic_metrics(c, metrics_static)

print "Start CFG analysis"
fname = idc.AskFile(0, ".db", "Choose sqlite db with trace data")
#fname = "C:\pin-trace-01-28-15-42-42.db" db for tests

metrics_dynamic = Metrics_dynamic()
metrics_dynamic.get_dynamic_metrics(fname)
print "done"
