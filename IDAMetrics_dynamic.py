'''
IDAMetrics_dynamic IDA plugin ver 0.7

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
    5. Highlight executed trace in IDA CFG


'''

import idc
import idaapi
import idautils
import sqlite3
from sets import Set
from idaapi import *
from IDAMetrics_static import *
from Tkinter import *
import tkMessageBox
import Tkinter

class Metrics_function_dynamic:
    def __init__(self, function_ea):
        self.function_ea = function_ea
        self.loc_executed_count = 0
        self.bbls_executed_count = 0
        self.bbls_boundaries_executed = dict()
        self.calls_executed_count = 0
        self.code_coverage = 0.0
        self.ask_save = True

class Metrics_dynamic:
    def __init__(self):
        self.image_base = idaapi.get_imagebase();
        self.code_coverage_total = 0.0
        self.loc_executed_total = 0
        self.bbls_executed_total = 0
        self.functions_executed_total = 0
        self.calls_executed_total = 0
        self.functions = dict()

    def get_basic_dynamic_metrics(self, trace, metrics_static, metrics_used):
        ''' The basic routine to get all dynamic and static metrics 
        @ trace - a list of executed instructions
        @ metrics_static - static Metrics()
        @ metrics_used - mask of used metrics
        ''' 
        instr_executed = list()
        null_mask = dict()
        instr_executed_dict = dict()
        for instr_addr in trace:
            instr_addr = int(instr_addr, 0) + self.image_base
            # set color for traced instructions
            idc.SetColor(instr_addr, idc.CIC_ITEM, 0xB8FF94)
            instr_executed.append(instr_addr)
       
        # get basic metrics required for code coverage assessment
        metrics_temp = Metrics()
        metrics_temp.start_analysis(metrics_used)
        
        for instr in instr_executed:
            instr_executed_dict[instr] = instr_executed_dict.get(instr, 0) + 1
        # Here we have only first instructions of the basic block, calls
        # and instruction after call
        for instr, count in instr_executed_dict.items():
            function_name = idc.GetFunctionName(instr)
            if function_name == "":
                # i#11 We need special algorithm instead of GetFunctionName in "red"
                # zones.
                print "Unknown function at ", hex(instr)
                continue
            if self.functions.get(function_name, None) == None:
                metrics_static.functions[function_name] = metrics_temp.functions[function_name]
                metrics_static.collect_total_metrics(function_name)
                function_dynamic = Metrics_function_dynamic(function_name)
            else:
                function_dynamic = self.functions[function_name]
            
            bbls_dict = metrics_static.functions[function_name].bbls_boundaries

            for bbl_key, bbl in bbls_dict.items():
                if hex(instr) in bbl and bbl[0] not in function_dynamic.bbls_boundaries_executed:
                    function_dynamic.bbls_boundaries_executed[bbl[0]] = bbl
            self.functions[function_name] = function_dynamic
        print "collect final metrics"
        metrics_static.collect_final_metrics()
        
        for name,function in self.functions.items():
            function.bbls_executed_count = len(function.bbls_boundaries_executed)
            for bbl_key, bbl in function.bbls_boundaries_executed.items():
                function.loc_executed_count += len(bbl)
                for instr in bbl:
                    if GetInstructionType(int(instr,16)) == CALL_INSTRUCTION:
                        function.calls_executed_count += 1
                    idc.SetColor(int(instr, 16), idc.CIC_ITEM, 0xB8FF94)
            if metrics_static.functions[name].loc_count != 0:
                function.code_coverage = float(function.loc_executed_count)/metrics_static.functions[name].loc_count
            
            self.loc_executed_total += function.loc_executed_count
            self.bbls_executed_total += function.bbls_executed_count
            self.calls_executed_total += function.calls_executed_count
        
        self.functions_executed_total = len(self.functions)
        #restore total values
        metrics_static.total_loc_count = metrics_temp.total_loc_count
        metrics_static.total_func_count = metrics_temp.total_func_count
        metrics_static.total_bbl_count = metrics_temp.total_bbl_count
        metrics_static.total_assign_count = metrics_temp.total_assign_count
        if metrics_static.total_loc_count != 0:
            self.code_coverage_total = float(self.loc_executed_total)/metrics_static.total_loc_count
        

    def load_trace(self, trace_name):
        ''' The routine loads trace of executed bbls 
        @ trace_name - name of trace
        @ trace - list of addresses
        '''
        f = open(trace_name, "r")
        trace = f.readlines()
        # we need to check trace before return it
        return trace

    def get_dynamic_metrics(self, trace_name, metrics_used):
        ''' The routine starts analysis 
        @trace_name - name of trace to analyze
        @metrics_used - mask of used metrics
        '''
        trace = self.load_trace(trace_name)
        metrics_static = Metrics()
        metrics_static.metrics_mask = metrics_used
        # collect metrics only for trace
        self.get_basic_dynamic_metrics(trace, metrics_static, metrics_used)
        self.save_dynamic_results(metrics_static)
        return metrics_static
        
        
    def save_dynamic_results(self, metrics_static):
        ''' The routine saves results in specified file 
        @metrics_static - static metrics results
        @return - None
        '''
        
        print 'Average lines of code in the executed functions:', metrics_static.average_loc_count
        print 'Total number of functions:', metrics_static.total_func_count
        print 'Total lines of code:', metrics_static.total_loc_count
        print 'Total bbls count:', metrics_static.total_bbl_count
        print 'Total assignments count:', metrics_static.total_assign_count
        print "----Total metrics for trace----\n"
        print 'Cyclomatic complexity', metrics_static.CC_total
        print 'Jilb\'s metric', metrics_static.CL_total
        print 'ABC:', metrics_static.ABC_total
        print 'Halstead:', metrics_static.Halstead_total.B
        print 'Pivovarsky:', metrics_static.Pivovarsky_total
        print 'Harrison:', metrics_static.Harrison_total
        print 'Boundary value', metrics_static.boundary_values_total
        print 'Span metric', metrics_static.span_metric_total
        print 'Global var metric', metrics_static.global_vars_metric_total
        print 'Oviedo metric', metrics_static.Oviedo_total
        print 'Chepin metric', metrics_static.Chepin_total
        print 'Henry&Cafura metric', metrics_static.HenrynCafura_total
        print 'Cocol metric', metrics_static.Cocol_total
        print 'Card&Glass metric', metrics_static.CardnGlass_total
        print '------Dynamic metrics ------\n'
        print 'LOC executed:', self.loc_executed_total
        print 'BBLs executed:', self.bbls_executed_total
        print 'Functions executed:', self.functions_executed_total
        print 'Calls executed in the functions:', self.calls_executed_total
        print 'Code coverage:',  self.code_coverage_total
        #Save in log file
        if (self.ask_save == True):
            current_time = strftime("%Y-%m-%d_%H-%M-%S")
            analyzed_file = idc.GetInputFile()
            analyzed_file = analyzed_file.replace(".","_")
            mask = analyzed_file + "_dynamic_" + current_time + ".txt"
            name = idc.AskFile(1, mask, "Where to save metrics ?")
            if name == None:
                return 0
            f = open(name, 'w')

            f.write('Average lines of code in the executed functions: ' + str(metrics_static.average_loc_count) + "\n")
            f.write('Total number of functions: ' + str(metrics_static.total_func_count) + "\n")
            f.write('Total lines of code: ' + str(metrics_static.total_loc_count) + "\n")
            f.write('Total bbls count: ' + str(metrics_static.total_bbl_count) + "\n")
            f.write('Total assignments count: ' + str(metrics_static.total_assign_count) + "\n")
            f.write('----Total metrics for trace----\n')
            f.write('Cyclomatic complexity: ' + str(metrics_static.CC_total) + "\n")
            f.write('Jilb\'s metric: ' + str(metrics_static.CL_total) + "\n")
            f.write('ABC: ' + str(metrics_static.ABC_total) + "\n")
            f.write('Halstead B:' + str(metrics_static.Halstead_total.B) + "\n")
            f.write('Pivovarsky: ' + str(metrics_static.Pivovarsky_total) + "\n")
            f.write('Harrison: ' + str(metrics_static.Harrison_total) + "\n")
            f.write('Boundary value: ' + str(metrics_static.boundary_values_total) + "\n")
            f.write('Span metric: ' + str(metrics_static.span_metric_total) + "\n")
            f.write('Oviedo metric: ' + str(metrics_static.Oviedo_total) + "\n")
            f.write('Chepin metric: ' + str(metrics_static.Chepin_total) + "\n")
            f.write('Henry&Cafura metric: ' + str(metrics_static.HenrynCafura_total) + "\n")
            f.write('Cocol metric: ' + str(metrics_static.Cocol_total) + "\n")
            f.write('CardnGlass metric: ' + str(metrics_static.CardnGlass_total) + "\n")
            f.write('------Dynamic metrics ------\n')
            f.write('LOC executed: ' + str(self.loc_executed_total) + "\n")
            f.write('BBLs executed: ' + str(self.bbls_executed_total) + "\n")
            f.write('Calls executed in functions: ' + str(self.calls_executed_total) + "\n")
            f.write('Functions executed: ' + str(self.functions_executed_total) + "\n")
            f.write('Code coverage: ' + str(self.code_coverage_total) + "\n")        

            for function in metrics_static.functions:
                f.write(str(function) + "\n")
                f.write('  Lines of code in the function: ' + str(metrics_static.functions[function].loc_count) + "\n")
                f.write('  Bbls count: ' + str(metrics_static.functions[function].bbl_count) + "\n")
                f.write('  Condition count: ' + str(metrics_static.functions[function].condition_count) + "\n")
                f.write('  Calls count: ' + str(metrics_static.functions[function].calls_count) + "\n")
                f.write('  Assignments count: ' + str(metrics_static.functions[function].assign_count) + "\n")
                f.write('  Cyclomatic complexity: ' + str(metrics_static.functions[function].CC) + "\n")
                f.write('  Cyclomatic complexity modified: ' + str(metrics_static.functions[function].CC_modified) + "\n")
                f.write('  Jilb\'s metric: ' + str(metrics_static.functions[function].CL) + "\n")
                f.write('  ABC: ' + str(metrics_static.functions[function].ABC) + "\n")
                f.write('  R count: ' + str(metrics_static.functions[function].R) + "\n")

                f.write('    Halstead.B: ' + str(metrics_static.functions[function].Halstead_basic.B) + "\n")
                f.write('    Halstead.E: ' + str(metrics_static.functions[function].Halstead_basic.E) + "\n")
                f.write('    Halstead.D: ' + str(metrics_static.functions[function].Halstead_basic.D) + "\n")
                f.write('    Halstead.N*: ' + str(metrics_static.functions[function].Halstead_basic.Ni) + "\n")
                f.write('    Halstead.V: ' + str(metrics_static.functions[function].Halstead_basic.V) + "\n")
                f.write('    Halstead.N1: ' + str(metrics_static.functions[function].Halstead_basic.N1) + "\n")
                f.write('    Halstead.N2: ' + str(metrics_static.functions[function].Halstead_basic.N2) + "\n")
                f.write('    Halstead.n1: ' + str(metrics_static.functions[function].Halstead_basic.n1) + "\n")
                f.write('    Halstead.n2: ' + str(metrics_static.functions[function].Halstead_basic.n2) + "\n")

                f.write('  Pivovarsky: ' + str(metrics_static.functions[function].Pivovarsky) + "\n")
                f.write('  Harrison: ' + str(metrics_static.functions[function].Harrison) + "\n")
                f.write('  Cocol metric' + str(metrics_static.functions[function].Cocol) + "\n")

                f.write('  Boundary value: ' + str(metrics_static.functions[function].boundary_values) + "\n")
                f.write('  Span metric: ' + str(metrics_static.functions[function].span_metric) + "\n")
                f.write('  Global vars metric:' + str(metrics_static.functions[function].global_vars_metric) + "\n")
                f.write('  Oviedo metric: ' + str(metrics_static.functions[function].Oviedo) + "\n")
                f.write('  Chepin metric: ' + str(metrics_static.functions[function].Chepin) + "\n")
                f.write('  CardnGlass metric: ' + str(metrics_static.functions[function].CardnGlass) + "\n")
                f.write('  Henry&Cafura metric: ' + str(metrics_static.functions[function].HenrynCafura) + "\n")
            f.close()
        

def prepare(metrics_used):
    fname = idc.AskFile(0, ".out", "Choose a trace file")
    if fname == None:
        print "You need to specify trace to get dynamic metrics"
        return 0
    print "Start trace analysis"

    metrics_dynamic = Metrics_dynamic()
    metrics_dynamic.get_dynamic_metrics(fname, metrics_used)

def main():
    ui_Setup = UI(prepare)
    print "done"

if __name__ == "__main__":
    main()
