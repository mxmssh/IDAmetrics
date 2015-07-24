"""
IDAMetrics_static IDA plugin ver. 0.7

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
"""

"""
This IDA script collects static software complexity metrics for binary executable
of x86 architecture.

Minimal requirements:
IDA 5.5.0
Python 2.5
IDAPython 1.2.0

Supported the following metrics:
    1. Lines of code (function/module)
    2. Average lines of code per basic block (module)
    3. Basic blocks count (function/module)
    4. Functions count (module)
    5. Conditions count (function/module)
    6. Assignments count (function/module)
    7. Cyclomatic complexity metric (function/module)
    8. Cyclomatic complexity modified metric (function/module)
    9. Jilb's metric (function/module)
    10. ABC metric (function/module)
    11. Pivovarsky metric (function/module)
    12. Halstead metric (function/module)
    13. Harrison metric (function/module)
    14. Boundary value metric (function/module)
    15. Span metric (function/module)
    16. Global variables access count (function/module)
    17. Oviedo metric (function/module)
    18. Chepin metric (function/module)
    19. Card & Glass metric (function/module)
    20. Henry & Cafura metric (function/module)
    21. Cocol metric (function/module)
Additional functionality:
     - node graph generation (function)
     - basic block boundaries generation (function)
"""

import sys
import idc
import idaapi
import idautils
import math
import gc
from time import strftime
from collections import defaultdict
from sets import Set
from idaapi import *

from Tkinter import *
import tkMessageBox
import Tkinter

OTHER_INSTRUCTION = 0
CALL_INSTRUCTION = 1
BRANCH_INSTRUCTION = 2
ASSIGNMENT_INSTRUCTION = 3
COMPARE_INSTRUCTION = 4
STACK_PUSH_INSTRUCTION = 5
STACK_POP_INSTRUCTION = 6
__EA64__ = idaapi.BADADDR == 0xFFFFFFFFFFFFFFFFL

FUNCATTR_END     =  4     # function end address
ARGUMENT_SIZE    =  4
if __EA64__:
    FUNCATTR_END     = 8
    ARGUMENT_SIZE = 8

metrics_list = ["loc", "bbls", "calls", "condit", "assign", "cc", "cc_mod", "jilb", "abc", "pi", "h",
                "harr", "bound", "span", "global", "oviedo", "chepin", "c&s", "h&c", "cocol"]
metrics_names = ["Lines of code", "Basic blocks count", "Routines calls count", "Conditions count",\
                 "Assignments count", "Cycl. complexity", "Cycl. complexity mod.", "Jilb", "ABC", \
                 "Pivovarsky", "Halstead", "Harrison", "Boundary values", "span metric", \
                 "Global vars access count", "Oviedo", "Chepin", "Card & Glass", "Henry & Cafura",\
                 "Cocol"]
# group of assignment instructions ($5.1.1 vol.1 Intel x86 manual):
assign_instructions_general = ["mov", "cmov", "xchg", "bswap", "xadd", "ad", "sub",
                       "sbb", "imul", "mul", "idiv", "div", "inc", "dec", "neg",
                       "da", "aa", "and", "or", "xor", "not", "sar", "shr", "sal",
                       "shl", "shrd", "shld", "ror", "rol", "rcr", "rcl", "lod", "sto", "lea"]
assign_instructions_fp = ["fld", "fst", "fild", "fisp", "fistp", "fbld", "fbstp", "fxch",
                          "fcmove", "fadd", "fiadd", "fsub", "fisub", "fmul", "fimul", "fdiv",
                          "fidiv", "fprem", "fabs", "fchs", "frndint", "fscale", "fsqrt", "fxtract",
                          "fsin", "fcos", "fsincos", "fptan", "fpatan", "f2xm", "fyl2x", "fld",
                          "fstcw", "fnstcw", "fldcw", "fstenv", "fnstenv", "fstsw", "fnstsw", "fxsave",
                          "fxrstop"]
compare_instructions = ["cmp", "test"]
registers = ["eax", "ebx", "ecx", "edx", "esi", "edi", "esp", "ebp"]
stack_push_instructions = ["push"]
stack_pop_instructions = ["pop"]
# i#1 add MMX/SSEx/AVX/64bit mode instructions.
# i#2 add tests

def GetInstructionType(instr_addr):
    instr_mnem = idc.GetMnem(instr_addr)
    if instr_mnem.startswith('call'):
        return CALL_INSTRUCTION
    elif instr_mnem.startswith('j'):
        # It seems that there is no other type of instructions
        # starting with j in x86/x86_64
        return BRANCH_INSTRUCTION
    for assign_instr_mnem in assign_instructions_general:
        if instr_mnem.startswith(assign_instr_mnem):
            return ASSIGNMENT_INSTRUCTION
    for assign_instr_mnem in assign_instructions_fp:
        if instr_mnem.startswith(assign_instr_mnem):
            return ASSIGNMENT_INSTRUCTION
    for compare_instruction in compare_instructions:
        if instr_mnem.startswith(compare_instruction):
            return COMPARE_INSTRUCTION
    for stack_push_instruction in stack_push_instructions:
        if instr_mnem.startswith(stack_push_instruction):
            return STACK_PUSH_INSTRUCTION
    for stack_pop_instruction in stack_pop_instructions:
        if instr_mnem.startswith(stack_pop_instruction):
            return STACK_POP_INSTRUCTION
    return OTHER_INSTRUCTION

class Halstead_metric:
    def __init__(self):
        self.n1 = 0
        self.n2 = 0
        self.N1 = 0
        self.N2 = 0
        self.V = 0
        self.Ni = 0
        self.D = 0
        self.E = 0
        self.B = 0

    def calculate(self):
        n = self.n1+self.n2
        N = self.N1+self.N2
        try:
            self.Ni = self.n1 * math.log(self.n1, 2) + self.n2 * math.log(self.n2, 2)
        except:
            print "WARNING: Ni value for Halstead metric is too large to calculate"
        self.V = N * math.log(n, 2)
        if self.n2 != 0:
            self.D = (self.n1/2)*(self.N2/self.n2)
        else:
            print "WARNING: n2 value for Halstead metric is 0. Skip evaluation for this routine"             
        self.E = self.D * self.V
        self.B = (self.E**(2.0/3.0))/3000

class Metrics_function:
    def __init__(self, function_ea):
        self.function_name = idc.GetFunctionName(function_ea)
        self.loc_count = 0
        self.bbl_count = 0
        self.condition_count = 0
        self.calls_count = 0
        self.R = 0.0
        self.CC = 0
        self.CL = 0
        self.assign_count = 0
        self.ABC = 0
        self.CC_modified = 0
        self.Pivovarsky = 0
        self.Halstead_basic = Halstead_metric()
        self.Harrison = 0
        self.boundary_values = 0.0
        self.span_metric = 0
        self.vars_local = dict()
        self.vars_args = dict()
        self.Oviedo = 0
        self.Chepin = 0
        self.global_vars_access = 0
        self.global_vars_used = dict()
        self.global_vars_metric = 0.0
        self.bbls_boundaries = dict()
        self.CardnGlass = 0
        self.fan_in_i = 0
        self.fan_in_s = 0
        self.fan_out_i = 0
        self.calls_dict = dict()
        self.fan_out_s = 0
        self.HenrynCafura = 0
        self.Cocol = 0

class Metrics:
    def __init__(self):
        self.metrics_mask = dict()
        self.total_loc_count = 0
        self.average_loc_count = 0.0
        self.total_bbl_count = 0
        self.total_func_count = 0
        self.total_condition_count = 0
        self.total_assign_count = 0
        self.R_total = 0.0
        self.CC_total = 0
        self.CL_total = 0
        self.ABC_total = 0
        self.Halstead_total = Halstead_metric()
        self.CC_modified_total = 0
        self.Pivovarsky_total = 0
        self.Harrison_total = 0.0
        self.boundary_values_total = 0.0
        self.span_metric_total = 0
        self.Oviedo_total = 0
        self.Chepin_total = 0
        self.global_vars_dict = dict()
        self.global_vars_metric_total = 0.0
        self.Cocol_total = 0
        self.HenrynCafura_total = 0.0
        self.CardnGlass_total = 0.0
        self.functions = dict()

    def start_analysis(self, metrics_used):
        """
        The function starts static metrics analysis.
        @metrics_used - a dictionary of metrics used in the following format {metrics_list element:1 or 0}
        PTAL metrics_list global list and args_parser routine
        @return - None
        """
        self.metrics_mask = metrics_used
        # For each of the segments
        for seg_ea in idautils.Segments():
            # For each of the functions
            function_ea = seg_ea
            while function_ea != 0xffffffffL:
                function_name = idc.GetFunctionName(function_ea)
                # if already analyzed
                if self.functions.get(function_name, None) != None:
                    function_ea = idc.NextFunction(function_ea)
                    continue
                print "Analysing ", hex(function_ea)
                try:
                    self.functions[function_name] = self.get_static_metrics(function_ea)
                except:
                    print 'Can\'t collect metric for this function ', hex(function_ea)
                    print 'Skip'
                    function_ea = idc.NextFunction(function_ea)
                    continue
                self.collect_total_metrics(function_name)
                function_ea = idc.NextFunction(function_ea)
        self.collect_final_metrics()

    def collect_final_metrics(self):
        ''' The routine collect some metrics that should be calculated after analysis
        '''
        if self.total_func_count > 0:
            self.average_loc_count = self.total_loc_count / self.total_func_count
        if self.metrics_mask["h"] == 1 or self.metrics_mask["cocol"] == 1:
            self.Halstead_total.calculate()
        if self.metrics_mask["global"] == 1:
            self.global_vars_metric_total = self.add_global_vars_metric()
        if self.metrics_mask["cocol"] == 1:
            self.Cocol_total += self.Halstead_total.B + self.CC_total + self.total_loc_count
            
    def collect_total_metrics(self, function_name):
        ''' The routine is used to add function measures to total metrics evaluation
        @function_name - name of function
        '''        
        self.total_loc_count += self.functions[function_name].loc_count
        self.total_bbl_count += self.functions[function_name].bbl_count
        self.total_func_count += 1
        self.total_condition_count += self.functions[function_name].condition_count
        self.total_assign_count += self.functions[function_name].assign_count
        self.R_total += self.functions[function_name].R

        self.CC_modified_total += self.functions[function_name].CC_modified
        self.Pivovarsky_total += self.functions[function_name].Pivovarsky
        self.Harrison_total += self.functions[function_name].Harrison
        self.boundary_values_total += self.functions[function_name].boundary_values

        self.Halstead_total.n1 += self.functions[function_name].Halstead_basic.n1
        self.Halstead_total.n2 += self.functions[function_name].Halstead_basic.n2
        self.Halstead_total.N1 += self.functions[function_name].Halstead_basic.N1
        self.Halstead_total.N2 += self.functions[function_name].Halstead_basic.N2

        self.CC_total += self.functions[function_name].CC
        self.CL_total += self.functions[function_name].CL
        self.ABC_total += self.functions[function_name].ABC

        self.span_metric_total += self.functions[function_name].span_metric
        self.Oviedo_total += self.functions[function_name].Oviedo
        self.Chepin_total += self.functions[function_name].Chepin
        self.HenrynCafura_total += self.functions[function_name].HenrynCafura
        self.CardnGlass_total += self.functions[function_name].CardnGlass
        
        if self.metrics_mask["cocol"] == 1:
            self.functions[function_name].Cocol = self.functions[function_name].Halstead_basic.B + self.functions[function_name].CC + self.functions[function_name].loc_count
            
    def add_global_vars_metric(self):
        '''
        The function calculates access count to global variables.
        @return - total access count
        '''

        total_metric_count = 0
        for function in self.functions:
            if len(self.global_vars_dict) > 0:
                self.functions[function].global_vars_metric = float(self.functions[function].global_vars_access)/len(self.global_vars_dict)
            total_metric_count += self.functions[function].global_vars_metric
        return total_metric_count

    def get_bbl_head(self, head):
        """
        The function returns address of the head instruction
        for the basic block.
        @head - address of arbitrary instruction in the basic block.
        @return - head address of the basic block.
        """

        while 1:
            prev_head = idc.PrevHead(head, 0)
            if isFlow(idc.GetFlags(prev_head)):
                head = prev_head
                if prev_head >= SegEnd(head):
                    raise Exception("Can't identify bbl head")
                continue
            else:
                if prev_head == hex(0xffffffffL):
                    return head
                else:
                    return prev_head
                break

    def enumerate_function_chunks(self, f_start):
        """
        The function gets a list of chunks for the function.
        @f_start - first address of the function
        @return - list of chunks
        """
        # Enumerate all chunks in the function
        chunks = list()
        first_chunk = idc.FirstFuncFchunk(f_start)
        chunks.append((first_chunk, idc.GetFchunkAttr(first_chunk, idc.FUNCATTR_END)))
        next_chunk = first_chunk
        while next_chunk != 0xffffffffL:
            next_chunk = idc.NextFuncFchunk(f_start, next_chunk)
            if next_chunk != 0xffffffffL:
                chunks.append((next_chunk, idc.GetFchunkAttr(next_chunk, idc.FUNCATTR_END)))
        return chunks

    def get_subgraph_nodes_count(self, node, node_graph, nodes_passed):
        """
        The function calculates total count of nodes in the subgraph for
        selected node.
        @node - first node to get subgraph
        @node_graph - node graph dictionary (result of make_graph function)
        @nodes_passed - list of passed nodes
        @return - total count of nodes in the subgraph
        """
        nodes_count = 0
        if node in nodes_passed:
            #already passed
            return 1
        else:
            nodes_passed.append(node)
        child_nodes = node_graph.get(node, None)
        if child_nodes != None:
            for child_node in child_nodes:
                if child_node in nodes_passed:
                    continue
                nodes_count += self.get_subgraph_nodes_count(child_node, node_graph, nodes_passed)
                nodes_count += 1
        return nodes_count

    def get_boundary_value_metric(self, node_graph, pivovarsky = False):
        """
        Function returns absolute boundary value metric or Pi value for
        Pivovarsky metric.
        @node_graph - node graph dictionary (result of make_graph function)
        @pivovarsky - if true function calculates Pivovarsky Pi operand
        @return - boundary value or Pi value
        """
        boundary_value = 0
        for node in node_graph:
            childs = node_graph.get(node, None)
            if childs == None:
                continue
            out_edges_count = len(childs)
            if pivovarsky:
                if out_edges_count == 2:
                    boundary_value += self.get_subgraph_nodes_count(node, node_graph, list())
            else:
                if out_edges_count >= 2:
                    boundary_value += self.get_subgraph_nodes_count(node, node_graph, list())
                else:
                    boundary_value += 1
        if not pivovarsky:
            boundary_value -= 1 #exclude terminal node for boundary value metric
        return boundary_value

    def get_node_complexity(self, node, node_graph, bbls_dict, nodes_passed):
        """
        This function is very similar with get_subgraph_nodes_count but it uses
        to calculate Harrison metric.
        @node - node address to get node complexity
        @node_graph - node graph dictionary (result of make_graph function)
        @bbls_dict - basic block boundaries dictionary
        @nodes_passed - list of passed nodes_count
        @return - node complexity by using loc measure and list of passed nodes
        """
        loc_measure = 0
        # i#3: add more initial complexity metrics e.g. Halstead
        if node in nodes_passed:
            #already passed
            return 0, nodes_passed
        else:
            nodes_passed.append(node)
        child_nodes = node_graph.get(node, None)
        if child_nodes != None:
            for child_node in child_nodes:
                if child_node in nodes_passed:
                    continue
                bbls_node = bbls_dict.get(child_node, None)
                if bbls_node == None:
                    print "WARNING: couldn't find bbl for child node: ", child_node
                    loc_measure += 0
                else:
                    loc_measure += len(bbls_node)
                    loc_measure += self.get_node_complexity(child_node, node_graph, bbls_dict, nodes_passed)
        return loc_measure

    def get_harrison_metric(self, node_graph, bbls):
        """
        The function calculates Harrison metric.
        @node_graph - node graph dictionary (result of make_graph function)
        @bbls - bbls set
        @return - Harrison metric
        """
        bbls_dict = dict()
        loc_measure = 0
        for bbl in bbls:
            bbls_dict[bbl[0]] = [x for x in bbl]
        for node in node_graph:
            childs = node_graph.get(node, None)
            if childs == None or len(childs) != 2:
                loc_measure_node = bbls_dict.get(node, None)
                if loc_measure_node != None:
                    loc_measure += len(loc_measure_node)
                else:
                    print "WARNING: couldn't find bbl for node: ", node
            else:
                loc_measure += self.get_node_complexity(node, node_graph, bbls_dict, list())
                bbls_predicate_node = bbls_dict.get(node, None)
                if bbls_predicate_node == None:
                    print "WARNING: couldn't find bbl for predicate node: ", node
                else:
                    loc_measure += len(bbls_predicate_node)
        return loc_measure

    # i#4 Support graphs with several terminal nodes
    # i#5 Ignore nodes without incoming edges
    def make_graph(self, edges, bbls, boundaries):
        """
        The function makes nodes graph by using edges,
        bbls and boundaries sets.
        @edges - set of edges
        @bbls - set of bbls
        @boundaries - set of boundaries
        @return node graph
        """
        node_graph = dict()
        edges_dict = dict()
        bbls_dict = dict()

        # i#6 This function needs re-factoring. Now it has ugly
        # additional functionality to make the graph correct for
        # functions with chunks and to add terminal nodes. (xref i#7)

        for edge_from,edge_to in edges:
            if edge_from == hex(0xffffffffL):
                raise Exception("Invalid edge reference", edge_from)
            edges_dict.setdefault(edge_from, []).append(edge_to)
        for bbl in bbls:
            bbls_dict[bbl[len(bbl)-1]] = [x for x in bbl]
        boundaries_list = [hex(x) for x in boundaries]

        for edge_from in edges_dict:
            node_edges_to = edges_dict[edge_from]
            if node_edges_to == None:
                raise Exception("Error when creating node graph")
            # check for additional chunks (xref i#6)
            if edge_from not in boundaries_list:
                bbl_edge_from = bbls_dict.get(edge_from, None)
                if bbl_edge_from == None:
                    print "WARNING: Can't find bbl for ", edge_from
                else:
                    node_graph[bbl_edge_from[0]] = node_edges_to
            else:
                node_graph[edge_from] = node_edges_to

        if len(node_graph) == 0 and len(edges_dict) == 0 and len(boundaries_list) == 1:
            node_graph[boundaries_list[0]] = None #it means that graph has only single root node
        elif len(node_graph) == 0 and len(edges_dict) !=0:
            raise Exception ("Error when creating node graph")
        #add terminal nodes (xref i#6)
        for bbl in bbls:
            check_bbl = node_graph.get(bbl[0], None)
            if check_bbl == None:
                node_graph[bbl[0]] = None
        return node_graph

    def get_bbls(self, chunks, boundaries, edges):
        """
        Set bbls using edges and boundaries
        @chunks - a list of function chunks
        @boundaries - a list of function boundaries (see get_static_metrics)
        @edges - a list of function edges (see get_static_metrics)
        @return - a set of bbls boundaries
        """
        bbls = []
        bbl = []
        # NOTE: We can handle if jump xrefs to chunk address space.
        for chunk in chunks:
            for head in idautils.Heads(chunk[0], chunk[1]):
                if head in boundaries or head in edges:
                    if len(bbl) > 0:
                        bbls.append(bbl)
                        bbl = []
                    bbl.append(hex(head))
                elif GetInstructionType(head) == BRANCH_INSTRUCTION:
                    bbl.append(hex(head))
                    bbls.append(bbl)
                    bbl = []
                else:
                    bbl.append(hex(head))
        # add last basic block
        if len(bbl) > 0:
            bbls.append(bbl)
        return bbls

    def get_instr_operands(self, head):
        """
        @head - instruction address
        @return - the function returns list of variables which is
        used in the instruction
        """
        i = 0
        instr_op = list()
        while i < 4:
            op = idc.GetOpnd(head, i)
            if op != "":
                instr_op.append((op, idc.GetOpType(head, i)))
            i += 1
        return instr_op

    def is_operand_called(self, op, bbl):
        '''
        The function checks whether operand used for call instruction in the
        following instructions or not.
        @op - operand
        @bbl - list of instructions in bbl
        @return - True if used
        '''
        for instr in bbl:
            instr_type = GetInstructionType(int(instr,16))
            if instr_type == CALL_INSTRUCTION or\
               instr_type == BRANCH_INSTRUCTION:
                instr_ops = self.get_instr_operands(int(instr, 16))
                if op in instr_ops:
                    return True
                #trying to replace ds: and check it again
                op = op.replace("ds:","")
                comment = idc.GetDisasm(int(instr,16))
                if comment != None and op in comment:
                    return True
        return False

    def get_function_args_count(self, function_ea, local_vars):
        """
        The function returns count of function arguments
        @function_ea - function entry point
        @local_vars - local variables dictionary
        @return - function arguments count
        """
        # i#9 Now, we can't identify fastcall functions.

        function_args_count = 0
        args_dict = dict()
        for local_var in local_vars:
            usage_list = local_vars.get(local_var, None)
            if usage_list == None:
                print "WARNING: empty usage list for ", local_var
                continue
            for head in usage_list:
                ops = self.get_instr_operands(int(head, 16))
                for idx, (op,type) in enumerate(ops):
                    if op.count("+") == 1:
                        value = idc.GetOperandValue(int (head, 16), idx)
                        if value < (15 * ARGUMENT_SIZE) and "ebp" in op:
                            args_dict.setdefault(local_var, []).append(head)
                    elif op.count("+") == 2:
                        if "arg" in local_var:
                            args_dict.setdefault(local_var, []).append(head)
                    else:
                        continue

        function_args_count = len(args_dict)
        if function_args_count:
            return function_args_count, args_dict

        #TODO Check previous algorithm here
        f_end = idc.FindFuncEnd(function_ea)
        f_end = idc.PrevHead(f_end, 0)
        instr_mnem = idc.GetMnem(f_end)
        #stdcall ?
        if "ret" in instr_mnem:
            ops = self.get_instr_operands(f_end)
            if len(ops) == 1:
                for op,type in ops:
                    op = op.replace("h", "")
                    function_args_count = int(op,16)/ARGUMENT_SIZE
                    return function_args_count, args_dict
        #cdecl ?
        refs = idautils.CodeRefsTo(function_ea, 0)
        for ref in refs:
            #trying to find add esp,x signature after call
            head = idc.NextHead(ref, 0xFFFFFFFF)
            if head:
                disasm = idc.GetDisasm(head)
                if "add" in disasm and "esp," in disasm:
                    ops = self.get_instr_operands(head)
                    op,type = ops[1]
                    if op:
                        op = op.replace("h", "")
                        function_args_count = int(op,16)/ARGUMENT_SIZE
                        return function_args_count, args_dict
        return function_args_count, args_dict

    def get_span_metric(self, bbls_dict):
        """
        The function calculates span metric.
        @bbls_dict - basic blocks dictionary
        @return - span metric
        """
        span_metric = 0
        for bbl_key, bbl in bbls_dict.items():
            for head in bbl:
                instr_op = self.get_instr_operands(int(head, 16))
                instr_type = GetInstructionType(int(head, 16))
                if instr_type == CALL_INSTRUCTION or instr_type == BRANCH_INSTRUCTION:
                    continue
                for op,type in instr_op:
                    if self.is_operand_called(op, bbl):
                        continue
                    if type >= idc.o_mem and type <= idc.o_displ:
                        span_metric += 1
        return span_metric

    def is_var_global(self, operand, head):
        '''
        The function checks whether operand global or not.
        @return - True if global
        '''
        if operand == -1:
            return False
        refs = idautils.DataRefsTo(operand)
        if len(list(refs)) > 1:
            return True
        return False

    def get_local_var_name(self, operand, head):
        '''
        The function returns variable name which is used in operand
        @operand - operand string representation
        @head - instruction head for debugging
        @return - variable name
        '''
        # i#8 Now we can't identify variables which is handled by registers.
        # We can only identify stack local variables.
        operand = operand.replace(" ", "")
        name = ""

        if operand.count("+") == 1:
            # [base reg+name]
            name = operand[operand.find("+") + 1:operand.find("]")]
        elif operand.count("+") == 2:
            # [base reg + reg + name]
            name = operand[operand.rfind("+") + 1:operand.find("]")]
        elif operand.count("+") > 2:
            #try to find var_XX mask
            if "var_" in operand:
                # [reg1+x*reg2+arg_XX+value] or [reg1+x*reg2+value+arg_XX]
                if operand.find("var_") > operand.rfind("+"):
                    operand = operand[operand.find("var_"):operand.find("]")]
                else:
                    operand = operand[operand.find("var_"):operand.rfind("+")]
            #try to find arg_XX mask
            elif "arg_" in operand:
                # [reg1+x*reg2+arg_XX+value] or [reg1+x*reg2+value+arg_XX]
                if operand.find("var_") > operand.rfind("+"):
                    operand = operand[operand.find("arg_"):operand.find("]")]
                else:
                    operand = operand[operand.find("arg_"):operand.rfind("+")]
            else:
                print "WARNING: unknown operand mask ", operand, hex(head)
                name = None
        else:
            name = None
        return name

    def get_oviedo_df(self, local_vars):
        '''
        The function calculates Oviedo's DF value
        @local_vars - a dictionary of local variables for function
        @return - Oviedo's DF value
        '''
        oviedo_df = 0
        # get local variables usage count, except initialization, such as:
        # mov [ebp+var_0], some_value
        for local_var in local_vars:
            usage_list = local_vars.get(local_var, None)
            if usage_list == None:
                print "WARNING: empty usage list for ", local_var
                continue
            for instr_addr in usage_list:
                instr_mnem = idc.GetMnem(int(instr_addr, 16))
                if instr_mnem.startswith('mov'):
                    # get local var position
                    operands = self.get_instr_operands(int(instr_addr, 16))
                    for idx, (operand, type) in enumerate(operands):
                        if local_var in operand and idx == 0:
                            oviedo_df -= 1
                            break
            oviedo_df += len(usage_list)
        return oviedo_df

    def get_chepin(self, local_vars, function_ea, function_metrics):
        '''
        The function calculates Chepin metric
        @local_vars - a dictionary of local variables
        @function_ea - function entry address
        @function_metrics - function metrics structure
        @return - Chepin value
        '''
        chepin = 0
        p = 0
        m = 0
        c = 0
        tmp_dict = dict()
        var_args_tmp = dict()
        (p, var_args_tmp) = self.get_function_args_count(function_ea, local_vars)
        for local_var in local_vars:
            usage_list = local_vars.get(local_var, None)
            if usage_list == None:
                print "WARNING: empty usage list for ", local_var
                continue
            for instr_addr in usage_list:
                instr_mnem = idc.GetMnem(int(instr_addr, 16))
                if instr_mnem.startswith('cmp') or instr_mnem.startswith('test'):
                    tmp_dict.setdefault(local_var, []).append(instr_addr)

        for var_arg in var_args_tmp:
            if var_arg in local_vars:
                del local_vars[var_arg]
        for cmp_var in tmp_dict:
            if cmp_var in local_vars:
                del local_vars[cmp_var]

        c = len(tmp_dict)
        m = len(local_vars)
        chepin = p + 2*m + 3*c
        return chepin

    def get_unique_vars_read_write_count(self, vars_dict):
        '''
        The function performs evaluation of read/write count for each
        variable in dictionary.
        @vars_dict - a dictionary of variable to get count
        @return - two dictionaries of read and write for each variable
        '''
        tmp_dict_read = dict()
        tmp_dict_write = dict()
        for arg_var in vars_dict:
            usage_list = vars_dict.get(arg_var, None)
            if usage_list == None:
                print "WARNING: empty usage list for ", arg_var
                continue
            for instr_addr in usage_list:
                instr_type = GetInstructionType(int(instr_addr,16))
                if instr_type == ASSIGNMENT_INSTRUCTION:
                    #detect operand position
                    ops = self.get_instr_operands(int(instr_addr, 16))
                    for idx, (op, type) in enumerate(ops):
                        if arg_var in op and idx == 0:
                            tmp_dict_write[arg_var] = tmp_dict_write.get(arg_var, 0) + 1
                            break
                        else:
                            tmp_dict_read[arg_var] = tmp_dict_read.get(arg_var, 0) + 1
                elif instr_type == COMPARE_INSTRUCTION:
                    tmp_dict_read[arg_var] = tmp_dict_read.get(arg_var, 0) + 1
                elif instr_type == STACK_PUSH_INSTRUCTION:
                    tmp_dict_write[arg_var] = tmp_dict_write.get(arg_var, 0) + 1
                else:
                    continue
        return len(tmp_dict_read), len(tmp_dict_write)

    def get_henryncafura_metric(self, function_ea, function_metrics):
        '''
        The function performs evaluation of Henry&Cafura metric
        @function_ea - function entry address
        @function_metrics - function_metrics structure
        @return - Henry&Cafura metric
        '''
        function_metrics.fan_out_s = len(function_metrics.calls_dict)
        refs_to = idautils.CodeRefsTo(function_ea, 0)
        function_metrics.fan_in_s = sum(1 for y in refs_to)

        (count, function_metrics.vars_args) = self.get_function_args_count(function_ea, function_metrics.vars_local)

        # check input args
        (read, write) = self.get_unique_vars_read_write_count(function_metrics.vars_args)
        function_metrics.fan_in_i += read
        function_metrics.fan_out_i += write
        # check global variables list
        (read, write) = self.get_unique_vars_read_write_count(function_metrics.global_vars_used)
        function_metrics.fan_in_i += read
        function_metrics.fan_out_i += write

        fan_in = function_metrics.fan_in_s + function_metrics.fan_in_i
        fan_out = function_metrics.fan_out_s + function_metrics.fan_out_i
        return function_metrics.CC + pow((fan_in + fan_out), 2)

    def get_static_metrics(self, function_ea):
        """
        The function calculates all supported metrics.
        @function_ea - function address
        @return - function metrics structure
        """
        f_start = function_ea
        f_end = idc.FindFuncEnd(function_ea)
        function_metrics = Metrics_function(function_ea)

        edges = set()
        boundaries = Set((f_start,))
        mnemonics = dict()
        operands = dict()
        node_graph = None
        cases_in_switches = 0

        chunks = self.enumerate_function_chunks(f_start)
        # For each defined chunk in the function.
        for chunk in chunks:
            for head in idautils.Heads(chunk[0], chunk[1]):
                # If the element is an instruction
                if head == hex(0xffffffffL):
                    raise Exception("Invalid head for parsing")
                if isCode(idc.GetFlags(head)):
                    function_metrics.loc_count += 1
                    # Get the references made from the current instruction
                    # and keep only the ones local to the function.
                    refs = idautils.CodeRefsFrom(head, 0)
                    refs_filtered = set()
                    for ref in refs:
                        if ref == hex(0xffffffffL):
                            print "Invalid reference for head", head
                            raise Exception("Invalid reference for head")
                        for chunk_filter in chunks:
                            if ref >= chunk_filter[0] and ref < chunk_filter[1]:
                                refs_filtered.add(ref)
                                break
                    refs = refs_filtered
                    # Get instruction type and increase metrics
                    instruction_type = GetInstructionType(head)
                    if instruction_type == BRANCH_INSTRUCTION:
                        function_metrics.condition_count += 1
                    elif instruction_type == CALL_INSTRUCTION:
                        function_metrics.calls_count += 1
                        # set dict of function calls
                        opnd = idc.GetOpnd(head, 0)
                        if opnd not in registers:
                            opnd = opnd.replace("ds","")
                            function_metrics.calls_dict[opnd] = function_metrics.calls_dict.get(opnd, 0) + 1
                        else:
                            opnd = idc.GetDisasm(head)
                            opnd = opnd[opnd.find(";") + 1:]
                            opnd = opnd.replace(" ", "")
                            if opnd != None:
                                function_metrics.calls_dict[opnd] = function_metrics.calls_dict.get(opnd, 0) + 1
                        # Thus, we skip dynamic function calls (e.g. call eax)
                    elif instruction_type == ASSIGNMENT_INSTRUCTION:
                        function_metrics.assign_count += 1
                    # Get the mnemonic and increment the mnemonic count
                    mnem = idc.GetMnem(head)
                    comment = idc.GetCommentEx(head, 0)
                    if comment != None and comment.startswith('switch') and 'jump' not in comment:
                        case_count = comment[7:]
                        space_index = case_count.find(" ")
                        case_count = case_count[:space_index]
                        case_count = int(case_count)
                        # there is calc_switch_cases idaapi function
                        cases_in_switches += case_count
                    mnemonics[mnem] = mnemonics.get(mnem, 0) + 1

                    if instruction_type != BRANCH_INSTRUCTION and instruction_type != CALL_INSTRUCTION:
                        ops = self.get_instr_operands(head)
                        for idx, (op,type) in enumerate(ops):
                            operands[op] = operands.get(op, 0) + 1
                            if type == 2:
                                if self.is_var_global(idc.GetOperandValue(head,idx), head) and "__" not in op:
                                    self.global_vars_dict[op] = operands.get(op, 0) + 1
                                    function_metrics.global_vars_used.setdefault(op, []).append(hex(head))
                                    function_metrics.global_vars_access += 1
                                elif "__" not in op:
                                    # static variable
                                    name = op
                                    function_metrics.vars_local.setdefault(name, []).append(hex(head))
                            elif type == 3 or type == 4:
                                name = self.get_local_var_name(op, head)
                                if name:
                                    function_metrics.vars_local.setdefault(name, []).append(hex(head))

                    if refs:
                        # If the flow continues also to the next (address-wise)
                        # instruction, we add a reference to it.
                        # For instance, a conditional jump will not branch
                        # if the condition is not met, so we save that
                        # reference as well.
                        next_head = idc.NextHead(head, chunk[1])
                        if next_head == hex(0xffffffffL):
                            print "Invalid next head after ", head
                            raise Exception("Invalid next head")
                        if isFlow(idc.GetFlags(next_head)):
                            refs.add(next_head)

                        # Update the boundaries found so far.
                        boundaries.union_update(refs)
                        # For each of the references found, and edge is
                        # created.
                        for r in refs:
                            # If the flow could also come from the address
                            # previous to the destination of the branching
                            # an edge is created.
                            if isFlow(idc.GetFlags(r)):
                                prev_head = hex(idc.PrevHead(r, chunk[0]))
                                if prev_head == hex(0xffffffffL):
                                    edges.add((hex(head), hex(r)))
                                    #raise Exception("invalid reference to previous instruction for", hex(r))
                                else:
                                    edges.add((prev_head, hex(r)))
                            edges.add((hex(head), hex(r)))
        # i#7: New algorithm of edges and boundaries constructing is required..
        # Now boundaries and edges are making by using internal IDA functionality
        # but it doesn't work for functions which have jumps beyond function boundaries
        # (or jumps to "red" areas of code). Now we're generating warning in such
        # situations but we need to manually parse all instructions.
        bbls = self.get_bbls(chunks, boundaries, edges)
        # save bbls boundaries in dict
        for bbl in bbls:
            function_metrics.bbls_boundaries[bbl[0]] = [x for x in bbl]
        #Cyclomatic complexity CC = E - V + 2
        if self.metrics_mask["cc"] == 1 or self.metrics_mask["cocol"] == 1:       
            function_metrics.CC = len(edges) - len(boundaries) + 2

        # R measure
        function_metrics.R = len(edges)/len(boundaries)
        #Basic blocks count
        function_metrics.bbl_count = len(boundaries)
        #Jilb's metric: cl = CL/n
        if self.metrics_mask["jilb"] == 1:
            function_metrics.CL = (float(function_metrics.condition_count) + \
                                   function_metrics.calls_count)/function_metrics.loc_count
        # ABC metric: ABC = sqrt(A*A + B*B + C*C)
        if self.metrics_mask["abc"] == 1:
            function_metrics.ABC = pow(function_metrics.assign_count, 2) +\
                                   pow(function_metrics.condition_count, 2) +\
                                   pow(function_metrics.calls_count, 2)
            function_metrics.ABC = math.sqrt(function_metrics.ABC)
        # Create node graph
        if self.metrics_mask["harr"] == 1 or self.metrics_mask["bound"] == 1 or self.metrics_mask["pi"] == 1:
            node_graph = self.make_graph(edges, bbls, boundaries)

        #Harrison metric: f = sum(ci) i: 0...n
        if self.metrics_mask["harr"] == 1:
            function_metrics.Harrison = self.get_harrison_metric(node_graph, bbls)

        #boundary values metric: Sa = sum(nodes_complexity)
        if self.metrics_mask["bound"] == 1:
            function_metrics.boundary_values = self.get_boundary_value_metric(node_graph)

        #CC_modified assumes switch (without default) as 1 edge and 1 node
        if self.metrics_mask["cc_mod"] == 1:
            if cases_in_switches:
                function_metrics.CC_modified = (len(edges) - ((cases_in_switches - 1)*2)) - (len(boundaries) - (cases_in_switches - 1)) + 2
            else:
                function_metrics.CC_modified = function_metrics.CC
        #Pivovarsky metric: N(G) = CC_modified + sum(pi) i: 0...n
        if self.metrics_mask["pi"] == 1:
            function_metrics.Pivovarsky = function_metrics.CC_modified + self.get_boundary_value_metric(node_graph, True)

        #Halstead metric. see http://en.wikipedia.org/wiki/Halstead_complexity_measures
        if self.metrics_mask["h"] == 1 or self.metrics_mask["cocol"] == 1:
            function_metrics.Halstead_basic.N1 = function_metrics.loc_count
            function_metrics.Halstead_basic.n1 = len(mnemonics)
            function_metrics.Halstead_basic.n2 = len(operands)
            if len(operands) != 0:
                function_metrics.Halstead_basic.N2 = sum(v for v in operands.itervalues())
                function_metrics.Halstead_basic.calculate()

        #Span metric
        if self.metrics_mask["span"] == 1:
            function_metrics.span_metric = self.get_span_metric(function_metrics.bbls_boundaries)

        # Oviedo metric C = aCF + bsum(DFi)
        if self.metrics_mask["oviedo"] == 1:
            function_metrics.Oviedo = len(edges) + self.get_oviedo_df(function_metrics.vars_local)

        # Chepin metric Q= P+2M+3C
        if self.metrics_mask["chepin"] == 1:
            function_metrics.Chepin = self.get_chepin(function_metrics.vars_local, function_ea, function_metrics)

        # Henry and Cafura metric
        if self.metrics_mask["h&c"] == 1 or self.metrics_mask["c&s"] == 1:
            function_metrics.HenrynCafura = self.get_henryncafura_metric(function_ea, function_metrics)

        # Card and Glass metric C = S + D
        if self.metrics_mask["c&s"] == 1:
            function_metrics.CardnGlass = pow((function_metrics.fan_out_i + function_metrics.fan_out_s), 2) +\
                                  (len(function_metrics.vars_args))/(function_metrics.fan_out_i + function_metrics.fan_out_s + 1)
        #free memory
        if node_graph:
            node_graph.clear()
        function_metrics.vars_local.clear()
        function_metrics.vars_args.clear()
        function_metrics.global_vars_used.clear()
        function_metrics.calls_dict.clear()
        mnemonics.clear()
        operands.clear()
        edges.clear()
        boundaries.clear()
        gc.collect()
        return function_metrics

def init_analysis (metrics_used):
    metrics_total = Metrics()
    metrics_total.start_analysis(metrics_used)
    
    current_time = strftime("%Y-%m-%d_%H-%M-%S")
    analyzed_file = idc.GetInputFile()
    analyzed_file = analyzed_file.replace(".","_")
    mask = analyzed_file + "_" + current_time + ".txt"
    name = AskFile(1, mask, "Where to save metrics ?")
    
    save_results(metrics_total, name)       
    return 0


class UI:
    def __init__(self, callback):
        self.mask = []
        self.metrics_used = dict()
        self.top = Tkinter.Tk()
        self.top.wm_title("Select metrics to calculate")        
        for i in enumerate(metrics_list):
            self.mask.append(IntVar())
        frame = Frame(self.top)
        frame.pack()
        bottomframe4 = Frame(self.top)
        bottomframe4.pack(side = BOTTOM)
        bottomframe3 = Frame(self.top)
        bottomframe3.pack(side = BOTTOM)
        bottomframe2 = Frame(self.top)
        bottomframe2.pack(side = BOTTOM)
        bottomframe1 = Frame(self.top)
        bottomframe1.pack(side = BOTTOM)
        for iter,i in enumerate(self.mask):
            if iter < 5:
                frame_temp = frame
            elif iter >= 5 and iter < 10:
                frame_temp = bottomframe1
            elif iter >= 10 and iter < 15:
                frame_temp = bottomframe2
            elif iter >=15:
                frame_temp = bottomframe3
            Checkbutton(frame_temp, text = metrics_names[iter], variable = i, \
                        onvalue = 1, offvalue = 0).pack(side=LEFT)      

        Button(bottomframe4, text = "Start", height=2, width = 10, \
               command = lambda: self.GetUserChoice(callback)).pack(side=LEFT)
        Button(bottomframe4, text = "Calculate all", height=2, width = 10, \
               command =lambda: self.CalculateAll(callback)).pack(side=LEFT)
        self.top.mainloop()
        
    def CalculateAll(self, callback):
        ''' The routine sets all metrics as used and calls callback function
        @ callback - callback function
        '''
        self.top.destroy()
        for i in metrics_list:
            self.metrics_used[i] = 1
        callback(self.metrics_used)
        return 0

    def GetUserChoice(self, callback):
        ''' The routine parses user choice and than calls callback function
        @ callback - callback function
        '''
        self.top.destroy()
        #parse user choice
        for iter,i in enumerate(metrics_list):
            self.metrics_used[i] = self.mask[iter].get()
        callback(self.metrics_used)
        return 0

def save_results(metrics_total, name):
    
    print 'Average lines of code in a function:', metrics_total.average_loc_count
    print 'Total number of functions:', metrics_total.total_func_count
    print 'Total lines of code:', metrics_total.total_loc_count
    print 'Total bbl count:', metrics_total.total_bbl_count
    print 'Total assignments count:', metrics_total.total_assign_count
    print 'Total R count:', metrics_total.R_total
    print 'Total Cyclomatic complexity:', metrics_total.CC_total
    print 'Total Jilb\'s metric:', metrics_total.CL_total
    print 'Total ABC:', metrics_total.ABC_total
    print 'Halstead:', metrics_total.Halstead_total.B
    print 'Pivovarsky:', metrics_total.Pivovarsky_total
    print 'Harrison:', metrics_total.Harrison_total
    print 'Boundary value', metrics_total.boundary_values_total
    print 'Span metric', metrics_total.span_metric_total
    print 'Global var metric', metrics_total.global_vars_metric_total
    print 'Oviedo metric', metrics_total.Oviedo_total
    print 'Chepin metric', metrics_total.Chepin_total
    print 'Henry&Cafura metric', metrics_total.HenrynCafura_total
    print 'Cocol metric', metrics_total.Cocol_total
    print 'Card&Glass metric', metrics_total.CardnGlass_total
    #Save in log file
    
    if name == None:
        return 0
    f = open(name, 'w')
    f.write('Average lines of code in a function: ' + str(metrics_total.average_loc_count) + "\n")
    f.write('Total number of functions: ' + str(metrics_total.total_func_count) + "\n")
    f.write('Total lines of code: ' + str(metrics_total.total_loc_count) + "\n")
    f.write('Total bbl count: ' + str(metrics_total.total_bbl_count) + "\n")
    f.write('Total assignments count: ' + str(metrics_total.total_assign_count) + "\n")
    f.write('Total R count: ' + str(metrics_total.R_total) + "\n")
    f.write('Total Cyclomatic complexity: ' + str(metrics_total.CC_total) + "\n")
    f.write('Total Jilb\'s metric: ' + str(metrics_total.CL_total) + "\n")
    f.write('Total ABC: ' + str(metrics_total.ABC_total) + "\n")
    f.write('Total Halstead:' + str(metrics_total.Halstead_total.B) + "\n")
    f.write('Total Pivovarsky: ' + str(metrics_total.Pivovarsky_total) + "\n")
    f.write('Total Harrison: ' + str(metrics_total.Harrison_total) + "\n")
    f.write('Total Boundary value: ' + str(metrics_total.boundary_values_total) + "\n")
    f.write('Total Span metric: ' + str(metrics_total.span_metric_total) + "\n")
    f.write('Total Oviedo metric: ' + str(metrics_total.Oviedo_total) + "\n")
    f.write('Total Chepin metric: ' + str(metrics_total.Chepin_total) + "\n")
    f.write('Henry&Cafura metric: ' + str(metrics_total.HenrynCafura_total) + "\n")
    f.write('Cocol metric: ' + str(metrics_total.Cocol_total) + "\n")
    f.write('CardnGlass metric: ' + str(metrics_total.CardnGlass_total) + "\n")
    for function in metrics_total.functions:
        f.write(str(function) + "\n")
        f.write('  Lines of code in the function: ' + str(metrics_total.functions[function].loc_count) + "\n")
        f.write('  Bbls count: ' + str(metrics_total.functions[function].bbl_count) + "\n")
        f.write('  Condition count: ' + str(metrics_total.functions[function].condition_count) + "\n")
        f.write('  Calls count: ' + str(metrics_total.functions[function].calls_count) + "\n")
        f.write('  Assignments count: ' + str(metrics_total.functions[function].assign_count) + "\n")
        f.write('  Cyclomatic complexity: ' + str(metrics_total.functions[function].CC) + "\n")
        f.write('  Cyclomatic complexity modified: ' + str(metrics_total.functions[function].CC_modified) + "\n")
        f.write('  Jilb\'s metric: ' + str(metrics_total.functions[function].CL) + "\n")
        f.write('  ABC: ' + str(metrics_total.functions[function].ABC) + "\n")
        f.write('  R count: ' + str(metrics_total.functions[function].R) + "\n")

        f.write('    Halstead.B: ' + str(metrics_total.functions[function].Halstead_basic.B) + "\n")
        f.write('    Halstead.E: ' + str(metrics_total.functions[function].Halstead_basic.E) + "\n")
        f.write('    Halstead.D: ' + str(metrics_total.functions[function].Halstead_basic.D) + "\n")
        f.write('    Halstead.N*: ' + str(metrics_total.functions[function].Halstead_basic.Ni) + "\n")
        f.write('    Halstead.V: ' + str(metrics_total.functions[function].Halstead_basic.V) + "\n")
        f.write('    Halstead.N1: ' + str(metrics_total.functions[function].Halstead_basic.N1) + "\n")
        f.write('    Halstead.N2: ' + str(metrics_total.functions[function].Halstead_basic.N2) + "\n")
        f.write('    Halstead.n1: ' + str(metrics_total.functions[function].Halstead_basic.n1) + "\n")
        f.write('    Halstead.n2: ' + str(metrics_total.functions[function].Halstead_basic.n2) + "\n")

        f.write('  Pivovarsky: ' + str(metrics_total.functions[function].Pivovarsky) + "\n")
        f.write('  Harrison: ' + str(metrics_total.functions[function].Harrison) + "\n")
        f.write('  Cocol metric' + str(metrics_total.functions[function].Cocol) + "\n")

        f.write('  Boundary value: ' + str(metrics_total.functions[function].boundary_values) + "\n")
        f.write('  Span metric: ' + str(metrics_total.functions[function].span_metric) + "\n")
        f.write('  Global vars metric:' + str(metrics_total.functions[function].global_vars_metric) + "\n")
        f.write('  Oviedo metric: ' + str(metrics_total.functions[function].Oviedo) + "\n")
        f.write('  Chepin metric: ' + str(metrics_total.functions[function].Chepin) + "\n")
        f.write('  CardnGlass metric: ' + str(metrics_total.functions[function].CardnGlass) + "\n")
        f.write('  Henry&Cafura metric: ' + str(metrics_total.functions[function].HenrynCafura) + "\n")
    f.close()

def main():
    print "Start metrics calculation" 
    idc.Wait() #wait while ida finish analysis
    if os.getenv('IDAPYTHON') != 'auto':
        ui_setup = UI(init_analysis)
        print "done"
        return 0
    else: #hidden mode
        metrics_mask = dict()
        # calculate all metrics
        for i in metrics_list:
            metrics_mask[i] = 1

        metrics_total = Metrics()
        metrics_total.start_analysis(metrics_mask)
        current_time = strftime("%Y-%m-%d_%H-%M-%S")
        analyzed_file = idc.GetInputFile()
        analyzed_file = analyzed_file.replace(".","_")
        name = os.getcwd()
        name = name + "/" + analyzed_file + "_" + current_time + ".txt"
        save_results(metrics_total, name)
    
    if os.getenv('IDAPYTHON') == 'auto':
        Exit(0)
    return 1
if __name__ == "__main__":
    main()