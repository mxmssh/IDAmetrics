"""
IDA-metrics_static plugin ver. 0.1

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
    8. Jilb's metric (function/module)
    9. ABC metric (function/module)
    10. Pivovarsky metric (function/module)
    11. Halstead metric (function/module)
    12. Harrison metric (function/module)
    13. Boundary value metric (function/module)
Additional functionality:
     - node graph generation (function)
     - basic block boundaries generation (function)
"""

import idc
import idaapi
import idautils
import math
from collections import defaultdict
from sets import Set
from idaapi import *

OTHER_INSTRUCTION = 0
CALL_INSTRUCTION = 1
BRANCH_INSTRUCTION = 2
ASSIGNMENT_INSTRUCTION = 3

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
# i#1 add MMX/SSEx/AVX/64bit mode instructions.
# i#2 add tests

def GetInstructionType(instr_addr):
    instr_mnem = idc.GetMnem(instr_addr)
    if instr_mnem.startswith('call'):
        return CALL_INSTRUCTION
    elif instr_mnem.startswith('j'):
        # It seems that there is no other type of instruction
        # starting with j in x86/x86_64
        return BRANCH_INSTRUCTION
    for assign_instr_mnem in assign_instructions_general:
        if instr_mnem.startswith(assign_instr_mnem):
            return ASSIGNMENT_INSTRUCTION
    for assign_instr_mnem in assign_instructions_fp:
        if instr_mnem.startswith(assign_instr_mnem):
            return ASSIGNMENT_INSTRUCTION
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
        self.Ni = self.n1 * math.log(self.n1, 2) + self.n2 * math.log(self.n2, 2)
        self.V = N * math.log(n, 2)
        self.D = (self.n1/2)*(self.N2/self.n2)
        self.E = self.D * self.V
        self.B = (self.E**(2.0/3.0))/3000

class Metrics_function:
    def __init__(self, function_ea):
        self.function_ea = function_ea
        self.loc_count = 0
        self.bbl_count = 0
        self.condition_count = 0
        self.calls_count = 0
        self.CC = 0
        self.CL = 0
        self.assign_count = 0
        self.ABC = 0
        self.CC_modified = 0
        self.Pivovarsky = 0
        self.Halstead_basic = Halstead_metric()
        self.Harrison = 0
        self.boundary_values = 0.0
class Metrics:
    def __init__(self):
        self.total_loc_count = 0
        self.average_loc_count = 0.0
        self.total_bbl_count = 0
        self.total_func_count = 0
        self.total_condition_count = 0
        self.total_assign_count = 0
        self.node_graph = dict()
        self.CC_total = 0
        self.CL_total = 0
        self.ABC_total = 0
        self.Halstead_total = Halstead_metric()
        self.CC_modified_total = 0
        self.Pivovarsky_total = 0
        self.Harrison_total = 0.0
        self.boundary_values_total = 0.0
        self.functions = dict()

        # For each of the segments
        for seg_ea in Segments():
            # For each of the functions
            for function_ea in Functions(seg_ea, SegEnd(seg_ea)):
                function_name = GetFunctionName(function_ea)
                self.functions[function_name] = self.get_static_metrics(function_ea)
                self.total_loc_count += self.functions[function_name].loc_count
                self.total_bbl_count += self.functions[function_name].bbl_count
                self.total_func_count += 1
                self.total_condition_count += self.functions[function_name].condition_count
                self.total_assign_count += self.functions[function_name].assign_count

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

        self.average_loc_count = self.total_loc_count / self.total_func_count
        self.Halstead_total.calculate()

    def get_bbl_head(self, head):
        """
        The function returns address of the head instruction
        for the basic block.
        @head - address of arbitrary instruction in the basic block.
        @return - head address of the basic block.
        """

        while 1:
            prev_head = PrevHead(head, 0)
            if isFlow(GetFlags(prev_head)):
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
        The function gets list of the chunks for the function.
        @f_start - first address of the function with chunks
        @return - list of the chunks
        """
        # Enumerate all chunks in the function
        chunks = list()
        first_chunk = FirstFuncFchunk(f_start)
        chunks.append((first_chunk, GetFchunkAttr(first_chunk, FUNCATTR_END)))
        next_chunk = first_chunk
        while next_chunk != 0xffffffffL:
            next_chunk = NextFuncFchunk(f_start, next_chunk)
            if next_chunk != 0xffffffffL:
                chunks.append((next_chunk, GetFchunkAttr(next_chunk, FUNCATTR_END)))
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
        child_nodes = self.node_graph.get(node, None)
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
        child_nodes = self.node_graph.get(node, None)
        if child_nodes != None:
            for child_node in child_nodes:
                if child_node in nodes_passed:
                    continue
                bbls_node = bbls_dict.get(child_node, None)
                if bbls_node == None:
                    print "WARNING: couldn't find bbl for child node: ", child_node
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
            # check for additional chunks (xref i#8)
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

    def get_static_metrics(self, function_ea):
        """
        The function calculate all supported metrics.
        @function_ea - function address
        @return - function metrics structure
        """

        f_start = function_ea
        f_end = FindFuncEnd(function_ea)
        function_metrics = Metrics_function(function_ea)

        edges = set()
        bbls = []
        bbl = []
        boundaries = Set((f_start,))
        mnemonics = dict()
        operands = dict()
        cases_in_switches = 0

        chunks = self.enumerate_function_chunks(f_start)
        # For each defined chunk in the function.
        for chunk in chunks:
            for head in Heads(chunk[0], chunk[1]):
                # If the element is an instruction
                if head == hex(0xffffffffL):
                    raise Exception("Invalid head for parsing")
                if isCode(GetFlags(head)):
                    function_metrics.loc_count += 1
                    # Get the references made from the current instruction
                    # and keep only the ones local to the function.
                    refs = CodeRefsFrom(head, 0)
                    refs_filtered = set()
                    for ref in refs:
                        if ref == hex(0xffffffffL):
                            print "Invalid reference for head", head
                            raise Exception("Invalid reference for head")
                        for chunk_filter in chunks:
                            if ref >= chunk_filter[0] and ref <= chunk_filter[1]:
                                refs_filtered.add(ref)
                                break
                    refs = refs_filtered
                    # Get instruction type and increase metrics
                    instruction_type = GetInstructionType(head)
                    if instruction_type == BRANCH_INSTRUCTION:
                        function_metrics.condition_count += 1
                    elif instruction_type == CALL_INSTRUCTION:
                        function_metrics.calls_count += 1
                    elif instruction_type == ASSIGNMENT_INSTRUCTION:
                        function_metrics.assign_count += 1
                    # Get the mnemonic and increment the mnemonic count
                    mnem = GetMnem(head)
                    comment = GetCommentEx(head, 0)
                    if comment != None and 'switch' in comment and 'jump' not in comment:
                        case_count = comment[7:]
                        space_index = case_count.find(" ")
                        case_count = case_count[:space_index]
                        case_count = int(case_count)
                        cases_in_switches += case_count 
                    mnemonics[mnem] = mnemonics.get(mnem, 0) + 1
                    i = 0
                    while i < 4:
                        op = GetOpnd(head, i)                      
                        if op != "":
                            operands[op] = operands.get(op, 0) + 1
                        i += 1
                    if refs:
                        # If the flow continues also to the next (address-wise)
                        # instruction, we add a reference to it.
                        # For instance, a conditional jump will not branch
                        # if the condition is not met, so we save that
                        # reference as well.
                        next_head = NextHead(head, chunk[1])
                        if next_head == hex(0xffffffffL):
                            print "Invalid next head after ", head
                            raise Exception("Invalid next head")
                        if isFlow(GetFlags(next_head)):
                            refs.add(next_head)

                        # Update the boundaries found so far.
                        boundaries.union_update(refs)
                        # For each of the references found, and edge is
                        # created.
                        for r in refs:
                            # If the flow could also come from the address
                            # previous to the destination of the branching
                            # an edge is created.
                            if isFlow(GetFlags(r)):
                                prev_head = hex(PrevHead(r, chunk[0]))
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
        
        # set bbls using edges and boundaries
        # NOTE: We can handle if jump xrefs to chunk address space.
        for chunk in chunks:
            for head in Heads(chunk[0], chunk[1]):
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
        if len(bbl) > 0:
            bbls.append(bbl)

        #Cyclomatic complexity CC = E - V + 2
        function_metrics.CC = len(edges) - len(boundaries) + 2
        #Basic blocks count
        function_metrics.bbl_count = len(boundaries)
        #Jilb's metric: cl = CL/n
        function_metrics.CL = (float(function_metrics.condition_count) + function_metrics.calls_count)/function_metrics.loc_count
        # ABC metric: ABC = sqrt(A*A + B*B + C*C)
        function_metrics.ABC = pow(function_metrics.assign_count, 2) +\
                               pow(function_metrics.condition_count, 2) +\
                               pow(function_metrics.calls_count, 2)
        function_metrics.ABC = math.sqrt(function_metrics.ABC)
        # Create node graph
        self.node_graph = self.make_graph(edges, bbls, boundaries)

        #Harrison metric: f = sum(ci) i: 0...n
        function_metrics.Harrison = self.get_harrison_metric(self.node_graph, bbls)

        #boundary values metric: Sa = sum(nodes_complexity)
        function_metrics.boundary_values = self.get_boundary_value_metric(self.node_graph)
        function_metrics.boundary_values = function_metrics.boundary_values
        
        #CC_modified assumes switch (without default) as 1 edge and 1 node
        if cases_in_switches:
            function_metrics.CC_modified = (len(edges) - ((cases_in_switches - 1)*2)) - (len(boundaries) - (cases_in_switches - 1)) + 2
        else:
            function_metrics.CC_modified = function_metrics.CC
        #Pivovarsky metric: N(G) = CC_modified + sum(pi) i: 0...n
        function_metrics.Pivovarsky = function_metrics.CC_modified + self.get_boundary_value_metric(self.node_graph, True)
        
        #Halstead metric. see http://en.wikipedia.org/wiki/Halstead_complexity_measures
        function_metrics.Halstead_basic.N1 = function_metrics.loc_count
        function_metrics.Halstead_basic.n1 = len(mnemonics)
        function_metrics.Halstead_basic.n2 = len(operands)
        if len(operands) != 0:
            function_metrics.Halstead_basic.N2 = sum(v for v in operands.itervalues())
            function_metrics.Halstead_basic.calculate()
        return function_metrics

        
''' Usage example '''
print "Start metrics calculation"

metrics_total = Metrics()
print 'Average lines of code in a function:', metrics_total.average_loc_count
print 'Total number of functions:', metrics_total.total_func_count
print 'Total lines of code:', metrics_total.total_loc_count
print 'Total bbl count:', metrics_total.total_bbl_count
print 'Total assignments count:', metrics_total.total_assign_count
print 'Total Cyclomatic complexity:', metrics_total.CC_total
print 'Total Jilb\'s metric:', metrics_total.CL_total
print 'Total ABC:', metrics_total.ABC_total
print 'Halstead:', metrics_total.Halstead_total.B
print 'Pivovarsky:', metrics_total.Pivovarsky_total
print 'Harrison:', metrics_total.Harrison_total
print 'Boundary value', metrics_total.boundary_values_total
#Save in log file
f = open('C:\log.txt', 'w')
f.write('Average lines of code in a function: ' + str(metrics_total.average_loc_count) + "\n")
f.write('Total number of functions: ' + str(metrics_total.total_func_count) + "\n")
f.write('Total lines of code: ' + str(metrics_total.total_loc_count) + "\n")
f.write('Total bbl count: ' + str(metrics_total.total_bbl_count) + "\n")
f.write('Total assignments count: ' + str(metrics_total.total_assign_count) + "\n")
f.write('Total Cyclomatic complexity: ' + str(metrics_total.CC_total) + "\n")
f.write('Total Jilb\'s metric: ' + str(metrics_total.CL_total) + "\n")
f.write('Total ABC: ' + str(metrics_total.ABC_total) + "\n")
f.write('Total Halstead:' + str(metrics_total.Halstead_total.B) + "\n")
f.write('Total Pivovarsky: ' + str(metrics_total.Pivovarsky_total) + "\n")
f.write('Total Harrison: ' + str(metrics_total.Harrison_total) + "\n")
f.write('Total Boundary value: ' + str(metrics_total.boundary_values_total) + "\n")


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
    f.write('  Boundary value: ' + str(metrics_total.functions[function].boundary_values) + "\n")
    
f.close()

print "done"
