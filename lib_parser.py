"""
IDAMetrics_basic IDA plugin ver. 0.1

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
TODO: script description
"""

import sys
import idc
import idaapi
import idautils
import math
import gc
from time import strftime


__EA64__ = idaapi.BADADDR == 0xFFFFFFFFFFFFFFFFL

FUNCATTR_END     =  4     # function end address
ARGUMENT_SIZE    =  4
if __EA64__:
    FUNCATTR_END     = 8
    ARGUMENT_SIZE = 8

  
MODE_INSTRUMENT_SUBCALLS = 0
MODE_DONT_INSTRUMENT_SUBCALLS = 1
SILENT = 1
MANUAL = 0


def enumerate_function_chunks(f_start):
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

def get_list_of_function_instr(addr, mode):
    #TODO follow subcalls MODE_INSTRUMENT_SUBCALLS
    f_start = addr
    f_end = idc.FindFuncEnd(addr)
    chunks = enumerate_function_chunks(f_start)
    list_of_addr = list()
    image_base = idaapi.get_imagebase(addr)
    for chunk in chunks:
        for head in idautils.Heads(chunk[0], chunk[1]):
            # If the element is an instruction
            if head == hex(0xffffffffL):
                raise Exception("Invalid head for parsing")
            if isCode(idc.GetFlags(head)):
                head = head - image_base
                head = str(hex(head))
                head = head.replace("L", "")
                head = head.replace("0x", "")
                list_of_addr.append(head)
    return list_of_addr
    
    
def find_function(function):
    for seg_ea in idautils.Segments():
        # For each of the functions
        function_ea = seg_ea
        while function_ea != 0xffffffffL:
            function_name = idc.GetFunctionName(function_ea)
            function = function.replace("\n", "")
            function = function.replace("\r", "")
            function = function.replace(" ", "")
            if function.lower() == function_name.lower():
                print "Found function ", function_name
                print hex(function_ea)
                return function_ea
            function_ea = idc.NextFunction(function_ea)  
    return -1


def save_instrumented(list_of_addr, is_silent):
    dll_name = idc.GetInputFile()
    dll_name = dll_name[:dll_name.find(".")]
    dll_name = dll_name + "!"
    print dll_name
    if is_silent == SILENT:
        current_time = strftime("%Y-%m-%d_%H-%M-%S")
        analyzed_file = idc.GetInputFile()
        analyzed_file = analyzed_file.replace(".","_")
        file_name = analyzed_file + "_" + current_time + ".txt"
    else:
        file_name = AskFile(1, "dllcode.in", "Please specify a file to save results.")
        if file_name == -1:
            return 0
    
    file = open(file_name, 'w')
    for sublist in list_of_addr:
        for addr in sublist:
            #print addr
            file.write(dll_name + addr + "\n")
    file.close()

def init_analysis (file_path, mode, is_silent):
    file = open(file_path, 'r')
    if file == -1:
        return 0
    functions_to_instrument = file.readlines()
    list_of_addr = list()
    for function in functions_to_instrument:
        func_first_addr = find_function(function)
        if func_first_addr != -1:
            list_of_addr.append(get_list_of_function_instr(func_first_addr, mode))
        else:
            print "Failed to find", function

    save_instrumented(list_of_addr, is_silent)       
    return 0

def main():
    print "Start metrics calculation" 
    idc.Wait() #wait while ida finish analysis
    if os.getenv('IDAPYTHON') != 'auto':
        name = AskFile(1, "*.*", "Where is a file with libcalls?")
        subcalls_mode = 0#AskYN(1,("HIDECANCEL\nDo you want to instrument subcalls in the routines?\n"))
        if subcalls_mode == -1:
            print "Terminated"
            return 0
        init_analysis(name, subcalls_mode, MANUAL)
        print "done"
        return 0
    #else: #hidden mode
        #todo: get flag (instrument or don't instrument subcalls and where is a file with a list of libcalls)
        #init_analysis(name, subcalls_mode, SILENT)
        
    
    if os.getenv('IDAPYTHON') == 'auto':
        Exit(0)
    return 1
if __name__ == "__main__":
    main()