/*
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
*/

/** pincc tool
 *  This is Intel PIN DBI tool that allows to get trace of executed basic blocks.
 */
 
#include <iostream>
#include <fstream>
#include <stdlib.h>
#include <string.h>
#include "pin.H"

struct node_t
{
    struct node_t * next;
    ADDRINT head;
};

struct node_t root;
bool no_dll;

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
    "o", "trace.out", "specify output trace file name");

KNOB<BOOL>   KnobDll(KNOB_MODE_WRITEONCE,  "pintool",
    "no_dll", "1", "ignore trace in dlls");

/** The function adds new bbl header in the list */
VOID List(ADDRINT addr)
{
	PIN_LockClient();
	IMG img = IMG_FindByAddress(addr);
	PIN_UnlockClient();

	if(!IMG_Valid(img))
		return;

	if(no_dll && !IMG_IsMainExecutable(img))
		return;

	ADDRINT offset = IMG_LoadOffset(img);

	struct node_t * new_node = (struct node_t *)malloc(sizeof(struct node_t));

    if(!new_node) {
        fprintf(stderr, "ERROR: ListAddNode: malloc failed\n");
        return;
    }

    addr = 0x0 + (addr - offset);
    new_node->head = addr;
	new_node->next = 0x0;
    
	struct node_t * marker = &root;

    if(!marker->next) {
        root.next = new_node;
        return;
	}

    while (marker->next) {
	    
		if(marker->head == addr) {
		    free(new_node);
		    return;
		}
		marker = marker->next;
	}
	new_node->next = 0x0;
	marker->next = new_node;
	return;
}
 
// Pin calls this function every time a new basic block is encountered
VOID Trace(TRACE trace, VOID *v)
{
    // Visit every basic block in the trace
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
    {
        // Insert a call to handle address for every bbl.
        // IPOINT_ANYWHERE allows Pin to schedule the call anywhere in the bbl to obtain best performance.
        BBL_InsertCall(bbl, IPOINT_ANYWHERE, AFUNPTR(List), IARG_ADDRINT, BBL_Address(bbl), IARG_END);
    }
}

// This function is called when the application exits
VOID Fini(INT32 code, VOID *v)
{
	ofstream OutFile;
	OutFile.open(KnobOutputFile.Value().c_str());
    	OutFile.setf(ios::showbase);

	struct node_t * marker = root.next;

	while(marker)
	{
		OutFile << std::hex << marker->head << endl;
		marker = marker->next;
	}

	OutFile.close();
}

int main(int argc, char * argv[])
{
    memset(&root, 0x00, sizeof(root));
    root.head = 0xffffffff;

    // Initialize pin
    PIN_Init(argc, argv);

    // Register Instruction to be called to instrument instructions
    TRACE_AddInstrumentFunction(Trace, 0);

    // Register Fini to be called when the application exits
    PIN_AddFiniFunction(Fini, 0);
    
	// Get flag
	no_dll = KnobDll.Value();

    // Start the program, never returns
    PIN_StartProgram();
    
    return 1;
}