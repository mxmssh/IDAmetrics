# ida-metrics_static
IDA plugin for software complexity metrics collection.

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
    
    14. Span metric (function/module)
    
    15. Global variables access count (function/module)
    
    
Additional functionality:

     - node graph generation (function)
     
     - basic block boundaries generation (function)
     
