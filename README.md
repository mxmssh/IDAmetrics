# IDAMetrics-static.py
IDA plugins for static software complexity metrics collection.

This IDA script collects static software complexity metrics 
for binary executable of x86 architecture.

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

    16. Oviedo metric (function/module)

    17. Chepin metric (function/module)

    18. Card & Glass metric (function/module)

    19. Henry & Cafura metric (function/module)

    20. Cocol metric (function/module)
    
Additional functionality:

     - node graph generation (function)
     
     - basic block boundaries generation (function)

# IDAMetrics-dynamic.py

IDA plugins for trace complexity assessment.

This IDA scripts allows to collect complexity only for 
for trace of executed application.

# pincc.cpp

Intel PIN DBI tool that allows to get trace of executed basic blocks.

# Metrics efficiency analysis

We tested metrics to predict bugs in the following list of vulnerable apps: http://goo.gl/4dKypy

The raw results are here: http://goo.gl/Kl0qBa

# sorter.py

This IDA Python script aimed to prioritize some test cases based on their coverage
complexity. By default Halstead B metric is used to get coverage complexity.
Also script excludes not unique cases based on executed trace.


#Bugs

Please read attentively current issues before using these scripts. Many metrics
were not originally created for binary code, so I made a lot of assumptions 
during implementation and you should use results of these scripts carefully.
Please mail me if you find any inaccuracy or mistakes in the implementation.
