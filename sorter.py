"""
IDAMetrics sorter IDA plugin ver. 0.7

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
This IDA Python script aimed to prioritize some test cases based on their coverage
complexity. By default Halstead B metric is used to get coverage complexity.
Also script excludes not unique cases based on executed trace.

Firstly the script asks user to specify first trace in the folder with test cases
to start prioritization. Folder should containts the following data:
test_case test_case_coverage e.g (file1.pdf file1.pdf_coverage file2.pdf file2.pdf_coverage etc.)

Minimal requirements:
IDA 5.5.0
Python 2.5
IDAPython 1.2.0
"""

import idc
import sys
import os
import operator
import hashlib
import collections
import IDAMetrics_static
import IDAMetrics_dynamic
from os import listdir
from os.path import isfile, join
import shutil

def hashfile(path, blocksize = 65536):
    """ 
    The routine takes md5 hash from file
    @path - path to file
    @blocksize - size of block for md5 hash (default 65536)
    @return - hash value in hex
    """
    afile = open(path, 'rb')
    hasher = hashlib.md5()
    buf = afile.read(blocksize)
    while len(buf) > 0:
        hasher.update(buf)
        buf = afile.read(blocksize)
    afile.close()
    return hasher.hexdigest()

def get_unique(test_cases_weight, pathname):
    """
    The routine tries to find the same coverages and delete them
    @test_cases_weight - dictionary, key=coverage file, value=complexity
    @pathname - path to folder with code coverages and test cases
    @return dictionary with unique test cases
    """
    # delete the same test cases and coverages
    print test_cases_weight
    flipped = dict()
    dups = dict()
    for key, value in test_cases_weight.items():
        if value not in flipped:
            flipped[value] = [key]
        else:
            flipped[value].append(key)

    for key, values in flipped.items():
        if len(flipped[key]) >= 2:
            #compare files
            for value in values:
                file_hash = hashfile(pathname + "\\" + value)
                dups.setdefault(file_hash, []).append(value)
    for key, value in dups.items():
        if len(value) >=2:
           for coverage in value[1:]:
              test_cases_weight.pop(coverage, None)

    return test_cases_weight

def save_sorted_data(test_cases_weight, pathname):
    """
    The routine sorts test cases using their code coverage 
    complexity and then saves them in the folder "sorted"
    @test_cases_weight - dictionary, key=coverage file, value=complexity
    @pathname - path to folder with code coverages and test cases
    """
    new_path = pathname + "\sorted"
    if os.path.exists(new_path):
        shutil.rmtree(new_path)

    os.makedirs(new_path)

    test_cases_weight = get_unique(dict(test_cases_weight), pathname)
    test_cases_weight = sorted(test_cases_weight.items(), key=operator.itemgetter(1),
                               reverse=True)
    print test_cases_weight

    for i, (test_case_name, value) in enumerate(test_cases_weight):
        test_case_name = test_case_name.replace("_coverage", "")
        new_name = new_path +"\\" + str(i) + "_" + test_case_name
        result = shutil.copy2(pathname + "\\" + test_case_name, new_name)

def get_weight(file_cov):
    """
    The routine performs calculation of code coverage complexity using 
    Halstead B metric.
    @file_cov - path to coverage file
    @return - Halstead B complexity
    """
    metrics_used = dict()
    if os.path.isfile(file_cov) == False:
       print "The folder doesn't containts the following coverage " + file_cov
       return -1

    for i in IDAMetrics_static.metrics_list:
        if i == 'h':
            metrics_used[i] = 1
        else:
            metrics_used[i] = 0
    print metrics_used
    metrics_dynamic = IDAMetrics_dynamic.Metrics_dynamic()
    metrics_dynamic.ask_save = False
    metrics_result = metrics_dynamic.get_dynamic_metrics(file_cov, metrics_used)
    return metrics_result.Halstead_total.B

def start_prior(pathname):
    """
    The routine starts prioritization
    @pathname - path to files for prioritization
    """
    test_cases_weight = dict();
    # get only files in the directory
    onlyfiles = [ f for f in listdir(pathname) if isfile(join(pathname,f)) ]

    for file in onlyfiles:
       if "coverage" not in file:
          file_cov = file + "_coverage"
          test_cases_weight[file_cov] = get_weight(pathname + "\\" + file_cov)

    save_sorted_data(test_cases_weight, pathname)

def main():
    message = "First of all you need to specify folder with test cases."
    idc.Warning(message)
    fname = idc.AskFile(0, "*.*", "Please specify first trace file in test cases folder \
                                   to start prioritization")
    if fname == None:
        print "You need to specify any file in test cases folder to start prioritization"
        return 0
    fname = os.path.dirname(fname)
    if fname == None:
        return 0
    print "Starting prioritization of " + fname
    start_prior(fname)
    print "Done"
if __name__ == "__main__":
    main()
