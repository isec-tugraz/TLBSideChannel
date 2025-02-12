#!/usr/bin/env python3

import re
import os
import numpy as np
import json

heap = "./heap/output"
stack = "./stack/output"
pagetable = "./page-table/output"

results = {"D1":[],"D3":[]}

def eval(defense: str, path: str):
    files = os.listdir(path)
    files = [f for f in files if ".git" not in f]
    datas = {}
    for fname in files:
        with open(path+"/"+fname, "r") as f:
            data = f.read()
            if fname not in datas:
                datas[fname] = data
            else:
                datas[fname] += data
    
    # print("[*] {}:".format(path))
    # print(json.dumps(datas, indent=4))
    for exploit,data in datas.items():
        tp = data.count("success")
        fp = data.count("fail")
        cnt = data.count("start")
        fn = cnt-tp-fp
        # print("[*]   {}:".format(exploit))
        # print("[*]   tp {:4d} fp {:4d} fn {:4d} cnt {:4d}".format(tp, fp, fn, cnt))
        times = re.findall(r"real\t0m.*\..*s", data)
        times = [float(t[7:-1]) for t in times]
        time = np.mean(times)
        sr = int(100*tp/cnt)
        cr = int(100*((tp/(fp+tp) * fn + tp)/cnt))
        result = {
            "SR": sr,
            "T": "{:.1f}".format(time),
            "CR": cr
        }
        exploit = exploit.replace("_leak", "").replace("pud", "PUD").replace("pmd", "PMD").replace("pt", "PT")
        results[defense].append({
            exploit: result
        })
        print("| {:20s} | {:5d} | {:3d} | {:3d} | {:5.1f} |".format(exploit, cnt, sr, cr, time))
        
print("----------------------------------------------------")
print("| {:20s} | {:5s} | {:3s} | {:3s} | {:5s} |".format("Leaked object", "Tries", "SR", "CR", "Time"))
print("----------------------------------------------------")
eval("D1", heap)
eval("D1", pagetable)
eval("D3", stack)
print("----------------------------------------------------")
# print(json.dumps(results, sort_keys=True, indent=4))
