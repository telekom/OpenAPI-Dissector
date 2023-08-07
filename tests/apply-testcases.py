#!/usr/bin/env python3

import subprocess
import json
import sys
import os

for i, line in enumerate(open(sys.argv[1]).read().splitlines()):
    if len(sys.argv) > 2:
        if str(i) not in sys.argv[2].split(","): continue

    line = line.strip()
    if not line or line.startswith("#"): continue

    schema = sys.argv[3] if len(sys.argv) > 3 else ""

    splitted = line.split()
    if len(splitted) == 6:
        method, path, reqdata, status, data, testsrc = splitted
    elif len(splitted) == 7:
        method, path, reqdata, status, data, testsrc, schema = splitted
    else:
        raise Exception("invalid number of arguments for given test case")

    reqdata = bytes.fromhex(reqdata).decode()
    print(f"# Request {method}:{status} {path} ({testsrc})")
    if reqdata.startswith("--------"):
        print("Request JSON is part of multipart data, not yet implemented")
    else:
        proc = subprocess.Popen(["lua", "test.lua", method, path, status, reqdata, "request", schema], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        output = proc.communicate()[0].decode()
        if reqdata.strip() == "Request Data:":
            print("Empty request data, ignoring.")
        else:
            print(json.dumps(json.loads(reqdata), indent=4))
            print(output)

    data = bytes.fromhex(data).decode()
    proc = subprocess.Popen(["lua", "test.lua", method, path, status, data, "response", schema], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    output = proc.communicate()[0].decode()
    print(f"# Response {method}:{status} {path} ({testsrc})")
    if data.strip() == "Response Data:":
        print("Empty response data, ignoring.")
    else:
        print(json.dumps(json.loads(data), indent=4))
        print(output)
