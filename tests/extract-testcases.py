#!/usr/bin/env python3

import pyshark
import subprocess
import sys
import time
import tqdm
import pathlib

requests = {}

for i in tqdm.tqdm(range(10)):
    with pyshark.FileCapture(sys.argv[1], display_filter="openapi") as capture:
        for packet in capture:
            if hasattr(packet.openapi, "response_status"):
                status = packet.openapi.response_status
            elif hasattr(packet.openapi, "response_location"):
                status = 201
            elif hasattr(packet.openapi, "response_data") and packet.openapi.response_data.startswith("{"):
                status = 200
            else:
                continue

            try:
                reqt = (packet.openapi.request_method, packet.openapi.request_path, packet.openapi.request_data)
                rest = (packet.openapi.response_status, packet.openapi.response_data)
                if reqt not in requests:
                    requests[reqt] = rest
            except:
                pass


for (method, path, reqdata), (status, data) in requests.items():
    print(f"{method} {path} {reqdata.encode().hex()} {status} {data.encode().hex()} {pathlib.Path(sys.argv[1]).expanduser().resolve()}")
    #proc = subprocess.Popen(["lua", "test.lua", method, path, status, data], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    #output = proc.communicate()[0].decode()

    #print(f"# {method} {path}")
    #print(output)

