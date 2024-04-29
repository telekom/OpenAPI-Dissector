#!/usr/bin/env python3

import subprocess
import json
import sys

class TShark(object):
    always_dicts = ["data_tree", "error", "warning"]

    def __init__(self, pcap, openapi_version="17.x", openapi_data_tree=False, openapi_machine_readable=True):
        cmd = ["tshark", "-2"]
        cmd += ["-N", "d"]
        cmd += ["-T", "json"]
        cmd += ["-o", f"openapi.version: {openapi_version}"]
        cmd += ["-o", f"openapi.data_tree: {'true' if openapi_data_tree else 'false'}"]
        cmd += ["-o", f"openapi.machine_readable: {'true' if openapi_machine_readable else 'false'}"]
        cmd += ["-r", pcap]
        cmd += ["-Y", "openapi"]
        cmd_output = subprocess.check_output(cmd).decode("utf-8", "ignore")

        def _array_on_duplicate_keys(ordered_pairs):
            """Convert duplicate keys to arrays."""
            # Source: https://stackoverflow.com/a/61416215
            d = {}
            for k, v in ordered_pairs:
                if k in d:
                    if type(d[k]) is list:
                        d[k].append(v)
                    else:
                        d[k] = [d[k],v]
                else:
                   d[k] = v
            return d

        self.capture = json.loads(cmd_output, object_pairs_hook=_array_on_duplicate_keys)
        self.requests = self.parse_requests()

    def parse_requests(self):

        requests_dict = {}
        for packet in self.capture:
            meta = {}

            if "ipv6" in packet["_source"]["layers"]:
                src_ip = packet["_source"]["layers"]["ipv6"]["ipv6.src"]
                dst_ip = packet["_source"]["layers"]["ipv6"]["ipv6.dst"]
            else:
                src_ip = packet["_source"]["layers"]["ip"]["ip.src"]
                dst_ip = packet["_source"]["layers"]["ip"]["ip.dst"]
            src_port = packet["_source"]["layers"]["tcp"]["tcp.srcport"]
            dst_port = packet["_source"]["layers"]["tcp"]["tcp.dstport"]
            meta["connection"] = ((src_ip, src_port), (dst_ip, dst_port))

            openapi_blocks = packet["_source"]["layers"]["openapi"]
            if not isinstance(openapi_blocks, list): openapi_blocks = [openapi_blocks]
            for openapi_block in openapi_blocks:
                openapi_block["meta"] = meta
                streamid = openapi_block["openapi.operation"]["openapi.operation.stream_id"]
                requests_dict[streamid] = openapi_block

        requests = []
        for openapi_block in requests_dict.values():
            for prefix in ["operation", "request", "response"]:
                openapi_block[prefix] = openapi_block.pop(f"openapi.{prefix}")

                tomove = []

                for key, value in openapi_block[prefix].items():
                    if key.startswith(f"openapi.{prefix}."):
                        newkey = key[len(f"openapi.{prefix}."):]
                        tomove.append((key, newkey))

                for oldkey, newkey in tomove:
                    openapi_block[prefix][newkey] = openapi_block[prefix].pop(oldkey)

                for key in openapi_block[prefix]:
                    if key in self.always_dicts or key.startswith("data."):
                        if not isinstance(openapi_block[prefix][key], list):
                            openapi_block[prefix][key] = [openapi_block[prefix][key]]

            requests.append(openapi_block)

        return requests

tshark = TShark("test.pcapng")

for req in tshark.requests:
    # ignore valid or unhandled packets
    if ("valid" not in req["request"] or req["request"]["valid"] == "Yes") and ("valid" not in req["response"] or req["response"]["valid"] == "Yes"): continue

    print(f'# {req["operation"]["operation"]} {req["meta"]["connection"][0]} <-> {req["meta"]["connection"][1]}')

    for prefix in ["operation", "request", "response"]:
        if ("error" in req[prefix] and req[prefix]["error"]) or ("warning" in req[prefix] and req[prefix]["warning"]):
            print(f"## {prefix.capitalize()}")

        if "error" in req[prefix]:
            for error in req[prefix]["error"]:

                print(f"- {prefix}.error,{error}")
        if "warning" in req[prefix]:
            for warning in req[prefix]["warning"]:
                print(f"- {prefix}.warning,{warning}")

