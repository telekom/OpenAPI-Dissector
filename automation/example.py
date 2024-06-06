#!/usr/bin/env python3

import subprocess
import json

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
                if isinstance(openapi_block["openapi.operation"], str): continue
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

def data_by_path(data, path):
    if path.startswith("root"):
        path = path[4:]

    if not path:
        return data

    if path.startswith("["):
        key, nextpath = path[1:].split("]", 1)
        if key[0] in ["'", '"']:
            key = key[1:-1]
        try:
            intkey = int(key)
        except:
            intkey = None
        if isinstance(data, dict) and key in data:
            return data_by_path(data[key], nextpath)
        elif isinstance(data, dict) and intkey is not None and intkey in data:
            return data_by_path(data[intkey], nextpath)
        elif isinstance(data, list) and intkey is not None:
            return data_by_path(data[intkey-1], nextpath)
        else:
            raise Exception("wat.")

def main():
    import sys
    tshark = TShark(sys.argv[1])

    for req in tshark.requests:
        # ignore valid or unhandled packets
        if ("valid" not in req["request"] or req["request"]["valid"] == "Yes") and ("valid" not in req["response"] or req["response"]["valid"] == "Yes"): continue

        print(f'# {req["operation"]["operation"] if "operation" in req["operation"] else req["request"]["path"]} {req["meta"]["connection"][0]} <-> {req["meta"]["connection"][1]}')

        for prefix in ["operation", "request", "response"]:
            if ("error" in req[prefix] and req[prefix]["error"]) or ("warning" in req[prefix] and req[prefix]["warning"]):
                print(f"## {prefix.capitalize()}")

            data = None
            try:
                if "data" in req[prefix]:
                    data = json.loads(req[prefix]["data"])
            except:
                pass

            for x in ["error", "warning"]:
                if x not in req[prefix]:
                    continue

                for msg in req[prefix][x]:
                    msgtype, msg = msg.split(",", 1)
                    msg = json.loads(msg)
                    msg["type"] = msgtype
                    try:
                        if data and "path" in msg:
                            msg["value"] = data_by_path(data, msg["path"])
                    except:
                        pass

                    print(f"- {prefix},{x},{msg}")

if __name__ == "__main__":
    main()
