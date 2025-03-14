#!/usr/bin/env python3
import json
import sys
import argparse

#GHIDRA_ADDR_OFFSET = 0x100000
GHIDRA_ADDR_OFFSET = 0

def print_bb(results, function_name=None):
    if function_name is not None:
	    results = [x for x in results if x["function_name"] == function_name]
    for func_data in results:
        func_name = func_data["function_name"]
        blocks = func_data["blocks"]
        if not len(blocks):
            continue
        block_addr = blocks[0]['bb_start_vaddr'] - GHIDRA_ADDR_OFFSET
        print(f"{block_addr:010x}  <{func_name}>:")

        for block in blocks:
            preblock = "    > Src: " + ", ".join(f"{addr-GHIDRA_ADDR_OFFSET:x}" for addr in block["source_vaddrs"])
            if block["is_entry_point"]:
                preblock += "(entry)"
            print(preblock)
            block_addr = block["bb_start_vaddr"] - GHIDRA_ADDR_OFFSET
            for instr in block["instructions"]:
                byte_instr = instr["instruction_byte"]
                str_instr = instr["instruction_str"]
                addr = instr["instr_offset"] - GHIDRA_ADDR_OFFSET
                print(f"{addr:7x}:   {byte_instr:20s} {str_instr}")

            problock = "    > Dst: " + ", ".join(f"{addr-GHIDRA_ADDR_OFFSET:x}" for addr in block["exit_vaddrs"])
            if block["is_exit_point"]:
                problock += "(exit)"
            print(problock)

            print()
        print()



if __name__ ==  "__main__":
    parser = argparse.ArgumentParser('parse_result_json.py', description='pretty print parsed json file')
    parser.add_argument("json_f")
    parser.add_argument("--function_name", default=None)
    args = parser.parse_args()

    with open(args.json_f, "r") as fd:
        data = json.load(fd)
    print_bb(data, args.function_name)
