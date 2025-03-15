#!/usr/bin/env python3
import json
import argparse
from subprocess import Popen, PIPE
import re
import os


def get_objdump_results(binary, offset=0):
    cmd = f"llvm-objdump -d -M no-aliases {binary}"
    print(f"Executing `{cmd}`")
    p = Popen(cmd, shell=True, stdout=PIPE, stderr=PIPE)
    out, err = p.communicate()
    if p.returncode != 0:
        print(err.decode())
        cmd = f"llvm-objdump -d --adjust-vma={offset} {binary}"
        print(f"Executing `{cmd}`")
        p = Popen(cmd, shell=True, stdout=PIPE, stderr=PIPE)
        out, err = p.communicate()
        if p.returncode != 0:
            print(err.decode())
            exit(1)
    disassembly = {}
    for line in out.decode().splitlines():
        if not re.match(r"^\s*[0-9a-f]+: ", line):
            continue
        address, rest = line.split(":", 1)
        address = int(address, 16)
        byte_string, instr = re.split(r"\s{2,}", rest)
        byte_string = byte_string.replace(" ", "")
        if "\t" not in instr:
            disassembly[address] = {
                    "mnem": "",
                    "operands": "",
                    "instruction_str": "",
                    "instruction_byte": byte_string,
                    "used": False
                    }
            continue
        mnem, op_str = instr.split("\t")
        op_str = op_str.strip()
        mnem = mnem.strip()
        instr = f"{mnem} {op_str}".strip()
        op_str = re.sub(r"<[\w_+-]+>", "", op_str).replace(" ", "").strip()
        disassembly[address] = {
                "mnem": mnem,
                "operands": op_str,
                "instruction_str": instr,
                "instruction_byte": byte_string,
                "used": False
                }
    return disassembly


if __name__ ==  "__main__":
    parser = argparse.ArgumentParser('llvm-objdump_pass.py', description='add llvm-objdump disassembly')
    parser.add_argument("binary")
    parser.add_argument("input_json")
    parser.add_argument("output_json")
    args = parser.parse_args()

    if not os.path.exists(args.binary):
        print(f"{args.binary} not found")
        exit(1)
    if not os.path.exists(args.input_json):
        print(f"{args.input_json} not found")
        exit(1)

    with open(args.input_json, "r") as fd:
        orig_data = json.load(fd)

    offset = orig_data[0]['blocks'][0]['bb_start_vaddr']
    objdump_results = get_objdump_results(args.binary, offset)


    instr_cnt = 0
    for func_data in orig_data:
        for block in func_data["blocks"]:
            for instr in block["instructions"]:
                new_data = objdump_results[instr["instr_offset"]]
                instr["mnem"] = new_data["mnem"]
                instr["operands"] = new_data["operands"]
                instr["instruction_str"] = new_data["instruction_str"]
                objdump_results[instr["instr_offset"]]["used"] = True
                instr_cnt += 1
    if instr_cnt != len(objdump_results):
        orig_data.append({
            "function_name": "_OBJDUMP_ORPHANS",
            "blocks": [{
                "bb_start_vaddr": -1,
                "bb_size": -1,
                "is_exit_point": False,
                "is_entry_point": True, 
                "exit_vaddrs": [],
                "source_vaddrs": [],
                "instr_mode": "?",
                "instructions": []
                }]
            })
        for addr, data in objdump_results.items():
            if not data["used"]:
                orig_data[-1]["blocks"][0]["instructions"].append({
                    "instr_offset": addr,
                    "instr_size": len(data["instruction_byte"])/2,
                    "mnem": data["mnem"],
                    "operands": data["operands"],
                    "regs_read": "?",
                    "results": "?",
                    "instruction_str": data["instruction_str"],
                    "instruction_byte": data["instruction_byte"],
                    "is_big_endian": False
                    })

    with open(args.output_json, "w") as fd:
        json.dump(orig_data, fd)

