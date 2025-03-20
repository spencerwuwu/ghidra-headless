#!/usr/bin/env python3
import json
import argparse
import os
import subprocess
import re
import sympy as sp

GHIDRA_ADDR_OFFSET = 0

# time of instr, condition, true time, false time if it branches
def time_of_riscv_instr(mnem, args, store_name, ML):
	time = None
	condition, true_time, false_time = None, None, None

	# Preprocess args into Picinae registers
	for i in range(len(args)):
		arg = args[i]
		if arg in "ra sp gp tp t0 t1 t2 t3 t4 t5 t6 s0 s1 s2 s3 s4 s5 s6 s7 s8 s9 s10 s11 a0 a1 a2 a3 a4 a5 a6 a7".split(" "):
			arg = f"R_{arg.upper()}"
		args[i] = arg

	if mnem in ["add", "sub", "xor", "or", "and", "slt", "sltu",
				"addi", "xori", "ori", "andi", "slti", "sltiu", 
				"lui", "auipc"]:
		time = "2"
	elif mnem in ["srl", "sll", "sra"]:
		time = f"3 + ({store_name} {args[2]} / 4 + {store_name} {args[2]} mod 4)"
	elif mnem == "clz":
		time = f"3 + clz ({store_name} {args[1]}) 32"
	elif mnem in ["srli", "slli", "srai"]:
		time = f"3 + args[2] / 4 + args[2] mod 4"
	elif mnem in ["lb", "lh", "lw", "lbu", "lhu", "sb", "sh", "sw"]:
		time = f"5 + ({ML} - 2)"
	elif mnem in ["beq", "bne", "blt", "bge", "bltu", "bgeu"]:
		true_time = f"5 + {ML} - 1"
		false_time = "3"
		op1 = '0' if args[0] == 'zero' else f"{store_name} {args[0]}"
		op2 = '0' if args[1] == 'zero' else f"{store_name} {args[1]}"
		letin = f"let rs1, rs2 := ({op1}, {op2}) in"
		if mnem == "beq":
			condition = "rs1 =? rs2"
		elif mnem == "bne":
			condition = "negb (rs1 =? rs2)"
		elif mnem == "blt":
			condition = ".ltb (toZ 32 rs1) (toZ 32 rs2)"
		elif mnem == "bge":
			condition = "Z.geb (toZ 32 rs1) (toZ 32 rs2)"
		elif mnem == "bltu":
			condition = "rs1 <? rs2"
		elif mnem == "bgeu":
			condition = "negb (rs1 <? rs2)"
		condition = f"({letin} {condition})"
		time = f"if {condition} then {true_time} else {false_time}"
	elif mnem in ["jal", "jalr"]:
		time = f"5 + ({ML} - 1)"
	elif mnem in ["mul", "mulh", "mulhsu", "mulhu", "div", "divu", "rem", "remu"]:
		time = f"36"
	else:
		# TODO : last few else ifs in Rocq RISCV timing function
		time = f"(* ERROR: {mnem} {args} *) err_time"

	return (time, condition, true_time, false_time)
	

def print_bb(results, function_name=""):
	if function_name != "":
		results = [x for x in results if x["function_name"] == function_name]
	for func_data in results:
		func_name = func_data["function_name"]
		blocks = func_data["blocks"]
		if not len(blocks):
			continue
		block_addr = blocks[0]['bb_start_vaddr'] + GHIDRA_ADDR_OFFSET
		print(f"{block_addr:010x}  <{func_name}>:")

		for block in blocks:
			preblock = "    > Src: " + ", ".join(f"{addr+GHIDRA_ADDR_OFFSET:x}" for addr in block["source_vaddrs"])
			if block["is_entry_point"]:
				preblock += "(entry)"
			print(preblock)
			block_addr = block["bb_start_vaddr"] + GHIDRA_ADDR_OFFSET
			for instr in block["instructions"]:
				byte_instr = instr["instruction_byte"]
				str_instr = instr["instruction_str"]
				addr = instr["instr_offset"] + GHIDRA_ADDR_OFFSET
				print(f"{addr:7x}:   {byte_instr:20s} {str_instr}")

			problock = "    > Dst: " + ", ".join(f"{addr+GHIDRA_ADDR_OFFSET:x}" for addr in block["exit_vaddrs"])
			if block["is_exit_point"]:
				problock += "(exit)"
			print(problock)

			print(time_of_basic_block(block))

			print()
		print()

# Return time of basic block, final instruction info extracted if it's a branch
def time_of_basic_block(block):
	times = [time_of_riscv_instr(instr['mnem'], instr['operands'], 's', 'ML')[0] for instr in block['instructions'][:-1]]
	times = [f"({time})" if " " in time else time for time in times]

	# Check final instruction for branching
	final_instr = block['instructions'][-1]
	final_time, condition, true_time, false_time = time_of_riscv_instr(final_instr['mnem'], final_instr['operands'], 's', 'ML')
	if condition is None:
		times.append(final_time)

	return f"{' + '.join(times)}", condition, true_time, false_time

def time_of_function_basic_blocks(results, function_name):
	func = [x for x in results if x["function_name"] == function_name][0]
	out = f"Definition basic_block_times_{function_name} (s : store) (ML : nat) (addr : N) : option nat :=\n"
	out += "  let err_time := 999 in\n"
	out += "  match addr with\n"
	for block in func["blocks"]:
		block_time, condition, tt, ft = time_of_basic_block(block)
		out += f"  | {hex(block['instructions'][-1]['instr_offset'] + GHIDRA_ADDR_OFFSET)} => {block_time}"
		if condition is not None:
			out += f" + (if {condition} then {tt} else {ft})"
		out += "\n"
	out += "  end.\n\n"
	return out

def preprocess_data(results, function_name):
	for i in range(len(results)):
		if results[i]['function_name'] == function_name:
			break

	blocks = results[i]["blocks"]
	
	for block in blocks:
		for instr in block["instructions"]:
			instr["operands"] = instr["operands"].split(",")
	
	results[i]["blocks"] = blocks

def simplify_expression(expr):
	"""Simplifies arithmetic expressions, preserving 'if' conditions and combining like terms."""
	
	# Regular expression to match 'if (...) then ... else ...' expressions
	conditional_pattern = re.compile(r'if\s*\(.*\)\s*then\s*(.*)\s*else\s*(.*)')
	
	def simplify_branch(match):
		"""Simplifies the then/else branches separately."""
		condition = match.group(0).split("then")[0] + "then"
		then_branch = match.group(1).strip()
		else_branch = match.group(2).strip()
		
		simplified_then = simplify_expression(then_branch) #str(sp.simplify(then_branch))
		simplified_else = simplify_expression(else_branch) #str(sp.simplify(else_branch))
		
		return f"{condition} {simplified_then} else {simplified_else}"
	
	# Simplify each branch within conditionals
	expr = conditional_pattern.sub(simplify_branch, expr)

	# Simplify the remaining arithmetic expression
	tokens = re.findall(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b|\d+|[+\-*/()]', expr)
	sym_expr = " ".join(tokens)
	
	try:
		simplified = str(sp.simplify(sym_expr))
	except:
		simplified = expr  # Fallback if sympy fails

	return simplified

def generate_timing_invariants(results, function_name):
	func = next(x for x in results if x["function_name"] == function_name)
	blocks = func["blocks"]
	
	# Build CFG
	cfg = {}
	for block in blocks:
		start_addr = block['bb_start_vaddr'] + GHIDRA_ADDR_OFFSET
		end_addr = block['instructions'][-1]['instr_offset'] + GHIDRA_ADDR_OFFSET + 4
		block_time, condition, true_time, false_time = time_of_basic_block(block)
		
		cfg[start_addr] = {
			'end_addr': end_addr,
			'time': block_time,
			'condition': condition,
			'true_time': true_time,
			'false_time': false_time,
			'predecessors': [addr + GHIDRA_ADDR_OFFSET for addr in block['source_vaddrs']],
			'successors': [addr + GHIDRA_ADDR_OFFSET for addr in block['exit_vaddrs']],
			'is_branch': condition is not None,
			'is_entry': block['is_entry_point']
		}

	# Build invariant set
	invariants = {}
	queue = [addr for addr in cfg if cfg[addr]['is_entry']]
	branch_origins = {}
	
	while queue:
		addr = queue.pop(0)
		block = cfg[addr]
		
		if addr not in invariants:
			invariants[addr] = set()
		
		# Accumulate time from predecessors
		for pred in block['predecessors']:
			if pred in invariants:
				invariants[addr].update(invariants[pred])
				
				# If merging back from a branch, add conditional invariant
				if pred in branch_origins:
					cond, t_time, f_time = branch_origins[pred]
					invariants[addr].add(f"if {cond} then {t_time} else {f_time}")
		
		# Add current block time
		invariants[addr].add(block['time'])
		
		# Propagate through successors
		for i, succ in enumerate(reversed(block['successors'])):
			if succ not in invariants:
				invariants[succ] = set()
			
			if block['is_branch']:
				invariants[succ].update(invariants[addr])
				if i == 1:  # True branch
					invariants[succ].add(block['true_time'])
					branch_origins[succ] = (block['condition'], block['true_time'], block['false_time'])
				else:  # False branch
					invariants[succ].add(block['false_time'])
					branch_origins[succ] = (block['condition'], block['true_time'], block['false_time'])
			else:
				invariants[succ].update(invariants[addr])
				invariants[succ].add(block['time'])
				
			if succ not in queue:
				queue.append(succ)

	rocq_output = f"""Definition {function_name}_timing_invs (_ : store) (p : addr) (base_mem : addr -> N) (t : trace) : option Prop :=
match t with (Addr a, s) :: t' => match a with\n"""

	for k, v in invariants.items():
		v = [simplify_expression(str(x)) for x in v]
		time = simplify_expression(' + '.join(v))
		rocq_output += f"    | {hex(cfg[k]['end_addr'])} => Some (time_of_trace t' = {time})\n"

	return rocq_output


if __name__ ==  "__main__":
	parser = argparse.ArgumentParser('time_of_riscv_function.py', description='pretty print parsed json file')
	parser.add_argument("bin")
	parser.add_argument("--riscv_objdump", default="riscv32-unknown-linux-gnu-objdump")
	parser.add_argument("--function_name", default="")
	parser.add_argument("--addr_offset", default=0, type=int)
	args = parser.parse_args()

	GHIDRA_ADDR_OFFSET = args.addr_offset

	# If preproc file doesn't exist, generate
	preproc_fn = f"{args.bin}.preprocessed.json"
	objdump_pass_fn = f"{args.bin}.preprocessed.objdump.json"
	if not os.path.exists(objdump_pass_fn):
		subprocess.run(["bash", "get_ghidra_basicblocks.sh", args.bin, preproc_fn], capture_output=True)

		# Run objdump pass
		from objdump_pass import objdump_pass
		class Object:
			pass
		objdump_args = Object()
		objdump_args.obj_bin = args.riscv_objdump
		objdump_args.binary = args.bin
		objdump_args.input_json = preproc_fn
		objdump_args.output_json = objdump_pass_fn
		objdump_pass(objdump_args, imported=True)

	with open(objdump_pass_fn, "r") as file:
			data = json.load(file)

	preprocess_data(data, args.function_name)
	# print(time_of_function_basic_blocks(data, args.function_name))
	print(generate_timing_invariants(data, args.function_name))
