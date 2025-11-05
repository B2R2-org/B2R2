import json
import os
import sys

def opcode_to_enum(opcode):
    if opcode.endswith("."):
        return (opcode[:-1] + "_dot").upper()
    else:
        return opcode.upper()
    
def operands_to_str(operands):
    operands_str = ""
    match len(operands):
        case 0:
            operands_str = "NoOperand"
        case 1:
            operands_str = "OneOperand"
        case 2:
            operands_str = "TwoOperands"
        case 3:
            operands_str = "ThreeOperands"
        case 4:
            operands_str = "FourOperands"
        case _:
            print("too many operands")
            sys.exit()

    return f"{operands_str}({", ".join(list(map(str.lower, operands)))})"

def range_to_extract(ran):
    l, r = ran
    if l == r:
        return f"Bits.pick bin {31 - l}u"
    else:
        return f"Bits.extract bin {31 - l}u {31 - r}u"
    
def range_to_size(ran):
    l, r = ran
    return r - l + 1

def extract_bits(bin, l, r):
    return (bin & ((1 << (r + 1)) - (1 << l))) >> l

def operand_to_let_oprReg(operand, instr):
    return f"    let {operand.lower()} = {range_to_extract(instr["fields"][operand])} |> getOprReg\n"

def operand_to_let_oprImm(operand, instr):
    return f"    let {operand.lower()} = {range_to_extract(instr["fields"][operand])} |> getOprImm\n"

def operand_to_let_oprCY(operand, instr):
    return f"    let {operand.lower()} = {range_to_extract(instr["fields"][operand])} |> getOprCY\n"

def operand_to_let_oprL(operand, instr):
    return f"    let {operand.lower()} = {range_to_extract(instr["fields"][operand])} |> getOprL\n"

def operand_to_let_D(operand, instr):
    if operand in instr["fields"]:
        return f"    let {operand.lower()} = {range_to_extract(instr["fields"][operand])} |> getOprImm\n"
    else:
        let1 = f"    let d0 = {range_to_extract(instr["fields"]["d0"])}\n"
        let2 = f"    let d1 = {range_to_extract(instr["fields"]["d1"])}\n"
        let3 = f"    let d2 = {range_to_extract(instr["fields"]["d2"])}\n"
        sz_d2 = range_to_size(instr["fields"]["d2"])
        sz_d1 = range_to_size(instr["fields"]["d1"])
        let4 = f"    let {operand.lower()} = Bits.concat d0 (Bits.concat d1 d2 {sz_d2}) {sz_d1 + sz_d2} |> getOprImm\n"
        return let1 + let2 + let3 + let4
    
def operand_to_let_target_addr(operand, instr):
    if "LI" in instr["fields"]:
        l, r = instr["fields"]["LI"]
    elif "BD" in instr["fields"]:
        l, r = instr["fields"]["BD"]
    else:
        print("there is no field for target address")
        assert False
    
    if extract_bits(instr["equal conditions"][1], 31 - instr["fields"]["AA"][1], 31 - instr["fields"]["AA"][0]) == 0:
        return f"    let {operand.lower()} = addr + extractExtendedField bin {31 - l}u {31 - r}u 2 |> getOprAddr\n"
    else:
        return f"    let {operand.lower()} = extractExtendedField bin {31 - l}u {31 - r}u 2 |> getOprAddr\n"
    
def operand_to_let_oprBO(operand, instr):
    return f"    let {operand.lower()} = {range_to_extract(instr["fields"][operand])} |> getOprBO\n"

def operand_to_let_oprBI(operand, instr):
    return f"    let {operand.lower()} = {range_to_extract(instr["fields"][operand])} |> getOprBI\n"

def operand_to_let_oprBH(operand, instr):
    return f"    let {operand.lower()} = {range_to_extract(instr["fields"][operand])} |> getOprBH\n"

def operand_to_let_eff_D_RA(operand, instr):
    l, r = instr["fields"]["D"]
    let1 = f"    let ra = {range_to_extract(instr["fields"]["RA"])}\n"
    let2 = f"    let d = extractExtendedField bin {31 - l}u {31 - r}u 0\n"
    let3 = f"    let d2ra = getOprMem d ra\n"
    return let1 + let2 + let3

def operand_to_let_eff_DS_RA(operand, instr):
    l, r = instr["fields"]["DS"]
    let1 = f"    let ra = {range_to_extract(instr["fields"]["RA"])}\n"
    let2 = f"    let ds = extractExtendedField bin {31 - l}u {31 - r}u 2\n"
    let3 = f"    let ds2ra = getOprMem ds ra\n"
    return let1 + let2 + let3

def operand_to_let_eff_DQ_RA(operand, instr):
    l, r = instr["fields"]["DQ"]
    let1 = f"    let ra = {range_to_extract(instr["fields"]["RA"])}\n"
    let2 = f"    let dq = extractExtendedField bin {31 - l}u {31 - r}u 4\n"
    let3 = f"    let dq2ra = getOprMem dq ra\n"
    return let1 + let2 + let3

operand_type_dict = {
    "RT": operand_to_let_oprReg,
    "RS": operand_to_let_oprReg,
    "RA": operand_to_let_oprReg,
    "RB": operand_to_let_oprReg,
    "SI": operand_to_let_oprImm,
    "D" : operand_to_let_D,
    "CY" : operand_to_let_oprCY,
    "L" : operand_to_let_oprL,
    "targetaddr": operand_to_let_target_addr,
    "BO": operand_to_let_oprBO,
    "BI": operand_to_let_oprBI,
    "BH": operand_to_let_oprBH,
    "D2RA": operand_to_let_eff_D_RA,
    "DS2RA": operand_to_let_eff_DS_RA,
    "DQ2RA": operand_to_let_eff_DQ_RA,
    "RTp": operand_to_let_oprReg,
    "RSp": operand_to_let_oprReg,
    "NB": operand_to_let_oprImm
}

def operand_to_let(operand, fields_dict):
    return operand_type_dict[operand](operand, fields_dict)



# Convert json datas in the input_json folder into F# parsing code

file_list = os.listdir("./input_jsons")
instr_data = []
for instr_file in file_list:
    with open("./input_jsons/" + instr_file) as f:
        instr_data.extend(json.load(f))
    f.close()

f_op_to_str = open("generated_codes/opCodeToString.txt", "w")
f_op = open("generated_codes/opcode.txt", "w")
f_parse = open("generated_codes/parseInstruction.txt", "w")

for i, instr in enumerate(instr_data):
    opcode = instr["opcode"]
    opcode_enum = opcode_to_enum(opcode)

    f_op_to_str.write(f"  | Op.{opcode_enum} -> \"{opcode}\"\n")
    f_op.write(f"  | {opcode_enum} = {i}\n")
    
    operands = instr["operands"]
    fields = instr["fields"]
    eq_conds = instr["equal conditions"]

    bitmask = 0
    target_bit = 0
    for eq_cond in eq_conds:
        l, r = 31 - eq_cond['field range'][1], 31 - eq_cond['field range'][0]
        v = int(eq_cond['value'])

        target_bit = target_bit ^ (v << l)
        bitmask = bitmask ^ ((1 << (r + 1)) - (1 << l))
    instr["equal conditions"] = (bitmask, target_bit)

    fields_dict = {}
    for field in fields:
        fields_dict[field['name']] = (field['field range'][0], field['field range'][1])
    instr["fields"] = fields_dict

    f_parse.write(f"  | b when b &&&\n    {bitmask:#032b}u = {target_bit:#032b}u ->\n")
    f_parse.write(f"    let opcode = Opcode.{opcode_enum}\n")
    for operand in operands:
        f_parse.write(operand_to_let(operand, instr))
    f_parse.write(f"    struct (opcode, {operands_to_str(operands)})\n")

f_op_to_str.close()
f_op.close()
f_parse.close()