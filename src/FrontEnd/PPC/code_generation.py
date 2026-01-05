import json
import os
import sys
import random
from enum import Enum

class CodeGenerationError(Exception):
    pass

class OprType(Enum):
    Unknown = 0
    Reg = 1
    FPReg = 2
    VReg = 3
    VSReg = 4
    CondReg = 5
    CondBitReg = 6
    FPSCondReg = 7
    FPSCondBitReg = 8
    SPReg = 9
    Imm = 10
    Imm64 = 11
    CY = 12
    L = 13
    Addr = 14
    BO = 15
    BH = 16
    TO = 17
    CRMask = 18
    FPSCRMask = 19
    W = 20
    DCM = 21
    DGM = 22
    Mem = 23

opr_type_conv_func_dict = {
    OprType.Unknown: "unknown",
    OprType.Reg: "getOprReg",
    OprType.FPReg: "getOprFPReg",
    OprType.VReg: "getOprVReg",
    OprType.VSReg: "getOprVSReg",
    OprType.CondReg: "getOprCondReg",
    OprType.CondBitReg: "getOprCondBitReg",
    OprType.FPSCondReg: "getOprFPSCondReg",
    OprType.FPSCondBitReg: "getOprFPSCondBitReg",
    OprType.SPReg: "getOprSPReg",
    OprType.Imm: "getOprImm",
    OprType.Imm64: "getOprImm64",
    OprType.CY: "getOprCY",
    OprType.L: "getOprL",
    OprType.Addr: "getOprAddr",
    OprType.BO: "getOprBO",
    OprType.BH: "getOprBH",
    OprType.TO: "getOprTO",
    OprType.CRMask: "getOprCRMask",
    OprType.FPSCRMask: "getOprFPSCRMask",
    OprType.W: "getOprW",
    OprType.DCM: "getOprDCM",
    OprType.DGM: "getOprDGM",
    OprType.Mem: "getOprMem",
}

f = open("byte_codes.json", "r")
instrs_byte_dict = json.load(f)
f.close()

if not os.path.exists("ambiguous_info.json"):
    f = open("ambiguous_info.json", "w")
    f.write(json.dumps({}, indent=2))
    f.close()

f = open("ambiguous_info.json", "r")
ambiguous_info = json.load(f)
f.close()

def opcode_to_enum(opcode):
    if opcode.endswith("."):
        return (opcode[:-1] + "_dot").upper()
    else:
        return opcode.upper()
    
def operand_to_str(operand):
    return operand.lower() + "Opr"
    
def operands_to_str(operands):
    operands_str = ""
    match len(operands):
        case 0:
            return "NoOperand"
        case 1:
            operands_str = "OneOperand"
        case 2:
            operands_str = "TwoOperands"
        case 3:
            operands_str = "ThreeOperands"
        case 4:
            operands_str = "FourOperands"
        case 5:
            operands_str = "FiveOperands"
        case _:
            raise CodeGenerationError("too many operands")

    return f"{operands_str}({", ".join(list(map(operand_to_str, operands)))})"

def range_to_extract(ran, extend_shift = None):
    l, r = ran
    if not (0 <= l and l <= 31 and 0 <= r and r <= 31):
        raise CodeGenerationError("invalid range")
    
    if extend_shift is not None:
        return f"extractExtendedField bin {31 - l}u {31 - r}u {extend_shift}"
    elif l == r:
        return f"Bits.pick bin {31 - l}u"
    else:
        return f"Bits.extract bin {31 - l}u {31 - r}u"
    
def range_to_size(ran):
    l, r = ran
    if not (0 <= l and l <= 31 and 0 <= r and r <= 31):
        raise CodeGenerationError("invalid range")
    
    return r - l + 1

def extract_bits(bin, l, r):
    if not (0 <= l and l <= 31 and 0 <= r and r <= 31):
        raise CodeGenerationError("invalid range")
    
    return (bin & ((1 << (r + 1)) - (1 << l))) >> l


def should_use_CR(operand, instr):
    use_CR = True
    ambiguous_name = instr["opcode"] + "@" + operand

    if ambiguous_name in ambiguous_info:
        if ambiguous_info[ambiguous_name] == "CR":
            use_CR = True
        elif ambiguous_info[ambiguous_name] == "FPSCR":
            use_CR = False
        else:
            raise CodeGenerationError("invalid ambiguous infomation")
    else:
        print(f"detect ambiguous operand in instruction {instr["opcode"]}: {operand}.")
        while True:
            print("If use CR, type C. If use FPSCR, type F.")
            chr = input()
            if chr == "C":
                ambiguous_info[ambiguous_name] = "CR"
                use_CR = True
                break
            elif chr == "F":
                ambiguous_info[ambiguous_name] = "FPSCR"
                use_CR = False
                break
        f = open("ambiguous_info.json", "w")
        f.write(json.dumps(ambiguous_info, indent=2))
        f.close()
    
    return use_CR

def get_ambiguous_opr_type(operand, instr):
    if operand in ["BF", "BFA"]:
        if should_use_CR(operand, instr):
            return OprType.CondReg
        else:
            return OprType.FPSCondReg
    elif operand == "BT":
        if should_use_CR(operand, instr):
            return OprType.CondBitReg
        else:
            return OprType.FPSCondBitReg
    else:
        raise CodeGenerationError("there is no field for target address")

def get_conv_func(opr_type):
    return opr_type_conv_func_dict[opr_type]

def operand_to_let_direct(operand, opr_type, instr):
    return f"    let {operand.lower()}Opr = {range_to_extract(instr["fields"][operand])} |> {get_conv_func(opr_type)}\n"

def operand_to_let_direct_ext(operand, opr_type, instr):
    return f"    let {operand.lower()}Opr = {range_to_extract(instr["fields"][operand], 0)} |> {get_conv_func(opr_type)}\n"

def operand_to_let_D(operand, opr_type, instr):
    if operand in instr["fields"]:
        return operand_to_let_direct_ext(operand, opr_type, instr)
    else:
        let1 = f"    let d0 = {range_to_extract(instr["fields"]["d0"])}\n"
        let2 = f"    let d1 = {range_to_extract(instr["fields"]["d1"])}\n"
        let3 = f"    let d2 = {range_to_extract(instr["fields"]["d2"])}\n"

        sz_d2 = range_to_size(instr["fields"]["d2"])
        sz_d1 = range_to_size(instr["fields"]["d1"])
        sz_d0 = range_to_size(instr["fields"]["d0"])

        let4 = f"    let d = Bits.concat d0 (Bits.concat d1 d2 {sz_d2}) {sz_d1 + sz_d2} |> uint64\n"
        let5 = f"    let {operand.lower()}Opr = Bits.signExtend {sz_d0 + sz_d1 + sz_d2} 64 d |> {get_conv_func(opr_type)}\n"
        return let1 + let2 + let3 + let4 + let5
    
def operand_to_let_DCMX(operand, opr_type, instr):
    if operand in instr["fields"]:
        return operand_to_let_direct(operand, opr_type, instr)
    else:
        let1 = f"    let dc = {range_to_extract(instr["fields"]["dc"])}\n"
        let2 = f"    let dm = {range_to_extract(instr["fields"]["dm"])}\n"
        let3 = f"    let dx = {range_to_extract(instr["fields"]["dx"])}\n"

        sz_dx = range_to_size(instr["fields"]["dx"])
        sz_dm = range_to_size(instr["fields"]["dm"])

        let4 = f"    let {operand.lower()}Opr = Bits.concat dc (Bits.concat dm dx {sz_dx}) {sz_dm + sz_dx} |> {get_conv_func(opr_type)}\n"
        return let1 + let2 + let3 + let4
    
def operand_to_let_target_addr(operand, opr_type, instr):
    if "LI" in instr["fields"]:
        addr_field = "LI"
    elif "BD" in instr["fields"]:
        addr_field = "BD"
    else:
        raise CodeGenerationError("invalid operands")
    
    if not "AA" in instr["fields"]:
        raise CodeGenerationError("invalid operands")
    
    return f"    let {operand.lower()}Opr = {range_to_extract(instr["fields"][addr_field], 2)} |> {get_conv_func(opr_type)}\n"

def operand_to_let_eff_D_RA(_, opr_type, instr):
    let1 = f"    let ra = {range_to_extract(instr["fields"]["RA"])}\n"
    let2 = f"    let d = {range_to_extract(instr["fields"]["D"], 0)}\n"
    let3 = f"    let d2raOpr = {get_conv_func(opr_type)} d ra\n"
    return let1 + let2 + let3

def operand_to_let_eff_DS_RA(_, opr_type, instr):
    let1 = f"    let ra = {range_to_extract(instr["fields"]["RA"])}\n"
    let2 = f"    let ds = {range_to_extract(instr["fields"]["DS"], 2)}\n"
    let3 = f"    let ds2raOpr = {get_conv_func(opr_type)} ds ra\n"
    return let1 + let2 + let3

def operand_to_let_eff_DQ_RA(_, opr_type, instr):
    let1 = f"    let ra = {range_to_extract(instr["fields"]["RA"])}\n"
    let2 = f"    let dq = {range_to_extract(instr["fields"]["DQ"], 4)}\n"
    let3 = f"    let dq2raOpr = {get_conv_func(opr_type)} dq ra\n"
    return let1 + let2 + let3

def operand_to_let_MB(operand, opr_type, instr):
    if "MB" in instr["fields"]:
        return operand_to_let_direct(operand, opr_type, instr)
    else:
        l, r = instr["fields"]["mb"]
        let1 = f"    let mb0 = {range_to_extract((l, r - 1))}\n"
        let2 = f"    let mb1 = {range_to_extract((r, r))}\n"
        sz_mb0 = range_to_size((l, r - 1))
        let3 = f"    let {operand.lower()}Opr = Bits.concat mb1 mb0 {sz_mb0} |> {get_conv_func(opr_type)}\n"
        return let1 + let2 + let3

def operand_to_let_ME(operand, opr_type, instr):
    if "ME" in instr["fields"]:
       return operand_to_let_direct(operand, opr_type, instr)
    else:
        l, r = instr["fields"]["me"]
        let1 = f"    let me0 = {range_to_extract((l, r - 1))}\n"
        let2 = f"    let me1 = {range_to_extract((r, r))}\n"
        sz_me0 = range_to_size((l, r - 1))
        let3 = f"    let {operand.lower()}Opr = Bits.concat me1 me0 {sz_me0} |> {get_conv_func(opr_type)}\n"
        return let1 + let2 + let3

def operand_to_let_SH(operand, opr_type, instr):
    if "SH" in instr["fields"]:
        return operand_to_let_direct(operand, opr_type, instr)
    else:
        let1 = f"    let sh0 = {range_to_extract(instr["fields"]["sh"])}\n"
        let2 = f"    let sh1 = {range_to_extract(instr["fields"]["sh1"])}\n"
        sz_sh0 = range_to_size(instr["fields"]["sh"])
        let3 = f"    let {operand.lower()}Opr = Bits.concat sh1 sh0 {sz_sh0} |> {get_conv_func(opr_type)}\n"
        return let1 + let2 + let3
    
def operand_to_let_XS(operand, opr_type, instr):
    let1 = f"    let s = {range_to_extract(instr["fields"]["S"])}\n"
    let2 = f"    let sx = {range_to_extract(instr["fields"]["SX"])}\n"
    let3 = f"    let {operand.lower()}Opr = 32u * sx + s |> {get_conv_func(opr_type)}\n"
    return let1 + let2 + let3

def operand_to_let_XT(operand, opr_type, instr):
    let1 = f"    let t = {range_to_extract(instr["fields"]["T"])}\n"
    let2 = f"    let tx = {range_to_extract(instr["fields"]["TX"])}\n"
    let3 = f"    let {operand.lower()}Opr = 32u * tx + t |> {get_conv_func(opr_type)}\n"
    return let1 + let2 + let3

def operand_to_let_XA(operand, opr_type, instr):
    let1 = f"    let a = {range_to_extract(instr["fields"]["A"])}\n"
    let2 = f"    let ax = {range_to_extract(instr["fields"]["AX"])}\n"
    let3 = f"    let {operand.lower()}Opr = 32u * ax + a |> {get_conv_func(opr_type)}\n"
    return let1 + let2 + let3

def operand_to_let_XB(operand, opr_type, instr):
    let1 = f"    let b = {range_to_extract(instr["fields"]["B"])}\n"
    let2 = f"    let bx = {range_to_extract(instr["fields"]["BX"])}\n"
    let3 = f"    let {operand.lower()}Opr = 32u * bx + b |> {get_conv_func(opr_type)}\n"
    return let1 + let2 + let3

def operand_to_let_XC(operand, opr_type, instr):
    let1 = f"    let c = {range_to_extract(instr["fields"]["C"])}\n"
    let2 = f"    let cx = {range_to_extract(instr["fields"]["CX"])}\n"
    let3 = f"    let {operand.lower()}Opr = 32u * cx + c |> {get_conv_func(opr_type)}\n"
    return let1 + let2 + let3

def operand_to_let_SPR(operand, opr_type, instr):
    if "SPR" in instr["fields"]:
        return operand_to_let_direct(operand, opr_type, instr)
    else:
        l, r = instr["fields"]["spr"]
        let1 = f"    let spr0 = {range_to_extract((l, l + 4))}\n"
        let2 = f"    let spr1 = {range_to_extract((l + 5, r))}\n"
        sz_spr0 = range_to_size((l, l + 4))
        let3 = f"    let {operand.lower()}Opr = Bits.concat spr1 spr0 {sz_spr0} |> {get_conv_func(opr_type)}\n"
        return let1 + let2 + let3

operand_type_dict = {
    "A": (operand_to_let_direct, OprType.Imm),
    "BA": (operand_to_let_direct, OprType.CondBitReg),
    "BB": (operand_to_let_direct, OprType.CondBitReg),
    "BC": (operand_to_let_direct, OprType.CondBitReg),
    "BF": (operand_to_let_direct, OprType.Unknown),
    "BFA": (operand_to_let_direct, OprType.Unknown),
    "BH": (operand_to_let_direct, OprType.BH),
    "BHRBE": (operand_to_let_direct, OprType.Imm),
    "BI": (operand_to_let_direct, OprType.CondBitReg),
    "BO": (operand_to_let_direct, OprType.BO),
    "BT": (operand_to_let_direct, OprType.Unknown),
    "CT" : (operand_to_let_direct, OprType.Imm),
    "CY" : (operand_to_let_direct, OprType.CY),
    "D" : (operand_to_let_D, OprType.Imm64),
    "D2RA": (operand_to_let_eff_D_RA, OprType.Mem),
    "DCM": (operand_to_let_direct, OprType.DCM),
    "DCMX" : (operand_to_let_DCMX, OprType.DCM),
    "DGM": (operand_to_let_direct, OprType.DGM),
    "DM" : (operand_to_let_direct, OprType.Imm),
    "DRM": (operand_to_let_direct, OprType.Imm),
    "DS2RA": (operand_to_let_eff_DS_RA, OprType.Mem),
    "DQ2RA": (operand_to_let_eff_DQ_RA, OprType.Mem),
    "EH": (operand_to_let_direct, OprType.Imm),
    "FC": (operand_to_let_direct, OprType.Imm),
    "FRA": (operand_to_let_direct, OprType.FPReg),
    "FRAp": (operand_to_let_direct, OprType.FPReg),
    "FRB": (operand_to_let_direct, OprType.FPReg),
    "FRBp": (operand_to_let_direct, OprType.FPReg),
    "FRC": (operand_to_let_direct, OprType.FPReg),
    "FRS": (operand_to_let_direct, OprType.FPReg),
    "FRSp": (operand_to_let_direct, OprType.FPReg),
    "FRT": (operand_to_let_direct, OprType.FPReg),
    "FRTp": (operand_to_let_direct, OprType.FPReg),
    "FXM": (operand_to_let_direct, OprType.CRMask),
    "FLM": (operand_to_let_direct, OprType.FPSCRMask),
    "IH": (operand_to_let_direct, OprType.Imm),
    "IMM8": (operand_to_let_direct, OprType.Imm),
    "L" : (operand_to_let_direct, OprType.L),
    "LEV": (operand_to_let_direct, OprType.Imm),
    "MB": (operand_to_let_MB, OprType.Imm),
    "ME": (operand_to_let_ME, OprType.Imm),
    "NB": (operand_to_let_direct, OprType.Imm),
    "PRS": (operand_to_let_direct, OprType.Imm),
    "PS": (operand_to_let_direct, OprType.Imm),
    "R": (operand_to_let_direct, OprType.Imm),
    "RA": (operand_to_let_direct, OprType.Reg),
    "RB": (operand_to_let_direct, OprType.Reg),
    "RC": (operand_to_let_direct, OprType.Reg),
    "RIC": (operand_to_let_direct, OprType.Imm),
    "RM": (operand_to_let_direct, OprType.Imm),
    "RMC": (operand_to_let_direct, OprType.Imm),
    "RS": (operand_to_let_direct, OprType.Reg),
    "RSp": (operand_to_let_direct, OprType.Reg),
    "RT": (operand_to_let_direct, OprType.Reg),
    "RTp": (operand_to_let_direct, OprType.Reg),
    "S": (operand_to_let_direct, OprType.Imm),
    "SH": (operand_to_let_SH, OprType.Imm),
    "SHB": (operand_to_let_direct, OprType.Imm),
    "SHW": (operand_to_let_direct, OprType.Imm),
    "SI": (operand_to_let_direct_ext, OprType.Imm64),
    "SIM": (operand_to_let_direct_ext, OprType.Imm64),
    "SIX": (operand_to_let_direct, OprType.Imm),
    "SP": (operand_to_let_direct, OprType.Imm),
    "SPR": (operand_to_let_SPR, OprType.SPReg),
    "ST": (operand_to_let_direct, OprType.Imm),
    "TBR": (operand_to_let_direct, OprType.Imm),
    "TE": (operand_to_let_direct, OprType.Imm),
    "TH": (operand_to_let_direct, OprType.Imm),
    "TO": (operand_to_let_direct, OprType.TO),
    "targetaddr": (operand_to_let_target_addr, OprType.Addr),
    "U": (operand_to_let_direct, OprType.Imm),
    "UI": (operand_to_let_direct, OprType.Imm),
    "UIM": (operand_to_let_direct, OprType.Imm),
    "VRA": (operand_to_let_direct, OprType.VReg),
    "VRB": (operand_to_let_direct, OprType.VReg),
    "VRC": (operand_to_let_direct, OprType.VReg),
    "VRS": (operand_to_let_direct, OprType.VReg),
    "VRT": (operand_to_let_direct, OprType.VReg),
    "W": (operand_to_let_direct, OprType.W),
    "WC": (operand_to_let_direct, OprType.Imm),
    "XA": (operand_to_let_XA, OprType.VSReg),
    "XB": (operand_to_let_XB, OprType.VSReg),
    "XC": (operand_to_let_XC, OprType.VSReg),
    "XS": (operand_to_let_XS, OprType.VSReg),
    "XT": (operand_to_let_XT, OprType.VSReg)
}

def operand_to_let(operand, instr):
    if not operand in operand_type_dict:
        raise CodeGenerationError(f"unimplemented operand: {operand}")
    parse_func, opr_type = operand_type_dict[operand]
    if opr_type == OprType.Unknown:
        opr_type = get_ambiguous_opr_type(operand, instr)
    return parse_func(operand, opr_type, instr)

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
f_byte = open("generated_codes/allBytes.txt", "w")

enum_idx = 0
generated_opcodes = set()

for instr in instr_data:
    opcode = instr["opcode"]
    opcode_enum = opcode_to_enum(opcode)

    if not opcode in instrs_byte_dict:
        print(f"Code generation error: invalid opcode {opcode}")
        continue

    if opcode in generated_opcodes:
        print(f"Code generation error: duplicated opcode {opcode}")
        continue
    
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
        field_name = field['name']
        # If the field name is duplicated, make it unique by attaching a number
        field_name_num = ""
        field_name_idx = 1
        while field_name + field_name_num in fields_dict:
            field_name_num = str(field_name_idx)
            field_name_idx += 1
        
        fields_dict[field_name + field_name_num] = (field['field range'][0], field['field range'][1])
    instr["fields"] = fields_dict

    parsing_code = ""

    parsing_code += f"  | b when b &&&\n    {bitmask:#032b}u = {target_bit:#032b}u ->\n"
    parsing_code += f"    let opcode = Opcode.{opcode_enum}\n"
    try:
        for operand in operands:
            parsing_code += operand_to_let(operand, instr)
    except Exception as e:
        print(f"Code generation error in instr {instr["opcode"]}: {e}")
        continue
    parsing_code += f"    struct (opcode, {operands_to_str(operands)})\n"

    f_op_to_str.write(f"  | Op.{opcode_enum} -> \"{opcode}\"\n")
    f_op.write(f"  | {opcode_enum} = {enum_idx}\n")
    f_byte.write(instrs_byte_dict[opcode])
    f_parse.write(parsing_code)

    enum_idx += 1
    generated_opcodes.add(opcode)

f_op_to_str.close()
f_op.close()
f_parse.close()
f_byte.close()

missed_opcodes = instrs_byte_dict.keys() - generated_opcodes
print("# of generated opcodes:", len(generated_opcodes))
print("# of missed opcodes:", len(missed_opcodes))
print("list:")
for opcode in missed_opcodes:
    print(opcode)