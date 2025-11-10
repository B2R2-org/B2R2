import json
import os
import sys

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
            operands_str = "NoOperand"
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
            print("too many operands")
            sys.exit(-1)

    return f"{operands_str}({", ".join(list(map(operand_to_str, operands)))})"

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
    return f"    let {operand.lower()}Opr = {range_to_extract(instr["fields"][operand])} |> getOprReg\n"

def operand_to_let_oprFPReg(operand, instr):
    return f"    let {operand.lower()}Opr = {range_to_extract(instr["fields"][operand])} |> getOprFPReg\n"

def should_use_CR(operand, instr):
    use_CR = True
    ambiguous_name = instr["opcode"] + "@" + operand

    if ambiguous_name in ambiguous_info:
        if ambiguous_info[ambiguous_name] == "CR":
            use_CR = True
        elif ambiguous_info[ambiguous_name] == "FPSCR":
            use_CR = False
        else:
            print("invalid ambiguous infomation")
            exit(-1)
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

def operand_to_let_BF(operand, instr):
    use_CR = should_use_CR(operand, instr)
    if use_CR:
        return f"    let {operand.lower()}Opr = {range_to_extract(instr["fields"][operand])} |> getOprCondReg\n"
    else:
        return f"    let {operand.lower()}Opr = {range_to_extract(instr["fields"][operand])} |> getOprFPSCondReg\n"

def operand_to_let_BT(operand, instr):
    use_CR = should_use_CR(operand, instr)
    if use_CR:
        return f"    let {operand.lower()}Opr = {range_to_extract(instr["fields"][operand])} |> getOprCondBitReg\n"
    else:
        return f"    let {operand.lower()}Opr = {range_to_extract(instr["fields"][operand])} |> getOprFPSCondBitReg\n"

def operand_to_let_BC(operand, instr):
    return f"    let {operand.lower()}Opr = {range_to_extract(instr["fields"][operand])} |> getOprCondBitReg\n"

def operand_to_let_oprImm(operand, instr):
    return f"    let {operand.lower()}Opr = {range_to_extract(instr["fields"][operand])} |> getOprImm\n"

def operand_to_let_oprCY(operand, instr):
    return f"    let {operand.lower()}Opr = {range_to_extract(instr["fields"][operand])} |> getOprCY\n"

def operand_to_let_oprL(operand, instr):
    return f"    let {operand.lower()}Opr = {range_to_extract(instr["fields"][operand])} |> getOprL\n"

def operand_to_let_D(operand, instr):
    if operand in instr["fields"]:
        return f"    let {operand.lower()}Opr = {range_to_extract(instr["fields"][operand])} |> getOprImm\n"
    else:
        let1 = f"    let d0 = {range_to_extract(instr["fields"]["d0"])}\n"
        let2 = f"    let d1 = {range_to_extract(instr["fields"]["d1"])}\n"
        let3 = f"    let d2 = {range_to_extract(instr["fields"]["d2"])}\n"
        sz_d2 = range_to_size(instr["fields"]["d2"])
        sz_d1 = range_to_size(instr["fields"]["d1"])
        let4 = f"    let {operand.lower()}Opr = Bits.concat d0 (Bits.concat d1 d2 {sz_d2}) {sz_d1 + sz_d2} |> getOprImm\n"
        return let1 + let2 + let3 + let4
    
def operand_to_let_target_addr(operand, instr):
    if "LI" in instr["fields"]:
        l, r = instr["fields"]["LI"]
    elif "BD" in instr["fields"]:
        l, r = instr["fields"]["BD"]
    else:
        print("there is no field for target address")
        sys.exit(-1)
    
    if extract_bits(instr["equal conditions"][1], 31 - instr["fields"]["AA"][1], 31 - instr["fields"]["AA"][0]) == 0:
        return f"    let {operand.lower()}Opr = addr + extractExtendedField bin {31 - l}u {31 - r}u 2 |> getOprAddr\n"
    else:
        return f"    let {operand.lower()}Opr = extractExtendedField bin {31 - l}u {31 - r}u 2 |> getOprAddr\n"
    
def operand_to_let_oprBO(operand, instr):
    return f"    let {operand.lower()}Opr = {range_to_extract(instr["fields"][operand])} |> getOprBO\n"

def operand_to_let_oprBI(operand, instr):
    return f"    let {operand.lower()}Opr = {range_to_extract(instr["fields"][operand])} |> getOprBI\n"

def operand_to_let_oprBH(operand, instr):
    return f"    let {operand.lower()}Opr = {range_to_extract(instr["fields"][operand])} |> getOprBH\n"

def operand_to_let_eff_D_RA(operand, instr):
    l, r = instr["fields"]["D"]
    let1 = f"    let ra = {range_to_extract(instr["fields"]["RA"])}\n"
    let2 = f"    let d = extractExtendedField bin {31 - l}u {31 - r}u 0\n"
    let3 = f"    let d2raOpr = getOprMem d ra\n"
    return let1 + let2 + let3

def operand_to_let_eff_DS_RA(operand, instr):
    l, r = instr["fields"]["DS"]
    let1 = f"    let ra = {range_to_extract(instr["fields"]["RA"])}\n"
    let2 = f"    let ds = extractExtendedField bin {31 - l}u {31 - r}u 2\n"
    let3 = f"    let ds2raOpr = getOprMem ds ra\n"
    return let1 + let2 + let3

def operand_to_let_eff_DQ_RA(operand, instr):
    l, r = instr["fields"]["DQ"]
    let1 = f"    let ra = {range_to_extract(instr["fields"]["RA"])}\n"
    let2 = f"    let dq = extractExtendedField bin {31 - l}u {31 - r}u 4\n"
    let3 = f"    let dq2raOpr = getOprMem dq ra\n"
    return let1 + let2 + let3

def operand_to_let_oprTO(operand, instr):
    return f"    let {operand.lower()}Opr = {range_to_extract(instr["fields"][operand])} |> getOprTO\n"

def operand_to_let_MB(operand, instr):
    if "MB" in instr["fields"]:
        return operand_to_let_oprImm(operand, instr)
    else:
        l, r = instr["fields"]["mb"]
        let1 = f"    let mb0 = {range_to_extract((l, r - 1))}\n"
        let2 = f"    let mb1 = {range_to_extract((r, r))}\n"
        sz_mb0 = range_to_size((l, r - 1))
        let3 = f"    let {operand.lower()}Opr = Bits.concat mb1 mb0 {sz_mb0} |> getOprImm\n"
        return let1 + let2 + let3

def operand_to_let_ME(operand, instr):
    if "ME" in instr["fields"]:
        return operand_to_let_oprImm(operand, instr)
    else:
        l, r = instr["fields"]["me"]
        let1 = f"    let me0 = {range_to_extract((l, r - 1))}\n"
        let2 = f"    let me1 = {range_to_extract((r, r))}\n"
        sz_me0 = range_to_size((l, r - 1))
        let3 = f"    let {operand.lower()}Opr = Bits.concat me1 me0 {sz_me0} |> getOprImm\n"
        return let1 + let2 + let3

def operand_to_let_SH(operand, instr):
    if "SH" in instr["fields"]:
        return operand_to_let_oprImm(operand, instr)
    else:
        let1 = f"    let sh0 = {range_to_extract(instr["fields"]["sh"])}\n"
        let2 = f"    let sh1 = {range_to_extract(instr["fields"]["sh1"])}\n"
        sz_sh0 = range_to_size(instr["fields"]["sh"])
        let3 = f"    let {operand.lower()}Opr = Bits.concat sh1 sh0 {sz_sh0} |> getOprImm\n"
        return let1 + let2 + let3
    
def operand_to_let_XS(operand, instr):
    let1 = f"    let s = {range_to_extract(instr["fields"]["S"])}\n"
    let2 = f"    let sx = {range_to_extract(instr["fields"]["SX"])}\n"
    let3 = f"    let {operand.lower()}Opr = 32u * sx + s |> getOprVSReg\n"
    return let1 + let2 + let3

def operand_to_let_XT(operand, instr):
    let1 = f"    let t = {range_to_extract(instr["fields"]["T"])}\n"
    let2 = f"    let tx = {range_to_extract(instr["fields"]["TX"])}\n"
    let3 = f"    let {operand.lower()}Opr = 32u * tx + t |> getOprVSReg\n"
    return let1 + let2 + let3

def operand_to_let_SPR(operand, instr):
    if "SPR" in instr["fields"]:
        return operand_to_let_oprImm(operand, instr)
    else:
        l, r = instr["fields"]["spr"]
        let1 = f"    let spr0 = {range_to_extract((l, l + 4))}\n"
        let2 = f"    let spr1 = {range_to_extract((l + 5, r))}\n"
        sz_spr0 = range_to_size((l, l + 4))
        let3 = f"    let {operand.lower()}Opr = Bits.concat spr1 spr0 {sz_spr0} |> getOprSPReg\n"
        return let1 + let2 + let3

def operand_to_let_oprCRMask(operand, instr):
    return f"    let {operand.lower()}Opr = {range_to_extract(instr["fields"][operand])} |> getOprCRMask\n"

def operand_to_let_oprFPSCRMask(operand, instr):
    return f"    let {operand.lower()}Opr = {range_to_extract(instr["fields"][operand])} |> getOprFPSCRMask\n"

def operand_to_let_oprW(operand, instr):
    return f"    let {operand.lower()}Opr = {range_to_extract(instr["fields"][operand])} |> getOprW\n"

operand_type_dict = {
    "BC": operand_to_let_BC,
    "BF": operand_to_let_BF,
    "BFA": operand_to_let_BF,
    "BH": operand_to_let_oprBH,
    "BI": operand_to_let_oprBI,
    "BO": operand_to_let_oprBO,
    "BT": operand_to_let_BT,
    "CY" : operand_to_let_oprCY,
    "D" : operand_to_let_D,
    "D2RA": operand_to_let_eff_D_RA,
    "DRM": operand_to_let_oprImm,
    "DS2RA": operand_to_let_eff_DS_RA,
    "DQ2RA": operand_to_let_eff_DQ_RA,
    "FRA": operand_to_let_oprFPReg,
    "FRAp": operand_to_let_oprFPReg,
    "FRB": operand_to_let_oprFPReg,
    "FRBp": operand_to_let_oprFPReg,
    "FRC": operand_to_let_oprFPReg,
    "FRS": operand_to_let_oprFPReg,
    "FRSp": operand_to_let_oprFPReg,
    "FRT": operand_to_let_oprFPReg,
    "FRTp": operand_to_let_oprFPReg,
    "FXM": operand_to_let_oprCRMask,
    "FLM": operand_to_let_oprFPSCRMask,
    "L" : operand_to_let_oprL,
    "MB": operand_to_let_MB,
    "ME": operand_to_let_ME,
    "NB": operand_to_let_oprImm,
    "RA": operand_to_let_oprReg,
    "RB": operand_to_let_oprReg,
    "RC": operand_to_let_oprReg,
    "RM": operand_to_let_oprImm,
    "RS": operand_to_let_oprReg,
    "RSp": operand_to_let_oprReg,
    "RT": operand_to_let_oprReg,
    "RTp": operand_to_let_oprReg,
    "SH": operand_to_let_SH,
    "SI": operand_to_let_oprImm,
    "SPR": operand_to_let_SPR,
    "TO": operand_to_let_oprTO,
    "targetaddr": operand_to_let_target_addr,
    "U": operand_to_let_oprImm,
    "UI": operand_to_let_oprImm,
    "W": operand_to_let_oprW,
    "XS": operand_to_let_XS,
    "XT": operand_to_let_XT
}

def operand_to_let(operand, instr):
    if not operand in operand_type_dict:
        print(f"unimplemented operand in instr {instr["opcode"]}: {operand}")
        sys.exit(-1)
    return operand_type_dict[operand](operand, instr)



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

enum_start_idx = 284

for i, instr in enumerate(instr_data):
    opcode = instr["opcode"]
    opcode_enum = opcode_to_enum(opcode)

    f_op_to_str.write(f"  | Op.{opcode_enum} -> \"{opcode}\"\n")
    f_op.write(f"  | {opcode_enum} = {enum_start_idx + i}\n")
    
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

    f_parse.write(f"  | b when b &&&\n    {bitmask:#032b}u = {target_bit:#032b}u ->\n")
    f_parse.write(f"    let opcode = Opcode.{opcode_enum}\n")
    for operand in operands:
        f_parse.write(operand_to_let(operand, instr))
    f_parse.write(f"    struct (opcode, {operands_to_str(operands)})\n")

f_op_to_str.close()
f_op.close()
f_parse.close()