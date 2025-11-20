import pdfplumber
import json
import sys
import re
import random

pdf = pdfplumber.open("PowerISA_public.v3.0C.pdf")
pages = pdf.pages

start_page, end_page = 1217, 1234

def additional_bit_offset(chr, form, name):
    match chr:
        case ".":
            if form == "VC" or form == "XX3":
                return 21
            else:
                return 31
        case "l":
            return 31
        case "a":
            return 30
        case "o":
            if "[usingroundtoOdd]" in re.sub("[ \t\n]", "", name):
                return 31
            else:
                return 21
        case "x":
            return 31
        case _:
            print("unknown symbol")
            sys.exit(-1)

byte_exceptions = {
    "lq": "111000 ..... ..... ..... ..... ..////",      # typo in pdf
    "fcfids": "111111 ..... ///// ..... 11010 011100",  # typo in pdf
    "fcfids.": "111111 ..... ///// ..... 11010 011101", # typo in pdf
    "mtspr": "011111 ..... 01000 00000 01110 10011/",   # This instrunction uses SPR. SPR in this code is LR.
    "mfspr": "011111 ..... 00011 11000 01010 10011/",   # This instrunction uses SPR. SPR in this code is PMC1.
}

instrs_dict = {}

def make_random_byte(byte_struct):
    n = 0
    for chr in byte_struct:
        if chr == '0':
            n *= 2
        elif chr == '1':
            n = n * 2 + 1
        elif chr == ".":
            n = n * 2 + random.randint(0, 1)
    return n

def add_instr(dict, opcode, byte_struct, form, name):
    if "[" in opcode:
        idx = opcode.find("[")
        offset = additional_bit_offset(opcode[idx + 1], form, name)
        assert byte_struct[offset] == "."

        add_instr(dict, opcode[:idx] + opcode[idx+3:], 
                  byte_struct[:offset] + "0" + byte_struct[offset+1:], form, name)
        
        add_instr(dict, opcode[:idx] + opcode[idx+1] + opcode[idx+3:], 
                  byte_struct[:offset] + "1" + byte_struct[offset+1:], form, name)
    else:
        if opcode in byte_exceptions:
            byte_struct = byte_exceptions[opcode].replace("/", "0").replace(" ", "")
        dict[opcode] = f"{make_random_byte(byte_struct):08X}"

for page in pages[start_page-1:end_page]:
    instrs = page.extract_table()
    for instr in instrs[1:]:
        opcode = instr[4]
        byte_struct = instr[0].replace("/", "0").replace(" ", "")
        form = instr[1]
        name = instr[8]
        add_instr(instrs_dict, opcode, byte_struct, form, name)

f = open("byte_codes.json", 'w')
f.write(json.dumps(instrs_dict, indent=2))
f.close()