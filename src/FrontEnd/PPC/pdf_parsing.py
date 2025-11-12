import pdfplumber
import json
import re
import sys

def is_offset_line(line):
    words = line.split(" ")
    for word in words:
        if not word.isdecimal():
            return False
    return len(words) >= 3 and words[0] == "0" and words[1] == "6" and words[-1].endswith("31")


def offset_line_to_list(offsets_line):
    offsets = []
    for offset in offsets_line.split(" "):
        offset_curr = ""
        for chr in offset:
            if int(offset_curr + chr) >= 32:
                # If pdf parser does not put a space between two offsets, cut appropriately
                assert not (len(offsets) > 0 and offsets[-1] >= int(offset_curr))
                offsets.append(int(offset_curr))
                offset_curr = ""
            offset_curr += chr
        
        assert not (len(offsets) > 0 and offsets[-1] >= int(offset_curr))
        offsets.append(int(offset_curr))
    
    return offsets

def to_json(operands_line, fields_line, offsets_line):
    operands = list(filter(None, re.split("[ ,]", operands_line)))
    offsets = offset_line_to_list(offsets_line)
    fields = fields_line.split(" ")

    # If the last field range is 31~31
    if len(offsets) == len(fields):
        offsets.append(31)
    assert(len(offsets) == len(fields) + 1)

    offsets[-1] += 1

    instr = {
        "opcode": operands[0],
        "operands": [],
        "fields": [],
        "equal conditions": []
    }

    condition_map = {}

    for operand in operands[1:]:
        if "=" in operand:
            field, value = re.sub("[()]", "", operand).split("=")
            condition_map[field] = value
        else:
            if "(" in operand:
                instr["operands"].append((operand.replace("(", "2")).replace(")", ""))
            else:
                instr["operands"].append(operand.replace("_", ""))

    for i in range(len(fields)):
        field = fields[i]
        field_range = [offsets[i], offsets[i + 1] - 1]
        if field.isdecimal():
            instr["equal conditions"].append({"value": int(field), "field range": field_range})
        elif field.startswith("/"):
            instr["equal conditions"].append({"value": 0, "field range": field_range})
        elif field in condition_map:
            instr["equal conditions"].append({"value": condition_map[field], "field range": field_range})
            instr["fields"].append({"name": field, "field range": field_range})
        else:
            instr["fields"].append({"name": field, "field range": field_range})

    return instr

def extract_instrs(page):
    lines = page.extract_text(x_tolerance = 1).split("\n")
    instrs = []
    for i in range(2, len(lines)):
        if not is_offset_line(lines[i]):
            continue

        offsets_line = lines[i]
        fields_line = lines[i - 1]

        start_idx = i - 2
        end_idx = i - 1

        # If the offsets are above the field table
        if i + 1 < len(lines) and not fields_line.split(" ")[0].isdecimal():
            fields_line = lines[i + 1]
            start_idx += 1
            end_idx += 1
        
        # If there are multiple instructions in one field table
        if lines[start_idx].endswith(")"):
            while start_idx > 0 and lines[start_idx - 1].endswith(")"):
                start_idx -= 1
                
        for operands_line in lines[start_idx:end_idx]:
            instrs.append(to_json(operands_line, fields_line, offsets_line))
    
    return instrs

pdf = pdfplumber.open("PowerISA_public.v3.0C.pdf")
pages = pdf.pages

if len(sys.argv) < 4:
    print("usage: python pdf_parsing.py start_page end_page output_file_name")
    sys.exit()

start_page, end_page = int(sys.argv[1]), int(sys.argv[2])
file_name = sys.argv[3]
f = open(file_name, 'w')

all_instrs = []

for i in range(start_page, end_page + 1):
    page = pages[i - 1]

    H, W = page.height, page.width
    left_page = page.crop((0, 0, W / 2, H))
    right_page = page.crop((W / 2, 0, W, H))

    left_instrs = extract_instrs(left_page)
    right_instrs = extract_instrs(right_page)

    all_instrs.extend(left_instrs)
    all_instrs.extend(right_instrs)

    print(f"page {i}: {len(left_instrs)} instrs in left, {len(right_instrs)} instrs in right.")

f.write(json.dumps(all_instrs, indent=2))
f.close()