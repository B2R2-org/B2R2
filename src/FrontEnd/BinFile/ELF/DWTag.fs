(*
  B2R2 - the Next-Generation Reversing Platform

  Copyright (c) SoftSec Lab. @ KAIST, since 2016

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in all
  copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
  SOFTWARE.
*)

namespace B2R2.FrontEnd.BinFile.ELF

/// Represents a DWARF tag.
type DWTag =
  | DW_TAG_array_type = 0x01us
  | DW_TAG_class_type = 0x02us
  | DW_TAG_entry_point = 0x03us
  | DW_TAG_enumeration_type = 0x04us
  | DW_TAG_formal_parameter = 0x05us
  | DW_TAG_imported_declaration = 0x08us
  | DW_TAG_label = 0x0aus
  | DW_TAG_lexical_block = 0x0bus
  | DW_TAG_member = 0x0dus
  | DW_TAG_pointer_type = 0x0fus
  | DW_TAG_reference_type = 0x10us
  | DW_TAG_compile_unit = 0x11us
  | DW_TAG_string_type = 0x12us
  | DW_TAG_structure_type = 0x13us
  | DW_TAG_subroutine_type = 0x15us
  | DW_TAG_typedef = 0x16us
  | DW_TAG_union_type = 0x17us
  | DW_TAG_unspecified_parameters = 0x18us
  | DW_TAG_variant = 0x19us
  | DW_TAG_common_block = 0x1aus
  | DW_TAG_common_inclusion = 0x1bus
  | DW_TAG_inheritance = 0x1cus
  | DW_TAG_inlined_subroutine = 0x1dus
  | DW_TAG_module = 0x1eus
  | DW_TAG_ptr_to_member_type = 0x1fus
  | DW_TAG_set_type = 0x20us
  | DW_TAG_subrange_type = 0x21us
  | DW_TAG_with_stmt = 0x22us
  | DW_TAG_access_declaration = 0x23us
  | DW_TAG_base_type = 0x24us
  | DW_TAG_catch_block = 0x25us
  | DW_TAG_const_type = 0x26us
  | DW_TAG_constant = 0x27us
  | DW_TAG_enumerator = 0x28us
  | DW_TAG_file_type = 0x29us
  | DW_TAG_friend = 0x2aus
  | DW_TAG_namelist = 0x2bus
  | DW_TAG_namelist_item = 0x2cus
  | DW_TAG_packed_type = 0x2dus
  | DW_TAG_subprogram = 0x2eus
  | DW_TAG_template_type_param = 0x2fus
  | DW_TAG_template_value_param = 0x30us
  | DW_TAG_thrown_type = 0x31us
  | DW_TAG_try_block = 0x32us
  | DW_TAG_variant_part = 0x33us
  | DW_TAG_variable = 0x34us
  | DW_TAG_volatile_type = 0x35us
  | DW_TAG_dwarf_procedure = 0x36us
  | DW_TAG_restrict_type = 0x37us
  | DW_TAG_interface_type = 0x38us
  | DW_TAG_namespace = 0x39us
  | DW_TAG_imported_module = 0x3aus
  | DW_TAG_unspecified_type = 0x3bus
  | DW_TAG_partial_unit = 0x3cus
  | DW_TAG_imported_unit = 0x3dus
  | DW_TAG_condition = 0x3fus
  | DW_TAG_shared_type = 0x40us
  | DW_TAG_type_unit = 0x41us
  | DW_TAG_rvalue_reference_type = 0x42us
  | DW_TAG_template_alias = 0x43us
  | DW_TAG_coarray_type = 0x44us
  | DW_TAG_generic_subrange = 0x45us
  | DW_TAG_dynamic_type = 0x46us
  | DW_TAG_atomic_type = 0x47us
  | DW_TAG_call_site = 0x48us
  | DW_TAG_call_site_parameter = 0x49us
  | DW_TAG_skeleton_unit = 0x4aus
  | DW_TAG_immutable_type = 0x4bus
  | DW_TAG_lo_user = 0x4080us
  | DW_TAG_hi_user = 0xffffus
  | DW_TAG_MIPS_loop = 0x4081us
  | DW_TAG_HP_array_descriptor = 0x4090us
  | DW_TAG_HP_Bliss_field = 0x4091us
  | DW_TAG_HP_Bliss_field_set = 0x4092us
  | DW_TAG_format_label = 0x4101us
  | DW_TAG_function_template = 0x4102us
  | DW_TAG_class_template = 0x4103us
  | DW_TAG_GNU_BINCL = 0x4104us
  | DW_TAG_GNU_EINCL = 0x4105us
  | DW_TAG_GNU_template_template_param = 0x4106us
  | DW_TAG_GNU_template_parameter_pack = 0x4107us
  | DW_TAG_GNU_formal_parameter_pack = 0x4108us
  | DW_TAG_GNU_call_site = 0x4109us
  | DW_TAG_GNU_call_site_parameter = 0x410aus
  | DW_TAG_upc_shared_type = 0x8765us
  | DW_TAG_upc_strict_type = 0x8766us
  | DW_TAG_upc_relaxed_type = 0x8767us
  | DW_TAG_PGI_kanji_type = 0xa000us
  | DW_TAG_PGI_interface_block = 0xa020us

[<RequireQualifiedAccess>]
module internal DWTag =
  open LanguagePrimitives

  let parse (v: uint16) = EnumOfValue<uint16, DWTag> v
