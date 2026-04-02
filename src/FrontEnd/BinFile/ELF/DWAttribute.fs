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

/// Represents a DWARF attribute.
type DWAttribute =
  | DW_AT_sibling = 0x01us
  | DW_AT_location = 0x02us
  | DW_AT_name = 0x03us
  | DW_AT_ordering = 0x09us
  | DW_AT_subscr_data = 0x0aus
  | DW_AT_byte_size = 0x0bus
  | DW_AT_bit_offset = 0x0cus
  | DW_AT_bit_size = 0x0dus
  | DW_AT_element_list = 0x0fus
  | DW_AT_stmt_list = 0x10us
  | DW_AT_low_pc = 0x11us
  | DW_AT_high_pc = 0x12us
  | DW_AT_language = 0x13us
  | DW_AT_member = 0x14us
  | DW_AT_discr = 0x15us
  | DW_AT_discr_value = 0x16us
  | DW_AT_visibility = 0x17us
  | DW_AT_import = 0x18us
  | DW_AT_string_length = 0x19us
  | DW_AT_common_reference = 0x1aus
  | DW_AT_comp_dir = 0x1bus
  | DW_AT_const_value = 0x1cus
  | DW_AT_containing_type = 0x1dus
  | DW_AT_default_value = 0x1eus
  | DW_AT_inline = 0x20us
  | DW_AT_is_optional = 0x21us
  | DW_AT_lower_bound = 0x22us
  | DW_AT_producer = 0x25us
  | DW_AT_prototyped = 0x27us
  | DW_AT_return_addr = 0x2aus
  | DW_AT_start_scope = 0x2cus
  | DW_AT_bit_stride = 0x2eus
  | DW_AT_upper_bound = 0x2fus
  | DW_AT_abstract_origin = 0x31us
  | DW_AT_accessibility = 0x32us
  | DW_AT_address_class = 0x33us
  | DW_AT_artificial = 0x34us
  | DW_AT_base_types = 0x35us
  | DW_AT_calling_convention = 0x36us
  | DW_AT_count = 0x37us
  | DW_AT_data_member_location = 0x38us
  | DW_AT_decl_column = 0x39us
  | DW_AT_decl_file = 0x3aus
  | DW_AT_decl_line = 0x3bus
  | DW_AT_declaration = 0x3cus
  | DW_AT_discr_list = 0x3dus
  | DW_AT_encoding = 0x3eus
  | DW_AT_external = 0x3fus
  | DW_AT_frame_base = 0x40us
  | DW_AT_friend = 0x41us
  | DW_AT_identifier_case = 0x42us
  | DW_AT_macro_info = 0x43us
  | DW_AT_namelist_item = 0x44us
  | DW_AT_priority = 0x45us
  | DW_AT_segment = 0x46us
  | DW_AT_specification = 0x47us
  | DW_AT_static_link = 0x48us
  | DW_AT_type = 0x49us
  | DW_AT_use_location = 0x4aus
  | DW_AT_variable_parameter = 0x4bus
  | DW_AT_virtuality = 0x4cus
  | DW_AT_vtable_elem_location = 0x4dus
  | DW_AT_allocated = 0x4eus
  | DW_AT_associated = 0x4fus
  | DW_AT_data_location = 0x50us
  | DW_AT_byte_stride = 0x51us
  | DW_AT_entry_pc = 0x52us
  | DW_AT_use_UTF8 = 0x53us
  | DW_AT_extension = 0x54us
  | DW_AT_ranges = 0x55us
  | DW_AT_trampoline = 0x56us
  | DW_AT_call_column = 0x57us
  | DW_AT_call_file = 0x58us
  | DW_AT_call_line = 0x59us
  | DW_AT_description = 0x5aus
  | DW_AT_binary_scale = 0x5bus
  | DW_AT_decimal_scale = 0x5cus
  | DW_AT_small = 0x5dus
  | DW_AT_decimal_sign = 0x5eus
  | DW_AT_digit_count = 0x5fus
  | DW_AT_picture_string = 0x60us
  | DW_AT_mutable = 0x61us
  | DW_AT_threads_scaled = 0x62us
  | DW_AT_explicit = 0x63us
  | DW_AT_object_pointer = 0x64us
  | DW_AT_endianity = 0x65us
  | DW_AT_elemental = 0x66us
  | DW_AT_pure = 0x67us
  | DW_AT_recursive = 0x68us
  | DW_AT_signature = 0x69us
  | DW_AT_main_subprogram = 0x6aus
  | DW_AT_data_bit_offset = 0x6bus
  | DW_AT_const_expr = 0x6cus
  | DW_AT_enum_class = 0x6dus
  | DW_AT_linkage_name = 0x6eus
  | DW_AT_string_length_bit_size = 0x6fus
  | DW_AT_string_length_byte_size = 0x70us
  | DW_AT_rank = 0x71us
  | DW_AT_str_offsets_base = 0x72us
  | DW_AT_addr_base = 0x73us
  | DW_AT_rnglists_base = 0x74us
  | DW_AT_dwo_name = 0x76us
  | DW_AT_reference = 0x77us
  | DW_AT_rvalue_reference = 0x78us
  | DW_AT_macros = 0x79us
  | DW_AT_call_all_calls = 0x7aus
  | DW_AT_call_all_source_calls = 0x7bus
  | DW_AT_call_all_tail_calls = 0x7cus
  | DW_AT_call_return_pc = 0x7dus
  | DW_AT_call_value = 0x7eus
  | DW_AT_call_origin = 0x7fus
  | DW_AT_call_parameter = 0x80us
  | DW_AT_call_pc = 0x81us
  | DW_AT_call_tail_call = 0x82us
  | DW_AT_call_target = 0x83us
  | DW_AT_call_target_clobbered = 0x84us
  | DW_AT_call_data_location = 0x85us
  | DW_AT_call_data_value = 0x86us
  | DW_AT_noreturn = 0x87us
  | DW_AT_alignment = 0x88us
  | DW_AT_export_symbols = 0x89us
  | DW_AT_deleted = 0x8aus
  | DW_AT_defaulted = 0x8bus
  | DW_AT_loclists_base = 0x8cus
  | DW_AT_lo_user = 0x2000us
  | DW_AT_hi_user = 0x3fffus
  | DW_AT_MIPS_fde = 0x2001us
  | DW_AT_MIPS_loop_begin = 0x2002us
  | DW_AT_MIPS_tail_loop_begin = 0x2003us
  | DW_AT_MIPS_epilog_begin = 0x2004us
  | DW_AT_MIPS_loop_unroll_factor = 0x2005us
  | DW_AT_MIPS_software_pipeline_depth = 0x2006us
  | DW_AT_MIPS_linkage_name = 0x2007us
  | DW_AT_MIPS_stride = 0x2008us
  | DW_AT_MIPS_abstract_name = 0x2009us
  | DW_AT_MIPS_clone_origin = 0x200aus
  | DW_AT_MIPS_has_inlines = 0x200bus
  | DW_AT_HP_block_index = 0x2000us
  | DW_AT_HP_unmodifiable = 0x2001us
  | DW_AT_HP_prologue = 0x2005us
  | DW_AT_HP_epilogue = 0x2008us
  | DW_AT_HP_actuals_stmt_list = 0x2010us
  | DW_AT_HP_proc_per_section = 0x2011us
  | DW_AT_HP_raw_data_ptr = 0x2012us
  | DW_AT_HP_pass_by_reference = 0x2013us
  | DW_AT_HP_opt_level = 0x2014us
  | DW_AT_HP_prof_version_id = 0x2015us
  | DW_AT_HP_opt_flags = 0x2016us
  | DW_AT_HP_cold_region_low_pc = 0x2017us
  | DW_AT_HP_cold_region_high_pc = 0x2018us
  | DW_AT_HP_all_variables_modifiable = 0x2019us
  | DW_AT_HP_linkage_name = 0x201aus
  | DW_AT_HP_prof_flags = 0x201bus
  | DW_AT_HP_unit_name = 0x201fus
  | DW_AT_HP_unit_size = 0x2020us
  | DW_AT_HP_widened_byte_size = 0x2021us
  | DW_AT_HP_definition_points = 0x2022us
  | DW_AT_HP_default_location = 0x2023us
  | DW_AT_HP_is_result_param = 0x2029us
  | DW_AT_sf_names = 0x2101us
  | DW_AT_src_info = 0x2102us
  | DW_AT_mac_info = 0x2103us
  | DW_AT_src_coords = 0x2104us
  | DW_AT_body_begin = 0x2105us
  | DW_AT_body_end = 0x2106us
  | DW_AT_GNU_vector = 0x2107us
  | DW_AT_GNU_guarded_by = 0x2108us
  | DW_AT_GNU_pt_guarded_by = 0x2109us
  | DW_AT_GNU_guarded = 0x210aus
  | DW_AT_GNU_pt_guarded = 0x210bus
  | DW_AT_GNU_locks_excluded = 0x210cus
  | DW_AT_GNU_exclusive_locks_required = 0x210dus
  | DW_AT_GNU_shared_locks_required = 0x210eus
  | DW_AT_GNU_odr_signature = 0x210fus
  | DW_AT_GNU_template_name = 0x2110us
  | DW_AT_GNU_call_site_value = 0x2111us
  | DW_AT_GNU_call_site_data_value = 0x2112us
  | DW_AT_GNU_call_site_target = 0x2113us
  | DW_AT_GNU_call_site_target_clobbered = 0x2114us
  | DW_AT_GNU_tail_call = 0x2115us
  | DW_AT_GNU_all_tail_call_sites = 0x2116us
  | DW_AT_GNU_all_call_sites = 0x2117us
  | DW_AT_GNU_all_source_call_sites = 0x2118us
  | DW_AT_GNU_macros = 0x2119us
  | DW_AT_GNU_deleted = 0x211aus
  | DW_AT_GNU_dwo_name = 0x2130us
  | DW_AT_GNU_dwo_id = 0x2131us
  | DW_AT_GNU_ranges_base = 0x2132us
  | DW_AT_GNU_addr_base = 0x2133us
  | DW_AT_GNU_pubnames = 0x2134us
  | DW_AT_GNU_pubtypes = 0x2135us
  | DW_AT_GNU_discriminator = 0x2136us
  | DW_AT_GNU_locviews = 0x2137us
  | DW_AT_GNU_entry_view = 0x2138us
  | DW_AT_VMS_rtnbeg_pd_address = 0x2201us
  | DW_AT_use_GNAT_descriptive_type = 0x2301us
  | DW_AT_GNAT_descriptive_type = 0x2302us
  | DW_AT_GNU_numerator = 0x2303us
  | DW_AT_GNU_denominator = 0x2304us
  | DW_AT_GNU_bias = 0x2305us
  | DW_AT_upc_threads_scaled = 0x3210us
  | DW_AT_PGI_lbase = 0x3a00us
  | DW_AT_PGI_soffset = 0x3a01us
  | DW_AT_PGI_lstride = 0x3a02us
  | DW_AT_APPLE_optimized = 0x3fe1us
  | DW_AT_APPLE_flags = 0x3fe2us
  | DW_AT_APPLE_isa = 0x3fe3us
  | DW_AT_APPLE_block = 0x3fe4us
  | DW_AT_APPLE_major_runtime_vers = 0x3fe5us
  | DW_AT_APPLE_runtime_class = 0x3fe6us
  | DW_AT_APPLE_omit_frame_ptr = 0x3fe7us
  | DW_AT_APPLE_property_name = 0x3fe8us
  | DW_AT_APPLE_property_getter = 0x3fe9us
  | DW_AT_APPLE_property_setter = 0x3feaus
  | DW_AT_APPLE_property_attribute = 0x3febus
  | DW_AT_APPLE_objc_complete_type = 0x3fecus
  | DW_AT_APPLE_property = 0x3fedus

[<RequireQualifiedAccess>]
module internal DWAttribute =
  open LanguagePrimitives

  let parse (v: uint16) = EnumOfValue<uint16, DWAttribute> v
