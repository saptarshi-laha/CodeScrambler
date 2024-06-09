import distorm3
import pefile
import sys


def read_pe_file(file_path):
    executable_sections_data = {}

    try:

        pe = pefile.PE(file_path)
        pe_type = pe.OPTIONAL_HEADER.Magic
        pe_oep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        pe_ib = pe.OPTIONAL_HEADER.ImageBase
        pe_oep_section = ""
        pe_oep_section_va = 0

        for section in pe.sections:
            if section.contains_rva(pe_oep):
                pe_oep_section = section.Name.decode().rstrip().rstrip('\x00')
                pe_oep_section_va = section.VirtualAddress

            is_executable = bool(section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_EXECUTE'])

            if is_executable:
                section_data = section.get_data()
                section_name = section.Name.decode().rstrip().rstrip('\x00')
                executable_sections_data[section_name] = section_data

        status_success = True
        return status_success, executable_sections_data, pe_type, pe_oep, pe_ib, pe_oep_section, pe_oep_section_va

    except Exception as e:
        print(f"Error reading PE file: {e}")
        status_success = False
        return status_success, -1, -1, -1, -1, -1, -1


def disassemble_machine_code(code, pe_type, pe_oep, pe_ib, pe_oep_section, pe_oep_section_va):
    output = {}

    for section_name, data in code.items():
        counter = 0
        if section_name not in output:
            output[section_name] = {}

        if pe_type == 0x10b:
            instructions = distorm3.Decode(0, data, distorm3.Decode32Bits)
            for (offset, size, instruction, hexdump) in instructions:
                output[section_name][counter] = size, hexdump, instruction
                counter += 1
        elif pe_type == 0x20b:
            instructions = distorm3.Decode(0, data, distorm3.Decode64Bits)
            for (offset, size, instruction, hexdump) in instructions:
                output[section_name][counter] = size, hexdump, instruction
                counter += 1
        else:
            print("Unsupported PE type")
            status_success = False
            return status_success, output, -1

    oep_offset = pe_ib + pe_oep_section_va
    oep_index = 0
    normalized_oep = pe_ib + pe_oep

    for section_name, instructions in output.items():
        if section_name == pe_oep_section:
            for index, (size, _, _) in enumerate(instructions.values()):
                if oep_offset == normalized_oep:
                    oep_index = index
                    break
                oep_offset += size
            break

    status_success = True
    return status_success, output, oep_index


def add_instructions_and_add_jump_positional_indicators(disassembled_machine_code, pe_type, oep_index, complexity):
    x64_instructions = [('90', 1), ('4889c0', 3), ('5058', 2), ('488d4000', 4)]
    x86_instructions = [('90', 1), ('89c0', 2), ('5058', 2), ('8d4000', 3)]

    # The aim for the above is to be imported from a different pre-defined list.
    # These are just examples above used for testing. This code will be added in later.


def main():
    if len(sys.argv) < 3:
        print(
            "Usage: python3 CodeScrambler.py <pefile> <complexity>\nThe complexity argument is a number between 0 and "
            "N which indicates the maximum number of junk arguments inserted into machine code between consecutive "
            "instructions.\nThe selection of junk opcodes is random and so is the number of junk arguments, "
            "but this number will never exceed complexity.\nIt is also important to remember that the complexity "
            "cannot exceed the number of junk instructions provided in the list.")
    else:
        filepath = sys.argv[1]
        complexity_percent = int(sys.argv[2])
        success, code, pe_type, pe_oep, pe_ib, pe_oep_section, pe_oep_section_va = read_pe_file(filepath)

        if success:
            print("Successfully loaded and read PE file")
            success, output, oep_index = disassemble_machine_code(code, pe_type, pe_oep, pe_ib, pe_oep_section,
                                                                  pe_oep_section_va)
            print(output)
            if success:
                print("Successfully disassembled instructions")
                add_instructions_and_add_jump_positional_indicators(output, pe_type, oep_index, complexity_percent)
            elif not success:
                print("Failed to disassemble instructions")
                return 1

        elif not success:
            print("Failed to load and read PE file")
            return 1


if __name__ == "__main__":
    main()
