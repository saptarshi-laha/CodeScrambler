import distorm3
import pefile
import sys
import numpy

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


def add_instructions_and_add_jump_positional_indicators(disassembled_machine_code, pe_type, complexity):
    if complexity <= 0:
        print("No complexity defined")
        status_success = False
        return status_success, -1, -1

    try:
        x64_instructions = []
        x86_instructions = []

        if pe_type == 0x10b:
            with open('x86_instructions.txt', 'r') as file:
                for line in file:
                    line = line.strip()
                    if line:
                        parts = line.replace('(', '').replace(')', '').split(',')
                        instruction = (parts[0].strip().strip("'"), int(parts[1].strip()))
                        x86_instructions.append(instruction)
        elif pe_type == 0x20b:
            with open('x64_instructions.txt', 'r') as file:
                for line in file:
                    line = line.strip()
                    if line:
                        parts = line.replace('(', '').replace(')', '').split(',')
                        instruction = (parts[0].strip().strip("'"), int(parts[1].strip()), -1)
                        x64_instructions.append(instruction)

        for section_name, instructions in disassembled_machine_code.items():
            total_instructions_in_section = len(instructions) * (complexity + 3)
            updated_instructions = {}
            for index, (_, _, _) in enumerate(instructions.values()):
                for i in range(0, complexity + 3):
                    if i % (complexity + 3) == complexity + 2:
                        updated_instructions[index*(complexity + 3)+i] = instructions[index]
                    elif i % (complexity + 3) == complexity + 1:
                        updated_instructions[index*(complexity + 3)+i] = (-3,-3,-3)
                    elif i % (complexity + 3) == complexity:
                        updated_instructions[index*(complexity + 3)+i] = (-2,-2,-2)
                    else:
                        updated_instructions[index*(complexity + 3)+i] = (-1, -1, -1)
            disassembled_machine_code[section_name] = updated_instructions

        status_success = True
        if pe_type == 0x10b:
            return status_success, disassembled_machine_code, x86_instructions
        elif pe_type == 0x20b:
            return status_success, disassembled_machine_code, x64_instructions

    except Exception as e:
        print(f"Error reading Junk Instruction file: {e}")
        status_success = False
        return status_success, -1, -1

def add_junk_instructions_to_positional_indicators(positional_indicators, complexity, junk_instructions):
    for section_name, instructions in positional_indicators.items():
        updated_instructions = {}
        complexity_counter = 0
        max_complexity = random_integer = numpy.random.randint(0, complexity + 1)
        updated_index = 0
        for index, (size, opcode, disassembly) in enumerate(instructions.values()):
            if (size == -2 and opcode == -2 and disassembly == -2):
                complexity_counter = 0
                max_complexity = numpy.random.randint(0, complexity + 1)

            if (size == -1 and opcode == -1 and disassembly == -1 and complexity_counter <= max_complexity):
                updated_instructions[updated_index] = junk_instructions[numpy.random.randint(0, len(junk_instructions))]
                updated_index += 1
                complexity_counter += 1
            elif (size == -1 and opcode == -1 and disassembly == -1 and complexity_counter > max_complexity):
                continue
            else:
                updated_instructions[updated_index] = instructions[index]
                updated_index += 1

        positional_indicators[section_name] = updated_instructions

    status_success = True
    return status_success, positional_indicators


def main():
    if len(sys.argv) < 5:
        print(
            "Usage: python3 CodeScrambler.py <pefile> <junk_instruction_complexity> <jump_complexity> <conditional jump on(1)/off(0)> <call/jump_switching on(1)/off(0)>")
        exit(1)
    else:
        filepath = sys.argv[1]
        complexity_junk_instr = int(sys.argv[2])
        complexity_jmp = int(sys.argv[3])
        conditional_jmp = int(sys.argv[4])
        call_jump_switching = int(sys.argv[5])
        success, code, pe_type, pe_oep, pe_ib, pe_oep_section, pe_oep_section_va = read_pe_file(filepath)

        if success:
            print("Successfully loaded and read PE file")
            success, output, oep_index = disassemble_machine_code(code, pe_type, pe_oep, pe_ib, pe_oep_section,
                                                                  pe_oep_section_va)
            if success:
                print("Successfully disassembled instructions")
                success, positional_output, junk_instructions = add_instructions_and_add_jump_positional_indicators(output, pe_type, complexity_junk_instr)

                if success:
                    print("Successfully added positional indicators")
                    success, positional_output = add_junk_instructions_to_positional_indicators(positional_output, complexity_junk_instr, junk_instructions)

                    if success:
                        print("Successfully added junk instructions to positions")
                        print(positional_output)

                    elif not success:
                        print("Error adding junk instructions to positions")
                        exit(1)

                elif not success:
                    print("Failed to add positional indicators")
                    exit(1)

            elif not success:
                print("Failed to disassemble instructions")
                exit(1)

        elif not success:
            print("Failed to load and read PE file")
            exit(1)


if __name__ == "__main__":
    main()
