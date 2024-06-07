import distorm3
import pefile

def read_pe_file(file_path):

    executable_sections_data = {}

    try:
        pe = pefile.PE(file_path)

        for section in pe.sections:
            is_executable = bool(section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_EXECUTE'])
            if is_executable:
                section_data = section.get_data()
                section_name = section.Name.decode().rstrip()
                executable_sections_data[section_name] = section_data
        return executable_sections_data

    except pefile.PEFormatError as e:
        print(f"Error reading PE file: {e}")

def disassemble_machine_code(code, mode):
    output = []
    for section_name, data in code.items():
        output.append(f"\nDisassembled instructions for section: {section_name}\n")
        instructions = distorm3.Decode(0, data, distorm3.Decode32Bits)
        for (offset, size, instruction, hexdump) in instructions:
            output.append(f"{offset:08x} ({size:02x}) {hexdump} {instruction}\n")

def print_instructions(instructions):
    for instruction in instructions:
        print(instruction)

def main():
    filepath = input("Enter the path to the PE file :\n")
    code = read_pe_file(filepath)
    disassemble_machine_code(code, distorm3.Decode64Bits)


if __name__ == "__main__":
    main()
