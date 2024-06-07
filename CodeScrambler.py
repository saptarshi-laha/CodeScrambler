import distorm3
import pefile

def read_pe_file(file_path):

    executable_sections_data = {}

    try:

        pe = pefile.PE(file_path)
        pe_type = pe.OPTIONAL_HEADER.Magic
        pe_oep = pe.OPTIONAL_HEADER.AddressOfEntryPoint

        for section in pe.sections:
            is_executable = bool(section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_EXECUTE'])
            if is_executable:
                section_data = section.get_data()
                section_name = section.Name.decode().rstrip().rstrip('\x00')
                executable_sections_data[section_name] = section_data
        return executable_sections_data, pe_type, pe_oep

    except pefile.PEFormatError as e:
        print(f"Error reading PE file: {e}")

def disassemble_machine_code(code, pe_type):

    status_success = False
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
            return status_success, output

    status_success = True
    return status_success, output

def main():

    filepath = input("Enter the path to the PE file :\n")
    code, pe_type, pe_oep = read_pe_file(filepath)
    success, output = disassemble_machine_code(code, pe_type)

    if success == True:
        print("Successfully disassembled instructions");
    elif success == False:
        print("Failed to disassemble instructions");


if __name__ == "__main__":
    main()
