from typing import List, Tuple

# Convert string to ASCII code for assembly.
# e.g. calc.exe -(HEX)-> 63616c632e657865 -(LITTLE-ENDIAN)-> 6578652e636c6163 -(NOT)-> 9A879AD19C939E9C
# If set 'not_op' to True, avoid to detect it in static analysis.
def str2hex(text: str, not_op: bool) -> Tuple[List[str], str]:
    # str -> hex
    cmd_hex = text.encode('utf-8').hex()

    # Split into 16-digit
    chunks = [cmd_hex[i:i+16] for i in range(0, len(cmd_hex), 16)]

    for i in range(0, len(chunks)):
        # hex -> hex(little-endian)
        chunks[i] = bytes.fromhex(chunks[i])[::-1].hex()

    # Get the shift right number for the last element (it's used for `shr rax, 0x[hex_num]` in assembly)
    shr_hex = hex((16 - len(chunks[-1])) * 4)[2:]

    # Fill with 'f' for the last element
    if len(chunks[-1]) < 16:
        chunks[-1] = chunks[-1].ljust(16, "f")

    # Lastly, reverse the chunks
    chunks.reverse()

    return chunks, shr_hex


    # if not_op is False:
    #     hexarr.append('0x' + cmd_hex_little)
    # else:
    #     # NOT operations
    #     not_result = ""
    #     max_len = 16
    #     # for i in range(0, max_len, 2):
    #     for i in range(0, len(cmd_hex_little), 2):
    #         try:
    #             hex_chars = cmd_hex_little[i:i+2]
    #             hex_chars_not_int = ~int(hex_chars, 16)
    #             hex_chars_not = format(hex_chars_not_int & 0xFF, '02x')
    #             not_result += hex_chars_not
    #         except:
    #             not_result += ''


        # hexarr.append('0x' + not_result)
    