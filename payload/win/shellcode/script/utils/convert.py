# Convert string to HEX array
# e.g. calc.exe -(HEX)-> 63616c632e657865 -(LITTLE-ENDIAN)-> 6578652e636c6163 -(NOT)-> 9A879AD19C939E9C
# If set 'is_not' to True, avoid to detect it in static analysis.
def str2hex(text: str, not_op: bool):
    hexarr = []

    # str -> hex
    cmd_hex = text.encode('utf-8').hex()

    # hex -> hex(little-endian)
    cmd_hex_little = bytes.fromhex(cmd_hex)[::-1].hex()

    if not_op is False:
        hexarr.append('0x' + cmd_hex_little)
    else:
        # NOT operations
        not_result = ""
        max_len = 16
        for i in range(0, max_len, 2):
            try:
                hex_chars = cmd_hex_little[i:i+2]
                hex_chars_not_int = ~int(hex_chars, 16)
                hex_chars_not = format(hex_chars_not_int & 0xFF, '02x')
                not_result += hex_chars_not
            except:
                not_result += '0f'

        hexarr.append('0x' + not_result)
    
    return hexarr
