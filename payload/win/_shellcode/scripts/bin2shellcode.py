import sys

if len(sys.argv) < 2:
    print("usage: %s <FILE>\n" % (sys.argv[0],))
    sys.exit(0)

shellcode = ""
ctr = 1
maxlen = 15

with open(sys.argv[1], "rb") as f:
    hexdata = f.read().hex()
    for i in range(0, len(hexdata), 2):
        shellcode += "\\x" + hexdata[i:i+2]

print(shellcode)

# for b in open(sys.argv[1], "rb").read():
#     print(b)
#     shellcode += "\\x" + b.encode("hex")
#     if ctr == maxlen:
#         shellcode += "\" +\n\""
#         ctr = 0
#     ctr += 1
# shellcode += "\""
# print(shellcode)