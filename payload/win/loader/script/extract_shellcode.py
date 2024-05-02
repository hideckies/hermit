#!/usr/bin/env python3
# -*- coding:utf-8 -*-
import pefile
import argparse

if __name__ in '__main__':
    try:
        parser = argparse.ArgumentParser(description='Extract shellcode from a PE file.')
        parser.add_argument('-f', required = True, help='Path to the PE file', type = str)
        parser.add_argument('-o', required = True, help='Path to the output raw file', type = str)
        args = parser.parse_args()

        shellcode = b""

        pe = pefile.PE(args.f)
        sec = pe.sections[0].get_data()

        print(sec)
        print(f"OSHIMAI: {sec.find(b'OSHIMAI')}")

        if sec.find(b'OSHIMAI') != None:
            secRaw = sec[:sec.find(b'OSHIMAI')]
            with open(args.o, 'wb+') as f:
                f.write(secRaw)
    except Exception as e:
        print('[!] error: {}'.format(e))
