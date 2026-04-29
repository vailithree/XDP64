import sys
import re
import struct
import math

def pack_f8(d):
    if math.isnan(d): return 0x79
    sign = 1 if math.copysign(1.0, d) < 0.0 else 0
    d = abs(d)
    if d == float('inf'): return (sign << 7) | 0x78
    if d == 0.0: return (sign << 7)

    mant, exp = math.frexp(d)
    mant *= 2.0
    exp -= 1

    stored_exp = exp + 7
    if stored_exp >= 0xF: return (sign << 7) | 0x78

    if stored_exp <= 0:
        mant = d / 0.015625
        m = int(mant * 8.0 + 0.5)
        if m >= 8: return (sign << 7) | (1 << 3) | 0
        return (sign << 7) | m

    m = int((mant - 1.0) * 8.0 + 0.5)
    if m >= 8:
        m = 0
        stored_exp += 1
        if stored_exp >= 0xF: return (sign << 7) | 0x78
    return (sign << 7) | (stored_exp << 3) | m

class XDP64Assembler:
    def __init__(self):
        self.labels = {}
        self.current_address = 0
        self.opcodes = {
            'NOP': 0, 'HLT': 1, 'LDR': 2, 'STR': 3, 'XCH': 4, 'ORL': 5,
            'AND': 6, 'NOT': 7, 'ADD': 8, 'SUB': 9, 'PUSH': 10, 'POP': 11,
            'SKE': 12, 'SNE': 13, 'SGT': 14, 'SLT': 15, 'SGE': 16, 'SLE': 17,
            'JMP': 18, 'JIZ': 19, 'JNZ': 20, 'JIN': 21, 'JIP': 22, 'JGZ': 23,
            'PUSHJ': 24, 'POPJ': 25, 'JIC': 26, 'MUL': 27, 'JAS': 28, 'AOS': 29,
            'ALS': 30, 'ALE': 31, 'AIZ': 32, 'ANZ': 33, 'AGZ': 34, 'AGE': 35,
            'AAS': 36, 'SOS': 37, 'SLS': 38, 'SLE_DEC': 39, 'SIZ': 40, 'SNZ': 41,
            'SGZ': 42, 'SGEZ': 43, 'SAS': 44, 'XOR': 45, 'EDS': 46, 'DIV': 47,
            'LSLI': 48, 'LSRI': 49, 'LSL': 50, 'LSR': 51,
            'ASLI': 52, 'ASRI': 53, 'ASL': 54, 'ASR': 55,
            'ROLI': 56, 'RORI': 57, 'ROL': 58, 'ROR': 59,
            'FAD': 60, 'FSB': 61, 'FML': 62, 'FDV': 63,
            'JAC': 67, 'JCC': 68, 'JISC': 69
        }
        self.special_ops = ['PRINTS', 'INPUT', 'PRINTI', 'TSTAT', 'ITOA', 'ATOI', 'FTOA', 'ATOF', 'FTOS', 'TWRITE', 'TREAD', 'LFS', 'LSA', 'TRAP', 'TRET', 'LDI', 'LSP', 'ADI']
        self.res_ops = ['RESW', 'RESH', 'RESF', 'RESB']

    def parse_reg(self, reg_str):
        if not reg_str: return 0
        match = re.search(r'A(\d+)', reg_str, re.I)
        return int(match.group(1)) if match else 0

    def parse_special_reg(self, name):
        name = name.strip().upper()
        if name == 'BASE': return 0
        if name == 'TTB': return 1
        if name == 'ETB': return 2
        try: return int(name, 0) & 0xFF
        except ValueError: return 0

    def parse_mem(self, mem_str):
        offset, index, pc_rel, mode = 0, 0, 0, 0
        if '(r)' in mem_str or ',r' in mem_str:
            pc_rel = 1
            mem_str = mem_str.replace('(r)', '').replace(',r', '').strip()
        match = re.search(r'\((.*?)\)', mem_str)
        if match:
            inner = match.group(1).strip()
            if inner.startswith('+'): mode, index = 1, self.parse_reg(inner[1:])
            elif inner.endswith('-'): mode, index = 2, self.parse_reg(inner[:-1])
            else: index = self.parse_reg(inner)
            mem_str = re.sub(r'\(.*?\)', '', mem_str).strip()
        if mem_str:
            try: offset = int(mem_str, 0)
            except ValueError:
                m_reg = re.match(r'^A(\d+)$', mem_str, re.I)
                if m_reg: offset = int(m_reg.group(1))
                else: offset = mem_str
        return offset, index, pc_rel, mode

    def get_label(self, name, addr):
        if name in self.labels:
            return self.labels[name]
        print(f"Assembler Error: Undefined label '{name}' referenced at address {addr:04X}")
        sys.exit(1)

    def parse_value(self, raw_str, addr):
        raw_str = raw_str.strip()
        prefix = raw_str[0].lower() if raw_str and raw_str[0].lower() in 'whfb' else 'w'
        val_str = raw_str[1:] if raw_str and raw_str[0].lower() in 'whfb' else raw_str

        is_float = False
        val = 0
        try:
            if '.' in val_str or 'e' in val_str.lower():
                val = float(val_str)
                is_float = True
            else:
                val = int(val_str, 0)
        except ValueError:
            return self.get_label(raw_str, addr)

        if is_float:
            if prefix == 'b': return pack_f8(val) & 0xFF
            elif prefix == 'f': return struct.unpack('<H', struct.pack('<e', val))[0]
            elif prefix == 'h': return struct.unpack('<I', struct.pack('<f', val))[0]
            else: return struct.unpack('<Q', struct.pack('<d', val))[0]
        else:
            return val

    def assemble(self, infile, outfile, verbose=False):
        try:
            with open(infile, 'r') as f:
                lines = f.readlines()
        except Exception as e:
            print(f"Error reading file: {e}")
            return

        # PASS 1: Resolution & Label Gathering
        self.current_address = 0
        clean_lines = []
        for line in lines:
            line = line.split(';')[0].strip()
            if not line: continue

            tokens = re.split(r'\s+', line, maxsplit=1)

            # Robust label matching to safely strip labels without breaking raw data
            label_match = re.match(r'^([A-Za-z_.][A-Za-z0-9_.$]*),$', tokens[0])
            if label_match:
                lbl = label_match.group(1)
                self.labels[lbl] = self.current_address
                if len(tokens) == 1:
                    continue
                line = tokens[1].strip()
                if not line: continue
                tokens = re.split(r'\s+', line, maxsplit=1)

            clean_lines.append((self.current_address, line))
            mnemonic = tokens[0].upper()

            m_base = mnemonic
            m_width_str = 'W'
            if '.' in mnemonic:
                parts = mnemonic.split('.')
                if len(parts) == 2 and parts[1] in ['W', 'H', 'F', 'B']:
                    m_base = parts[0]
                    m_width_str = parts[1]

            if m_base == 'ALIGN':
                align_val = int(tokens[1]) if len(tokens) > 1 else 8
                rem = self.current_address % align_val
                if rem != 0: self.current_address += (align_val - rem)
                continue

            if m_base == 'IWORD':
                self.current_address += 8
                continue

            if m_base == 'RES' or m_base in self.res_ops:
                try: count = int(tokens[1], 0) if len(tokens) > 1 else 1
                except ValueError: count = self.labels.get(tokens[1].strip(), 1) if len(tokens) > 1 else 1

                if m_base == 'RES':
                    multiplier = {'B': 1, 'F': 2, 'H': 4, 'W': 8}.get(m_width_str, 8)
                else:
                    multiplier = {'RESB': 1, 'RESF': 2, 'RESH': 4, 'RESW': 8}.get(m_base, 8)
                self.current_address += count * multiplier
                continue

            # Fallback: If not recognized as an opcode, process entire line as a data array
            if m_base not in self.opcodes and m_base not in self.special_ops:
                raw_val = line
                for part in re.split(r',\s*(?=(?:[^"]*"[^"]*")*[^"]*$)', raw_val):
                    part = part.strip()
                    if not part: continue
                    if '"' in part:
                        match = re.search(r'([whfbWHFB]?)"(.*)"', part)
                        if match:
                            prefix = match.group(1).lower()
                            s_content = match.group(2).replace('\\n', '\n').replace('\\r', '\r').replace('\\t', '\t').replace('\\0', '\x00')
                            word_size = 1
                            if prefix == 'w': word_size = 8
                            elif prefix == 'h': word_size = 4
                            elif prefix == 'f': word_size = 2
                            self.current_address += len(s_content) * word_size
                    else:
                        pfx = part[0].lower() if part and part[0].lower() in 'whfb' else 'w'
                        if pfx == 'b': self.current_address += 1
                        elif pfx == 'f': self.current_address += 2
                        elif pfx == 'h': self.current_address += 4
                        else: self.current_address += 8
                continue

            self.current_address += 8

        # PASS 2: Generation
        binary_output = bytearray()
        print(f"Assembling {infile}...")
        for addr, line in clean_lines:
            tokens = re.split(r'\s+', line, maxsplit=1)
            mnemonic = tokens[0].upper()
            args = tokens[1] if len(tokens) > 1 else ""

            m_base = mnemonic
            m_width_str = 'W'
            if '.' in mnemonic:
                parts = mnemonic.split('.')
                if len(parts) == 2 and parts[1] in ['W', 'H', 'F', 'B']:
                    m_base = parts[0]
                    m_width_str = parts[1]

            if m_base == 'RET':
                m_base = 'POPJ'
                args = 'A255, 0'
            elif m_base == 'SET':
                m_base = 'JAS'
                if not args: args = '0, 1(r)'
                elif ',' not in args: args += ', 1(r)'

            if m_base == 'ALIGN':
                align_val = int(args) if args else 8
                rem = len(binary_output) % align_val
                if rem != 0: binary_output.extend(b'\x00' * (align_val - rem))
                continue

            if m_base == 'IWORD':
                arg_list = [a.strip() for a in args.split(',')]
                r1 = self.parse_reg(arg_list[0]) if len(arg_list) > 0 else 0
                r2 = self.parse_reg(arg_list[1]) if len(arg_list) > 1 else 0
                addr_str = arg_list[2] if len(arg_list) > 2 else "0"
                try: target_addr = int(addr_str, 0)
                except ValueError: target_addr = self.get_label(addr_str, addr)

                iw = (r1 << 56) | (r2 << 48) | (target_addr & 0xFFFFFFFFFF)
                binary_output.extend(struct.pack('<Q', iw))
                if verbose: print(f"  {addr:04X}: {mnemonic} {args} -> {iw:016X}")
                continue

            if m_base == 'RES' or m_base in self.res_ops:
                try: count = int(args, 0) if args else 1
                except ValueError: count = self.get_label(args.strip(), addr) if args else 1

                if m_base == 'RES':
                    multiplier = {'B': 1, 'F': 2, 'H': 4, 'W': 8}.get(m_width_str, 8)
                else:
                    multiplier = {'RESB': 1, 'RESF': 2, 'RESH': 4, 'RESW': 8}.get(m_base, 8)

                binary_output.extend(b'\x00' * (count * multiplier))
                if verbose: print(f"  {addr:04X}: {mnemonic} {args} -> [{count * multiplier} bytes reserved]")
                continue

            # Fallback: Process pure data directly!
            if m_base not in self.opcodes and m_base not in self.special_ops:
                raw_val = line
                for part in re.split(r',\s*(?=(?:[^"]*"[^"]*")*[^"]*$)', raw_val):
                    part = part.strip()
                    if not part: continue
                    if '"' in part:
                        match = re.search(r'([whfbWHFB]?)"(.*)"', part)
                        if match:
                            prefix = match.group(1).lower()
                            string_content = match.group(2).replace('\\n', '\n').replace('\\r', '\r').replace('\\t', '\t').replace('\\0', '\x00')
                            word_size = 1
                            if prefix == 'w': word_size = 8
                            elif prefix == 'h': word_size = 4
                            elif prefix == 'f': word_size = 2

                            for char in string_content:
                                val = ord(char)
                                if word_size == 1: binary_output.append(val & 0xFF)
                                elif word_size == 2: binary_output.extend(struct.pack('<H', val & 0xFFFF))
                                elif word_size == 4: binary_output.extend(struct.pack('<I', val & 0xFFFFFFFF))
                                elif word_size == 8: binary_output.extend(struct.pack('<Q', val))
                    else:
                        prefix = part[0].lower() if part and part[0].lower() in 'whfb' else 'w'
                        val_str = part[1:] if part and part[0].lower() in 'whfb' else part

                        is_float = False
                        val = 0
                        try:
                            if '.' in val_str or 'e' in val_str.lower():
                                val = float(val_str)
                                is_float = True
                            else:
                                val = int(val_str, 0)
                        except ValueError:
                            val = self.get_label(val_str, addr)

                        if is_float:
                            if prefix == 'b': binary_output.append(pack_f8(val) & 0xFF)
                            elif prefix == 'f': binary_output.extend(struct.pack('<e', val))
                            elif prefix == 'h': binary_output.extend(struct.pack('<f', val))
                            else: binary_output.extend(struct.pack('<d', val))
                        else:
                            if prefix == 'b': binary_output.append(val & 0xFF)
                            elif prefix == 'f': binary_output.extend(struct.pack('<H', val & 0xFFFF))
                            elif prefix == 'h': binary_output.extend(struct.pack('<I', val & 0xFFFFFFFF))
                            else: binary_output.extend(struct.pack('<Q', val & 0xFFFFFFFFFFFFFFFF))
                continue

            width = 0
            if m_base.endswith('HW'): width = 1; m_base = m_base[:-2]
            elif m_base.endswith('FW'): width = 2; m_base = m_base[:-2]
            elif m_base.endswith('B'): width = 3; m_base = m_base[:-1]

            if m_width_str == 'H': width = 1
            elif m_width_str == 'F': width = 2
            elif m_width_str == 'B': width = 3

            if m_base in self.opcodes:
                op = self.opcodes[m_base]
                arg_list = [a.strip() for a in args.split(',')]

                if m_base in ['JIC', 'JAS', 'JAC', 'JCC', 'JISC']:
                    st_flags = {'OVF': 1, 'OS1': 2, 'OS2': 4, 'OS3': 8, 'FPE': 16, 'PRIV': 32}
                    flag_str = arg_list[0].upper() if len(arg_list) > 0 else "0"

                    if flag_str in st_flags:
                        reg = st_flags[flag_str]
                    else:
                        try:
                            # Safely parse naked 8-bit binary strings (e.g. 00000010)
                            if set(flag_str) <= {'0', '1'} and len(flag_str) == 8:
                                reg = int(flag_str, 2) & 0xFF
                            else:
                                reg = int(flag_str, 0) & 0xFF
                        except ValueError:
                            reg = 0
                    mem_part = arg_list[1] if len(arg_list) > 1 else "0"

                elif m_base in ['PUSH', 'POP', 'PUSHJ', 'POPJ'] and len(arg_list) == 1:
                    reg = 255
                    mem_part = arg_list[0]
                elif len(arg_list) == 1:
                    reg = 0
                    mem_part = arg_list[0]
                else:
                    reg = self.parse_reg(arg_list[0]) if arg_list else 0
                    mem_part = arg_list[1] if len(arg_list) > 1 else "0"

                off, idx, pcr, mod = self.parse_mem(mem_part)
                if isinstance(off, str): off = self.get_label(off, addr)

                instr = (op & 0x3FF) << 54
                instr |= (reg & 0xFF) << 46
                instr |= (idx & 0xFF) << 37
                instr |= (width & 0x3) << 35
                instr |= (pcr & 0x1) << 34
                instr |= (mod & 0x3) << 32
                instr |= (off & 0xFFFFFFFF)
                binary_output.extend(struct.pack('<Q', instr))
                if verbose: print(f"  {addr:04X}: {mnemonic} -> {instr:016X}")

            elif m_base in self.special_ops:
                arg_list = [a.strip() for a in args.split(',')]
                header = 0x3F << 58

                if m_base in ['TRAP', 'TRET']:
                    reg = self.parse_reg(arg_list[0]) if len(arg_list) > 0 else 255
                    t = 0 if m_base == 'TRAP' else 1
                    imm8 = 0
                    if m_base == 'TRAP' and len(arg_list) > 1:
                        imm_str = arg_list[1]
                        try: imm8 = int(imm_str, 0) & 0xFF
                        except ValueError: imm8 = self.get_label(imm_str, addr) & 0xFF
                    instr = (65 << 54) | (reg << 46) | (t << 45) | (imm8)
                    binary_output.extend(struct.pack('<Q', instr))
                    if verbose: print(f"  {addr:04X}: {mnemonic} -> {instr:016X}")

                elif m_base == 'ADI':
                    reg_part = arg_list[0].split()
                    reg = self.parse_reg(reg_part[0])
                    h = 1 if len(reg_part) > 1 and reg_part[1].upper() == 'H' else 0
                    imm_str = arg_list[1] if len(arg_list) > 1 else "0"
                    imm32 = self.parse_value(imm_str, addr)
                    instr = (66 << 54) | (reg << 46) | (h << 45) | (imm32 & 0xFFFFFFFF)
                    binary_output.extend(struct.pack('<Q', instr))
                    if verbose: print(f"  {addr:04X}: {mnemonic} -> {instr:016X}")

                elif m_base == 'LDI':
                    reg_part = arg_list[0].split()
                    reg = self.parse_reg(reg_part[0])
                    mode_str = reg_part[1].upper() if len(reg_part) > 1 else 'L'
                    mode = 0 if mode_str == 'L' else 1 if mode_str == 'H' else 2 if mode_str == 'B' else 3

                    imm_str = arg_list[1] if len(arg_list) > 1 else "0"
                    imm32 = self.parse_value(imm_str, addr)

                    instr = (64 << 54) | (reg << 46) | (mode << 44) | (imm32 & 0xFFFFFFFF)
                    binary_output.extend(struct.pack('<Q', instr))
                    if verbose: print(f"  {addr:04X}: {mnemonic} -> {instr:016X}")

                elif m_base in ['LFS', 'LSA']:
                    if m_base == 'LFS':
                        sp_reg = self.parse_special_reg(arg_list[0]) if len(arg_list) > 0 else 0
                        a_reg = self.parse_reg(arg_list[1]) if len(arg_list) > 1 else 0
                        op = 1
                        instr = header | (0x00 << 50) | (op << 42) | (sp_reg << 34) | (a_reg << 26)
                    else:
                        a_reg = self.parse_reg(arg_list[0]) if len(arg_list) > 0 else 0
                        sp_reg = self.parse_special_reg(arg_list[1]) if len(arg_list) > 1 else 0
                        op = 2
                        instr = header | (0x00 << 50) | (op << 42) | (a_reg << 34) | (sp_reg << 26)
                    binary_output.extend(struct.pack('<Q', instr))
                    if verbose: print(f"  {addr:04X}: {mnemonic} -> {instr:016X}")

                elif m_base == 'LSP':
                    reg_part = arg_list[0].split()
                    sp_reg = self.parse_special_reg(reg_part[0])
                    mode_str = reg_part[1].upper() if len(reg_part) > 1 else 'L'
                    mode = 0 if mode_str == 'L' else 1 if mode_str == 'H' else 2 if mode_str == 'B' else 3

                    imm_str = arg_list[1] if len(arg_list) > 1 else "0"
                    imm32 = self.parse_value(imm_str, addr)

                    op = 0
                    instr = header | (0x00 << 50) | (op << 42) | (sp_reg << 34) | (mode << 32) | (imm32 & 0xFFFFFFFF)
                    binary_output.extend(struct.pack('<Q', instr))
                    if verbose: print(f"  {addr:04X}: {mnemonic} -> {instr:016X}")

                elif m_base == 'PRINTI':
                    term_str = arg_list[0] if arg_list and arg_list[0] else "0"
                    i_sel = 0
                    if term_str.upper().startswith('A'):
                        i_sel = 1
                        term = self.parse_reg(term_str)
                    else:
                        try: term = int(term_str, 0) & 0xF
                        except ValueError: term = 0

                    content_part = args.split(',', 1)[1].strip() if ',' in args else '""'
                    if '"' in content_part:
                        content = content_part.split('"')[1].replace('\\n', '\n').replace('\\r', '\r').replace('\\t', '\t').replace('\\0', '\x00')[:5]
                    else: content = ""

                    char1 = ord(content[0]) if len(content) > 0 else 0
                    str_val = 0
                    for i in range(1, 5):
                        if i < len(content): str_val |= (ord(content[i]) << (32 - i*8))

                    dev = 0x02
                    op = 2
                    instr = header | (dev << 50) | (op << 46) | (term << 42) | (0 << 41) | (i_sel << 40) | ((char1 & 0xFF) << 32) | (str_val & 0xFFFFFFFF)
                    binary_output.extend(struct.pack('<Q', instr))
                    if verbose: print(f"  {addr:04X}: {mnemonic} -> {instr:016X}")

                elif m_base in ['PRINTS', 'INPUT', 'TSTAT']:
                    term_str = arg_list[0] if arg_list and arg_list[0] else "0"
                    i_sel = 0
                    if term_str.upper().startswith('A'):
                        i_sel = 1
                        term = self.parse_reg(term_str)
                    else:
                        try: term = int(term_str, 0) & 0xF
                        except ValueError: term = 0

                    mem_part = arg_list[1] if len(arg_list) > 1 else "0"
                    off, idx, pcr, mod = self.parse_mem(mem_part)
                    if isinstance(off, str): off = self.get_label(off, addr)

                    op = 0 if m_base == 'PRINTS' else 1 if m_base == 'INPUT' else 3
                    dev = 0x02
                    instr = header | (dev << 50) | (op << 46) | (term << 42) | ((pcr & 1) << 41) | (i_sel << 40) | ((idx & 0xFF) << 32) | (off & 0xFFFFFFFF)
                    binary_output.extend(struct.pack('<Q', instr))
                    if verbose: print(f"  {addr:04X}: {mnemonic} -> {instr:016X}")

                elif m_base in ['ITOA', 'ATOI', 'FTOA', 'ATOF', 'FTOS']:
                    src = self.parse_reg(arg_list[0]) if len(arg_list) > 0 else 0
                    dst = self.parse_reg(arg_list[1]) if len(arg_list) > 1 else 0

                    op = 0 if m_base == 'ITOA' else 1 if m_base == 'ATOI' else 2 if m_base in ['FTOA', 'FTOS'] else 3
                    dev = 0x03
                    instr = header | (dev << 50) | (op << 42) | (src << 34) | (dst << 26) | ((width & 3) << 24)
                    binary_output.extend(struct.pack('<Q', instr))
                    if verbose: print(f"  {addr:04X}: {mnemonic} -> {instr:016X}")

                elif m_base in ['TREAD', 'TWRITE']:
                    tape = int(arg_list[0], 0) & 0x7 if len(arg_list) > 0 else 0
                    acc_str = arg_list[1].strip() if len(arg_list) > 1 else "A0"
                    ind = 0
                    if acc_str.startswith('(') and acc_str.endswith(')'):
                        ind = 1
                        acc_str = acc_str[1:-1]
                    acc = self.parse_reg(acc_str)

                    mem_part = arg_list[2] if len(arg_list) > 2 else "0"
                    off, idx, pcr, mod = self.parse_mem(mem_part)
                    if isinstance(off, str): off = self.get_label(off, addr)

                    op = 0 if m_base == 'TWRITE' else 1
                    dev = 0x04
                    instr = header | (dev << 50) | (op << 42) | (ind << 41) | (tape << 38) | (acc << 30) | ((width & 3) << 28) | ((idx & 0xFF) << 20) | (off & 0xFFFFF)
                    binary_output.extend(struct.pack('<Q', instr))
                    if verbose: print(f"  {addr:04X}: {mnemonic} -> {instr:016X}")

        if not binary_output:
            print("Warning: No instructions generated.")
            return

        while len(binary_output) % 8 != 0: binary_output.append(0)

        with open(outfile, 'wb') as f:
            f.write(binary_output)
        print(f"Success: {outfile} created ({len(binary_output)} bytes).")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python assemble.py <infile> [-o <outfile>] [-v]")
    else:
        args = sys.argv[1:]
        verbose = False

        if "-v" in args:
            verbose = True
            args.remove("-v")

        if len(args) == 0:
            print("Usage: python assemble.py <infile> [-o <outfile>] [-v]")
            sys.exit(1)

        infile = args[0]
        out = "out.bin"

        if "-o" in args:
            idx = args.index("-o")
            if idx + 1 < len(args):
                out = args[idx + 1]

        XDP64Assembler().assemble(infile, out, verbose=verbose)
