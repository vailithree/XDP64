import sys
import re
import struct
import math

def pack_f8(d):
    if math.isnan(d): return 0x79
    sign = 1 if math.copysign(1.0, d) < 0.0 else 0
    d = abs(d)

    if d == float('inf'):
        return (sign << 7) | 0x78
    if d == 0.0:
        return (sign << 7)

    mant, exp = math.frexp(d)
    mant *= 2.0
    exp -= 1

    stored_exp = exp + 7
    if stored_exp >= 0xF:
        return (sign << 7) | 0x78

    if stored_exp <= 0:
        mant = d / 0.015625
        m = int(mant * 8.0 + 0.5)
        if m >= 8:
            return (sign << 7) | (1 << 3) | 0
        return (sign << 7) | m

    m = int((mant - 1.0) * 8.0 + 0.5)
    if m >= 8:
        m = 0
        stored_exp += 1
        if stored_exp >= 0xF:
            return (sign << 7) | 0x78

    return (sign << 7) | (stored_exp << 3) | m

class XDP64Assembler:
    def __init__(self):
        self.labels = {}
        self.sym_defs = {}
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
            'JAC': 67, 'JCC': 68, 'JISC': 69,

            'SIN': 70, 'COS': 71, 'TAN': 72, 'SQRT': 73, 'MOD': 74, 'FMOD': 75,
            'FLOOR': 76, 'CEIL': 77, 'CUBE': 78, 'SQ': 79, 'FCUB': 80, 'FSQ': 81,
            'FINC': 82, 'FDEC': 83, 'MAX': 84, 'FMAX': 85, 'MIN': 86, 'FMIN': 87,

            'REP': 88, 'BCOPY': 89, 'BSET': 90,
            'POPCNT': 91, 'CLZ': 92, 'CTZ': 93, 'BSTR': 94
        }

        self.op3_ops = {
            'TADD': 0, 'TSUB': 1, 'TMUL': 2, 'TDIV': 3,
            'TFAD': 4, 'TFSB': 5, 'TFML': 6, 'TFDV': 7,
            'TXP': 8, 'TFXP': 9
        }

        self.simd_ops = {
            'VFAD': 0, 'VFSB': 1, 'VFML': 2, 'VFDV': 3, 'VADD': 4, 'VSUB': 5,
            'VDOT': 6, 'VFDOT': 7, 'VLRP': 8, 'VFLRP': 9, 'VFMAX': 10, 'VMAX': 11,
            'VFMIN': 12, 'VMIN': 13, 'VAND': 14, 'VOR': 15, 'VXOR': 16, 'VNOT': 17,
            'VCEQ': 18, 'VCGT': 19, 'VCLT': 20, 'VBRD': 21, 'VSHF': 22, 'VPACK': 23
        }

        self.special_ops = [
            'PRINTS', 'INPUT', 'PRINTI', 'TSTAT', 'ITOA', 'ATOI', 'FTOA', 'ATOF', 'FTOS',
            'TWRITE', 'TREAD', 'LFS', 'LSA', 'TRAP', 'TRET', 'LDI', 'LSP', 'ADI',
            'ERET', 'EFLSH', 'ESTCK', 'READ', 'WRITE', 'ENMMU', 'DMMU', 'INVPG', 'SPSP',
            'VBASE', 'VMODE', 'VFLIP', 'VSTAT', 'WAIT', 'BRTL', 'BRTR', 'CAS', 'BBRTL', 'BBRTR'
        ] + list(self.op3_ops.keys()) + list(self.simd_ops.keys())

        self.res_ops = ['RESW', 'RESH', 'RESF', 'RESB']

    def eval_expr(self, expr, addr):
        if not expr:
            return None
        expr = expr.replace('$', str(addr))
        tokens = re.split(r'([^a-zA-Z0-9_.]+)', expr)

        for i, tok in enumerate(tokens):
            if not tok or not re.match(r'^[a-zA-Z_.]', tok):
                continue
            if re.match(r'^A\d+$', tok, re.I):
                continue
            if tok in self.labels:
                tokens[i] = str(self.labels[tok])
            else:
                return None

        parsed_expr = ''.join(tokens)
        try:
            parsed_expr = parsed_expr.replace('/', '//')
            return int(eval(parsed_expr))
        except Exception:
            return None

    def parse_reg(self, reg_str):
        if not reg_str:
            return 0
        match = re.search(r'A(\d+)', reg_str, re.I)
        return int(match.group(1)) if match else 0

    def parse_special_reg(self, name):
        name = name.strip().upper()
        mapping = {
            'BASE': 0, 'TTB': 1, 'ETB': 2, 'VIB': 3,
            'EXCLK': 4, 'CTCLK': 5, 'TST': 6, 'CTCLKI': 7, 'CRB': 8,
            'UBT': 9, 'KBT': 10, 'UKS': 11, 'CURAPP': 12
        }
        if name in mapping:
            return mapping[name]
        try:
            return int(name, 0) & 0xFF
        except ValueError:
            return 0

    def parse_mem(self, mem_str, addr):
        offset, index, pc_rel, mode = 0, 0, 0, 0

        if re.search(r',\s*r\)', mem_str, re.I):
            pc_rel = 1
            mem_str = re.sub(r',\s*r\)', ')', mem_str, flags=re.I)
        elif '(r)' in mem_str.lower() or '(R)' in mem_str:
            pc_rel = 1
            mem_str = mem_str.replace('(r)', '').replace('(R)', '')

        match = re.search(r'\((.*?)\)', mem_str)
        if match:
            inner = match.group(1).strip()
            if inner.endswith('+'):
                mode, index = 1, self.parse_reg(inner[:-1])
            elif inner.startswith('-'):
                mode, index = 2, self.parse_reg(inner[1:])
            else:
                index = self.parse_reg(inner)
            mem_str = re.sub(r'\(.*?\)', '', mem_str).strip()

        if mem_str:
            m_reg = re.match(r'^A(\d+)$', mem_str, re.I)
            if m_reg:
                offset = int(m_reg.group(1)) * 8
            else:
                try:
                    offset = int(mem_str, 0)
                except ValueError:
                    v = self.eval_expr(mem_str, addr)
                    offset = v if v is not None else self.get_label(mem_str, addr)

        return offset, index, pc_rel, mode

    def get_label(self, name, addr):
        if name in self.labels:
            return self.labels[name]
        print(f"Assembler Error: Undefined label/symbol '{name}' referenced at address {addr:04X}")
        sys.exit(1)

    def parse_value(self, raw_str, addr):
        raw_str = raw_str.strip()
        prefix = 'w'
        val_str = raw_str

        if raw_str and raw_str[0].lower() in 'whfb':
            if len(raw_str) > 1 and (raw_str[1] == '"' or raw_str[1] in '0123456789$-+('):
                prefix = raw_str[0].lower()
                val_str = raw_str[1:]
            elif len(raw_str) > 1 and raw_str[1] == ' ':
                prefix = raw_str[0].lower()
                val_str = raw_str[1:].strip()

        is_float = False
        val = 0
        try:
            if '.' in val_str and re.match(r'^-?\d+\.\d+$', val_str):
                val = float(val_str)
                is_float = True
            else:
                val = int(val_str, 0)
        except ValueError:
            v = self.eval_expr(val_str, addr)
            if v is not None:
                val = v
            else:
                val = self.get_label(val_str, addr)

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

        self.current_address = 0
        clean_lines = []

        # --- PASS 1: Label, ORG, and SYM Resolution ---
        for line in lines:
            line = line.split(';')[0].strip()
            if not line:
                continue

            tokens = re.split(r'\s+', line, maxsplit=1)

            label_match = re.match(r'^([A-Za-z_.][A-Za-z0-9_.$]*),$', tokens[0])
            if label_match:
                lbl = label_match.group(1)
                self.labels[lbl] = self.current_address
                if len(tokens) == 1:
                    continue
                line = tokens[1].strip()
                if not line:
                    continue
                tokens = re.split(r'\s+', line, maxsplit=1)

            is_szi = False
            if tokens[0].upper() == 'SZI':
                is_szi = True
                if len(tokens) > 1:
                    line = tokens[1].strip()
                    tokens = re.split(r'\s+', line, maxsplit=1)
                else:
                    continue

            clean_lines.append((self.current_address, line, is_szi))
            mnemonic = tokens[0].upper()

            m_base = mnemonic
            m_width_str = 'W'
            if '.' in mnemonic:
                parts = mnemonic.split('.')
                if len(parts) == 2 and parts[1] in ['W', 'H', 'F', 'B']:
                    m_base = parts[0]
                    m_width_str = parts[1]

            if m_base == 'ORG':
                try:
                    self.current_address = int(tokens[1], 0)
                except ValueError:
                    self.current_address = self.labels.get(tokens[1].strip(), 0)
                continue

            if m_base == 'SYM':
                if len(tokens) > 1:
                    parts = tokens[1].split(None, 1)
                    if len(parts) == 2:
                        sym_name, sym_expr = parts[0].strip(), parts[1].strip()
                        self.sym_defs[sym_name] = (sym_expr, self.current_address)
                continue

            if m_base == 'ALIGN':
                align_val = int(tokens[1]) if len(tokens) > 1 else 8
                rem = self.current_address % align_val
                if rem != 0:
                    self.current_address += (align_val - rem)
                continue

            if m_base == 'IWORD':
                self.current_address += 8
                continue

            if m_base == 'RES' or m_base in self.res_ops:
                args = tokens[1] if len(tokens) > 1 else ""
                try:
                    count = int(args, 0) if args else 1
                except ValueError:
                    v = self.eval_expr(args.strip(), self.current_address)
                    count = v if v is not None else self.labels.get(args.strip(), 1)

                if m_base == 'RES':
                    multiplier = {'B': 1, 'F': 2, 'H': 4, 'W': 8}.get(m_width_str, 8)
                else:
                    multiplier = {'RESB': 1, 'RESF': 2, 'RESH': 4, 'RESW': 8}.get(m_base, 8)

                self.current_address += count * multiplier
                continue

            if m_base not in self.opcodes and m_base not in self.special_ops and m_base not in ['RET', 'SET']:
                raw_val = line
                for part in re.split(r',\s*(?=(?:[^"]*"[^"]*")*[^"]*$)', raw_val):
                    part = part.strip()
                    if not part:
                        continue
                    if '"' in part:
                        match = re.search(r'([whfbWHFB]?)"(.*)"', part)
                        if match:
                            prefix = match.group(1).lower()
                            s_content = match.group(2).replace('\\n', '\n').replace('\\0', '\x00')
                            word_size = 1
                            if prefix == 'w': word_size = 8
                            elif prefix == 'h': word_size = 4
                            elif prefix == 'f': word_size = 2
                            self.current_address += len(s_content) * word_size
                    else:
                        pfx = part[0].lower() if part and part[0].lower() in 'whfb' and (len(part)>1 and part[1] in '0123456789$-+("') else 'w'
                        if pfx == 'b': self.current_address += 1
                        elif pfx == 'f': self.current_address += 2
                        elif pfx == 'h': self.current_address += 4
                        else: self.current_address += 8
                continue

            self.current_address += 8

        # --- Resolve Dependent Symbols ---
        changed = True
        while changed:
            changed = False
            for name, (expr, addr) in list(self.sym_defs.items()):
                val = self.eval_expr(expr, addr)
                if val is not None:
                    self.labels[name] = val
                    changed = True
                    del self.sym_defs[name]

        if self.sym_defs:
            print("Assembler Warning: Unresolvable SYM directives detected.")

        binary_output = bytearray()
        print(f"Assembling {infile}...")

        # --- PASS 2: Binary Generation ---
        for addr, line, is_szi in clean_lines:
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

            if m_base == 'SYM':
                continue

            if m_base == 'RET':
                m_base = 'POPJ'
                args = 'A255, 0'
            elif m_base == 'SET':
                m_base = 'JAS'
                if not args:
                    args = '0, 1(r)'
                elif ',' not in args:
                    args += ', 1(r)'

            if m_base == 'ORG':
                try:
                    target = int(args, 0) if args else 0
                except ValueError:
                    v = self.eval_expr(args.strip(), addr)
                    target = v if v is not None else self.labels.get(args.strip(), 0)

                if target > len(binary_output):
                    binary_output.extend(b'\x00' * (target - len(binary_output)))
                continue

            if m_base == 'ALIGN':
                align_val = int(args) if args else 8
                rem = len(binary_output) % align_val
                if rem != 0:
                    binary_output.extend(b'\x00' * (align_val - rem))
                continue

            if m_base == 'IWORD':
                arg_list = [a.strip() for a in args.split(',')]
                r1, r2, addr_str = 0, 0, "0"
                if len(arg_list) == 1:
                    addr_str = arg_list[0]
                elif len(arg_list) == 2:
                    r1 = self.parse_reg(arg_list[0])
                    addr_str = arg_list[1]
                elif len(arg_list) >= 3:
                    r1 = self.parse_reg(arg_list[0])
                    r2 = self.parse_reg(arg_list[1])
                    addr_str = arg_list[2]

                try:
                    target_addr = int(addr_str, 0)
                except ValueError:
                    v = self.eval_expr(addr_str, addr)
                    target_addr = v if v is not None else self.get_label(addr_str, addr)

                iw = (r1 << 56) | (r2 << 48) | (target_addr & 0xFFFFFFFFFF)
                binary_output.extend(struct.pack('<Q', iw))
                if verbose: print(f"  {addr:04X}: {mnemonic} {args} -> {iw:016X}")
                continue

            if m_base == 'RES' or m_base in self.res_ops:
                try:
                    count = int(args, 0) if args else 1
                except ValueError:
                    v = self.eval_expr(args.strip(), addr)
                    count = v if v is not None else self.get_label(args.strip(), addr)

                if m_base == 'RES':
                    multiplier = {'B': 1, 'F': 2, 'H': 4, 'W': 8}.get(m_width_str, 8)
                else:
                    multiplier = {'RESB': 1, 'RESF': 2, 'RESH': 4, 'RESW': 8}.get(m_base, 8)

                binary_output.extend(b'\x00' * (count * multiplier))
                if verbose: print(f"  {addr:04X}: {mnemonic} {args} -> [{count * multiplier} bytes reserved]")
                continue

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
                        val = self.parse_value(part, addr)
                        prefix = 'w'
                        if part and part[0].lower() in 'whfb' and (len(part)>1 and part[1] in '0123456789$-+("'):
                            prefix = part[0].lower()

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
                            if set(flag_str) <= {'0', '1'} and len(flag_str) == 8:
                                reg = int(flag_str, 2) & 0xFF
                            else:
                                v = self.eval_expr(flag_str, addr)
                                reg = v if v is not None else int(flag_str, 0) & 0xFF
                        except ValueError:
                            reg = 0
                    mem_part = arg_list[1] if len(arg_list) > 1 else "0"

                elif m_base == 'REP':
                    r_str = arg_list[0].strip()
                    a_str = arg_list[1].strip()
                    i_flag = 1 if r_str.startswith('#') else 0

                    if i_flag:
                        v1 = self.eval_expr(r_str[1:], addr)
                        r_val = v1 if v1 is not None else int(r_str[1:], 0)
                    else:
                        r_val = self.parse_reg(r_str)

                    f_flag = 1 if a_str.startswith('#') else 0
                    if f_flag:
                        v2 = self.eval_expr(a_str[1:], addr)
                        a_val = v2 if v2 is not None else int(a_str[1:], 0)
                    else:
                        a_val = self.parse_reg(a_str)

                    instr = (op << 54) | ((r_val & 0xFF) << 46) | (i_flag << 45) | ((a_val & 0xFF) << 37) | (f_flag << 36)
                    binary_output.extend(struct.pack('<Q', instr))
                    if verbose: print(f"  {addr:04X}: {mnemonic} -> {instr:016X}")
                    continue

                elif m_base in ['BCOPY', 'BSTR']:
                    a_reg = self.parse_reg(arg_list[0])
                    b_reg = self.parse_reg(arg_list[1])
                    c_str = arg_list[2].strip()
                    i_flag = 1 if c_str.startswith('#') else 0

                    if i_flag:
                        v = self.eval_expr(c_str[1:], addr)
                        c_val = v if v is not None else int(c_str[1:], 0)
                    else:
                        c_val = self.parse_reg(c_str)

                    instr = (op << 54) | (width << 52) | ((a_reg & 0xFF) << 44) | ((b_reg & 0xFF) << 36) | ((c_val & 0xFF) << 28) | (i_flag << 27)
                    binary_output.extend(struct.pack('<Q', instr))
                    if verbose: print(f"  {addr:04X}: {mnemonic} -> {instr:016X}")
                    continue

                elif m_base == 'BSET':
                    a_str = arg_list[0].strip()
                    v_a = self.eval_expr(a_str, addr)
                    a_val = v_a if v_a is not None else int(a_str, 0) & 0xFF

                    b_reg = self.parse_reg(arg_list[1])
                    c_str = arg_list[2].strip()
                    i_flag = 1 if c_str.startswith('#') else 0

                    if i_flag:
                        v_c = self.eval_expr(c_str[1:], addr)
                        c_val = v_c if v_c is not None else int(c_str[1:], 0)
                    else:
                        c_val = self.parse_reg(c_str)

                    instr = (op << 54) | (a_val << 46) | ((b_reg & 0xFF) << 38) | ((c_val & 0xFF) << 30) | (i_flag << 29)
                    binary_output.extend(struct.pack('<Q', instr))
                    if verbose: print(f"  {addr:04X}: {mnemonic} -> {instr:016X}")
                    continue

                elif m_base in ['PUSH', 'POP', 'PUSHJ', 'POPJ'] and len(arg_list) == 1:
                    reg = 255
                    mem_part = arg_list[0]
                elif len(arg_list) == 1:
                    reg = 0
                    mem_part = arg_list[0]
                else:
                    reg = self.parse_reg(arg_list[0]) if arg_list else 0
                    mem_part = arg_list[1] if len(arg_list) > 1 else "0"

                off, idx, pcr, mod = self.parse_mem(mem_part, addr)
                if is_szi:
                    mod = 3

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

                # ----------------------------------------------------
                # 3OPMATH Implementation
                # ----------------------------------------------------
                if m_base in self.op3_ops:
                    op3 = self.op3_ops[m_base]
                    a_reg = self.parse_reg(arg_list[0]) if len(arg_list) > 0 else 0
                    b_reg = self.parse_reg(arg_list[1]) if len(arg_list) > 1 else 0
                    c_reg = self.parse_reg(arg_list[2]) if len(arg_list) > 2 else 0
                    d_reg = self.parse_reg(arg_list[3]) if len(arg_list) > 3 else 0

                    # [0001011111][ooooo][ww][aaaaaaaa][bbbbbbbb][cccccccc][dddddddd]
                    instr = (95 << 54) | (op3 << 49) | ((width & 3) << 47) | (a_reg << 39) | (b_reg << 31) | (c_reg << 23) | (d_reg << 15)
                    binary_output.extend(struct.pack('<Q', instr))
                    if verbose: print(f"  {addr:04X}: {mnemonic} -> {instr:016X}")

                # ----------------------------------------------------
                # SIMD Implementation
                # ----------------------------------------------------
                elif m_base in self.simd_ops:
                    sop = self.simd_ops[m_base]

                    arg_a = arg_list[0].strip() if len(arg_list) > 0 else "A0"
                    ia = 1 if arg_a.startswith('(') and arg_a.endswith(')') else 0
                    a_reg = self.parse_reg(arg_a[1:-1] if ia else arg_a)

                    arg_b = arg_list[1].strip() if len(arg_list) > 1 else "A0"
                    ib = 1 if arg_b.startswith('(') and arg_b.endswith(')') else 0
                    b_reg = self.parse_reg(arg_b[1:-1] if ib else arg_b)

                    arg_c = arg_list[2].strip() if len(arg_list) > 2 else "A0"
                    ic = 1 if arg_c.startswith('(') and arg_c.endswith(')') else 0
                    c_reg = self.parse_reg(arg_c[1:-1] if ic else arg_c)

                    iii = (ia << 2) | (ib << 1) | ic

                    # [0001100000][oooooo][ww][aaaaaaaa][bbbbbbbb][cccccccc][iii]
                    instr = (96 << 54) | (sop << 48) | ((width & 3) << 46) | (a_reg << 38) | (b_reg << 30) | (c_reg << 22) | (iii << 19)
                    binary_output.extend(struct.pack('<Q', instr))
                    if verbose: print(f"  {addr:04X}: {mnemonic} -> {instr:016X}")

                elif m_base in ['ENMMU', 'DMMU', 'INVPG']:
                    op = 0 if m_base == 'ENMMU' else 1 if m_base == 'DMMU' else 2
                    dev = 0x01
                    instr = header | (dev << 50) | (op << 42)
                    binary_output.extend(struct.pack('<Q', instr))
                    if verbose: print(f"  {addr:04X}: {mnemonic} -> {instr:016X}")

                elif m_base == 'ESTCK':
                    dev = 0x00
                    op = 5
                    reg = self.parse_reg(arg_list[0]) if len(arg_list) > 0 else 0
                    instr = header | (dev << 50) | (op << 42) | (reg << 34)
                    binary_output.extend(struct.pack('<Q', instr))
                    if verbose: print(f"  {addr:04X}: {mnemonic} -> {instr:016X}")

                elif m_base in ['TRAP', 'TRET']:
                    reg = self.parse_reg(arg_list[0]) if len(arg_list) > 0 else 255
                    t = 0 if m_base == 'TRAP' else 1
                    imm8 = 0
                    if m_base == 'TRAP' and len(arg_list) > 1:
                        imm_str = arg_list[1]
                        try:
                            imm8 = int(imm_str, 0) & 0xFF
                        except ValueError:
                            v = self.eval_expr(imm_str, addr)
                            imm8 = v if v is not None else self.get_label(imm_str, addr) & 0xFF

                    instr = (65 << 54) | (reg << 46) | (t << 45) | (imm8)
                    binary_output.extend(struct.pack('<Q', instr))
                    if verbose: print(f"  {addr:04X}: {mnemonic} -> {instr:016X}")

                elif m_base == 'ADI':
                    reg_part = arg_list[0].split()
                    reg = self.parse_reg(reg_part[0])
                    h = 1 if len(reg_part) > 1 and reg_part[1].upper() == 'H' else 0
                    imm_str = arg_list[1] if len(arg_list) > 1 else "0"

                    try:
                        imm32 = int(imm_str, 0)
                    except ValueError:
                        v = self.eval_expr(imm_str, addr)
                        imm32 = v if v is not None else self.get_label(imm_str, addr)

                    instr = (66 << 54) | (reg << 46) | (h << 45) | (imm32 & 0xFFFFFFFF)
                    binary_output.extend(struct.pack('<Q', instr))
                    if verbose: print(f"  {addr:04X}: {mnemonic} -> {instr:016X}")

                elif m_base == 'LDI':
                    reg_part = arg_list[0].split()
                    reg = self.parse_reg(reg_part[0])
                    mode_str = reg_part[1].upper() if len(reg_part) > 1 else 'L'
                    mode = 0 if mode_str == 'L' else 1 if mode_str == 'H' else 2 if mode_str == 'B' else 3

                    imm_str = arg_list[1] if len(arg_list) > 1 else "0"
                    try:
                        imm32 = int(imm_str, 0)
                    except ValueError:
                        v = self.eval_expr(imm_str, addr)
                        imm32 = v if v is not None else self.get_label(imm_str, addr)

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
                    try:
                        imm32 = int(imm_str, 0)
                    except ValueError:
                        v = self.eval_expr(imm_str, addr)
                        imm32 = v if v is not None else self.get_label(imm_str, addr)

                    op = 0
                    instr = header | (0x00 << 50) | (op << 42) | (sp_reg << 34) | (mode << 32) | (imm32 & 0xFFFFFFFF)
                    binary_output.extend(struct.pack('<Q', instr))
                    if verbose: print(f"  {addr:04X}: {mnemonic} -> {instr:016X}")

                elif m_base in ['ERET', 'EFLSH']:
                    op = 3 if m_base == 'ERET' else 4
                    instr = header | (0x00 << 50) | (op << 42)
                    binary_output.extend(struct.pack('<Q', instr))
                    if verbose: print(f"  {addr:04X}: {mnemonic} -> {instr:016X}")

                elif m_base == 'PRINTI':
                    term_str = arg_list[0].strip() if arg_list and arg_list[0] else "0"
                    i_sel = 0

                    if term_str.upper().startswith('A'):
                        i_sel = 1
                        term = self.parse_reg(term_str)
                    else:
                        if term_str.startswith('#'): term_str = term_str[1:]
                        try:
                            term = int(term_str, 0) & 0xF
                        except ValueError:
                            term = 0

                    content_part = args.split(',', 1)[1].strip() if ',' in args else '""'
                    if '"' in content_part:
                        content = content_part.split('"')[1].replace('\\n', '\n').replace('\\r', '\r').replace('\\t', '\t').replace('\\0', '\x00')[:5]
                    else:
                        content = ""

                    char1 = ord(content[0]) if len(content) > 0 else 0
                    str_val = 0
                    for i in range(1, 5):
                        if i < len(content):
                            str_val |= (ord(content[i]) << (32 - i*8))

                    dev = 0x02
                    op = 2
                    instr = header | (dev << 50) | (op << 46) | (term << 42) | (0 << 41) | (i_sel << 40) | ((char1 & 0xFF) << 32) | (str_val & 0xFFFFFFFF)
                    binary_output.extend(struct.pack('<Q', instr))
                    if verbose: print(f"  {addr:04X}: {mnemonic} -> {instr:016X}")

                elif m_base in ['PRINTS', 'INPUT', 'TSTAT']:
                    term_str = arg_list[0].strip() if arg_list and arg_list[0] else "0"
                    i_sel = 0

                    if term_str.upper().startswith('A'):
                        i_sel = 1
                        term = self.parse_reg(term_str)
                    else:
                        if term_str.startswith('#'): term_str = term_str[1:]
                        try:
                            term = int(term_str, 0) & 0xF
                        except ValueError:
                            term = 0

                    mem_part = arg_list[1] if len(arg_list) > 1 else "0"
                    off, idx, pcr, mod = self.parse_mem(mem_part, addr)

                    op = 0 if m_base == 'PRINTS' else 1 if m_base == 'INPUT' else 3
                    dev = 0x02
                    instr = header | (dev << 50) | (op << 46) | ((term & 0xF) << 42) | ((pcr & 1) << 41) | (i_sel << 40) | ((idx & 0xFF) << 32) | (off & 0xFFFFFFFF)
                    binary_output.extend(struct.pack('<Q', instr))
                    if verbose: print(f"  {addr:04X}: {mnemonic} -> {instr:016X}")

                elif m_base in ['ITOA', 'ATOI', 'FTOA', 'ATOF', 'FTOS']:
                    src = self.parse_reg(arg_list[0]) if len(arg_list) > 0 else 0
                    dst = self.parse_reg(arg_list[1]) if len(arg_list) > 1 else 0
                    len_dst = self.parse_reg(arg_list[2]) if len(arg_list) > 2 else 0

                    op = 0 if m_base == 'ITOA' else 1 if m_base == 'ATOI' else 2 if m_base in ['FTOA', 'FTOS'] else 3
                    dev = 0x03

                    # [111111][00000011][oooooooo][aaaaaaaa][bbbbbbbb][dddddddd][ww]
                    instr = header | (dev << 50) | (op << 42) | (src << 34) | (dst << 26) | (len_dst << 18) | ((width & 3) << 16)
                    binary_output.extend(struct.pack('<Q', instr))
                    if verbose: print(f"  {addr:04X}: {mnemonic} -> {instr:016X}")

                elif m_base == 'SPSP':
                    src = self.parse_reg(arg_list[0]) if len(arg_list) > 0 else 0
                    dst = self.parse_reg(arg_list[1]) if len(arg_list) > 1 else 0
                    len_dst = self.parse_reg(arg_list[2]) if len(arg_list) > 2 else 0

                    c_str = arg_list[3].strip() if len(arg_list) > 3 else "0"
                    y_flag = 1 if c_str.startswith('#') else 0

                    if y_flag:
                        v = self.eval_expr(c_str[1:], addr)
                        c_val = v if v is not None else int(c_str[1:], 0)
                    else:
                        c_val = self.parse_reg(c_str)

                    op = 4
                    dev = 0x03
                    instr = header | (dev << 50) | (op << 42) | (src << 34) | (dst << 26) | (len_dst << 18) | ((width & 3) << 16) | ((c_val & 0xFF) << 8) | (y_flag << 7)
                    binary_output.extend(struct.pack('<Q', instr))
                    if verbose: print(f"  {addr:04X}: {mnemonic} -> {instr:016X}")

                elif m_base in ['VBASE', 'VMODE', 'VFLIP', 'VSTAT']:
                    op = {'VBASE': 0, 'VMODE': 1, 'VFLIP': 2, 'VSTAT': 3}[m_base]
                    s_str = arg_list[0].strip() if len(arg_list) > 0 else "0"

                    if s_str.startswith('#'):
                        s_str = s_str[1:]

                    try:
                        s_val = int(s_str, 0) & 0xF
                    except ValueError:
                        v = self.eval_expr(s_str, addr)
                        s_val = (v if v is not None else self.get_label(s_str, addr)) & 0xF

                    a_val = 0
                    i_flag = 0
                    if len(arg_list) > 1:
                        a_str = arg_list[1].strip()
                        if a_str.startswith('#'):
                            i_flag = 1
                            v = self.eval_expr(a_str[1:], addr)
                            a_val = v if v is not None else int(a_str[1:], 0)
                        else:
                            a_val = self.parse_reg(a_str)

                    dev = 0x07
                    instr = header | (dev << 50) | (op << 46) | (s_val << 42) | ((a_val & 0xFF) << 34) | (i_flag << 33) | ((width & 3) << 31)
                    binary_output.extend(struct.pack('<Q', instr))
                    if verbose: print(f"  {addr:04X}: {mnemonic} -> {instr:016X}")

                elif m_base == 'WAIT':
                    arg_str = arg_list[0].strip() if len(arg_list) > 0 else "0"
                    if arg_str.upper().startswith('A'):
                        op = 1
                        reg = self.parse_reg(arg_str)
                        instr = header | (0x06 << 50) | (op << 46) | (reg << 38)
                    else:
                        op = 0
                        imm_str = arg_str[1:] if arg_str.startswith('#') else arg_str
                        try:
                            imm32 = int(imm_str, 0)
                        except ValueError:
                            v = self.eval_expr(imm_str, addr)
                            imm32 = v if v is not None else self.get_label(imm_str, addr)
                        instr = header | (0x06 << 50) | (op << 46) | (imm32 & 0xFFFFFFFF)
                    binary_output.extend(struct.pack('<Q', instr))
                    if verbose: print(f"  {addr:04X}: {mnemonic} -> {instr:016X}")

                elif m_base in ['BRTL', 'BRTR', 'BBRTL', 'BBRTR']:
                    is_bit = 1 if m_base.startswith('BB') else 0
                    d_val = 0 if m_base.endswith('L') else 1

                    a_str = arg_list[0].strip() if len(arg_list) > 0 else "A0"
                    a_reg = self.parse_reg(a_str)

                    b_str = arg_list[1].strip() if len(arg_list) > 1 else "A0"
                    i_flag = 1 if b_str.startswith('#') else 0
                    if i_flag:
                        v = self.eval_expr(b_str[1:], addr)
                        b_val = (v if v is not None else int(b_str[1:], 0)) & 0xFF
                    else:
                        b_val = self.parse_reg(b_str)

                    c_str = arg_list[2].strip() if len(arg_list) > 2 else "A0"
                    o_flag = 0 if c_str.startswith('#') else 1
                    if o_flag == 0:
                        v = self.eval_expr(c_str[1:], addr)
                        c_val = (v if v is not None else int(c_str[1:], 0)) & 0xFF
                    else:
                        c_val = self.parse_reg(c_str)

                    op = 99 if is_bit else 97
                    instr = (op << 54) | ((width & 3) << 52) | (d_val << 51) | ((a_reg & 0xFF) << 43) | ((b_val & 0xFF) << 35) | (i_flag << 34) | ((c_val & 0xFF) << 26) | (o_flag << 25)
                    binary_output.extend(struct.pack('<Q', instr))
                    if verbose: print(f"  {addr:04X}: {mnemonic} -> {instr:016X}")

                elif m_base == 'CAS':
                    a_reg = self.parse_reg(arg_list[0]) if len(arg_list) > 0 else 0
                    b_reg = self.parse_reg(arg_list[1]) if len(arg_list) > 1 else 0
                    c_reg = self.parse_reg(arg_list[2]) if len(arg_list) > 2 else 0

                    instr = (98 << 54) | ((width & 3) << 52) | ((a_reg & 0xFF) << 44) | ((b_reg & 0xFF) << 36) | ((c_reg & 0xFF) << 28)
                    binary_output.extend(struct.pack('<Q', instr))
                    if verbose: print(f"  {addr:04X}: {mnemonic} -> {instr:016X}")

                elif m_base in ['TREAD', 'TWRITE']:
                    t_str = arg_list[0].strip() if len(arg_list) > 0 else "0"
                    if t_str.startswith('#'):
                        t_str = t_str[1:]

                    try:
                        tape = int(t_str, 0) & 0x7
                    except ValueError:
                        v = self.eval_expr(t_str, addr)
                        tape = (v if v is not None else self.get_label(t_str, addr)) & 0x7

                    acc_str = arg_list[1].strip() if len(arg_list) > 1 else "A0"
                    ind = 0

                    if acc_str.startswith('(') and acc_str.endswith(')'):
                        ind = 1
                        acc_str = acc_str[1:-1]
                    acc = self.parse_reg(acc_str)

                    mem_part = arg_list[2] if len(arg_list) > 2 else "0"
                    off, idx, pcr, mod = self.parse_mem(mem_part, addr)

                    op = 0 if m_base == 'TWRITE' else 1
                    dev = 0x04
                    instr = header | (dev << 50) | (op << 42) | (ind << 41) | (tape << 38) | (acc << 30) | ((width & 3) << 28) | ((idx & 0xFF) << 20) | (off & 0xFFFFF)
                    binary_output.extend(struct.pack('<Q', instr))
                    if verbose: print(f"  {addr:04X}: {mnemonic} -> {instr:016X}")

                elif m_base in ['READ', 'WRITE']:
                    op = 0 if m_base == 'READ' else 1
                    ind = 0
                    r = 0

                    arg0 = arg_list[0] if len(arg_list) > 0 else "A0"
                    if arg0.startswith('(') and arg0.endswith(')'):
                        ind = 1
                        a_val = self.parse_reg(arg0[1:-1])
                    else:
                        a_val = self.parse_reg(arg0)

                    arg1 = arg_list[1] if len(arg_list) > 1 else "A0"
                    if arg1.startswith('#'):
                        r = 1
                        v = self.eval_expr(arg1[1:], addr)
                        d_val = (v if v is not None else int(arg1[1:], 0)) & 0xFF
                    else:
                        d_val = self.parse_reg(arg1)

                    arg2 = arg_list[2] if len(arg_list) > 2 else "A0"
                    l_val = self.parse_reg(arg2)

                    dev = 0x05
                    instr = header | (dev << 50) | ((width & 3) << 48) | (op << 44) | (a_val << 36) | (ind << 35) | (d_val << 27) | (r << 26) | (l_val << 18)
                    binary_output.extend(struct.pack('<Q', instr))
                    if verbose: print(f"  {addr:04X}: {mnemonic} {args} -> {instr:016X}")

        if not binary_output:
            print("Warning: No instructions generated.")
            return

        while len(binary_output) % 8 != 0:
            binary_output.append(0)

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
