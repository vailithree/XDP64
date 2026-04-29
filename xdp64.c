#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <winsock2.h>

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <conio.h>
#include <errno.h>
#include <math.h>

#pragma comment(lib, "ws2_32.lib")

#define MEMORY_SIZE (1ULL << 24)
#define PC_MASK     0x000000FFFFFFFFF8ULL
#define ADDR_MASK   0x000000FFFFFFFFFFULL
#define ST_MASK     0x0FFFFF0000000000ULL
#define SYS_MASK    0xFFFFFF0000000000ULL

#define OVF_BIT     0x0000010000000000ULL
#define OS1_BIT     0x0000020000000000ULL
#define OS2_BIT     0x0000040000000000ULL
#define OS3_BIT     0x0000080000000000ULL
#define FPE_BIT     0x0000100000000000ULL
#define PRIV_BIT    0x0000200000000000ULL

#define SWAP16(x) ((uint16_t)((((x) >> 8) & 0xff) | (((x) & 0xff) << 8)))
#define SWAP32(x) ((((x) & 0xff000000u) >> 24) | (((x) & 0x00ff0000u) >> 8) | (((x) & 0x0000ff00u) << 8) | (((x) & 0x000000ffu) << 24))
#define SWAP64(x) ((((x) & 0xff00000000000000ull) >> 56) | (((x) & 0x00ff000000000000ull) >> 40) | (((x) & 0x0000ff0000000000ull) >> 24) | (((x) & 0x000000ff00000000ull) >> 8) | (((x) & 0x00000000ff000000ull) << 8) | (((x) & 0x0000000000ff0000ull) << 24) | (((x) & 0x000000000000ff00ull) << 40) | (((x) & 0x00000000000000ffull) << 56))

typedef struct {
    uint64_t A[256];
    uint64_t PC;
    uint64_t BASE;
    uint64_t TTB;
    uint64_t ETB;
    uint8_t *memory;
    int halted;
    uint64_t step_count;
    char tape_files[4][256];
    FILE *log_file;

    SOCKET listen_socket;
    SOCKET client_sockets[16];
    char input_buffer[16][1024];

    int input_len[16];
    int esc_state[16];

    int last_was_cr[16];

} XDP64;

static inline uint64_t get_pc(XDP64 *cpu) { return cpu->PC & ADDR_MASK; }
static inline uint32_t get_pc32(XDP64 *cpu) { return (uint32_t)(cpu->PC & 0xFFFFFFFFULL); }
static inline uint8_t  get_st_low8(XDP64 *cpu) { return (uint8_t)((cpu->PC >> 40) & 0xFF); }
static inline void     set_ovf(XDP64 *cpu, int v) { if (v) cpu->PC |= OVF_BIT; else cpu->PC &= ~OVF_BIT; }
static inline void     set_os1(XDP64 *cpu, int v) { if (v) cpu->PC |= OS1_BIT; else cpu->PC &= ~OS1_BIT; }
static inline void     set_os2(XDP64 *cpu, int v) { if (v) cpu->PC |= OS2_BIT; else cpu->PC &= ~OS2_BIT; }
static inline void     set_fpe(XDP64 *cpu, int v) { if (v) cpu->PC |= FPE_BIT; else cpu->PC &= ~FPE_BIT; }

#define DO_JMP(target_ea, is_indirect) do { \
uint64_t tgt = (target_ea) & ~7ULL; \
if (is_indirect) cpu->PC = (cpu->PC & SYS_MASK) | (tgt & PC_MASK); \
    else cpu->PC = (cpu->PC & 0xFFFFFFFF00000000ULL) | (tgt & 0xFFFFFFF8ULL); \
} while(0)

void trigger_exception(XDP64 *cpu, int exception_num);

uint64_t mem_read(XDP64 *cpu, uint64_t addr, uint8_t w) {
    addr &= ADDR_MASK;
    if (addr < 2048) {
        uint64_t reg_idx = addr >> 3;
        uint64_t val = cpu->A[reg_idx];
        if (w == 0) return val;
        if (w == 1) return (uint32_t)val;
        if (w == 2) return (uint16_t)val;
        if (w == 3) return (uint8_t)val;
    }
    if (addr >= MEMORY_SIZE) { trigger_exception(cpu, 1); return 0; }
    switch (w) {
        case 0: return *(uint64_t*)(cpu->memory + (addr & ~7ULL));
        case 1: return *(uint32_t*)(cpu->memory + (addr & ~3ULL));
        case 2: return *(uint16_t*)(cpu->memory + (addr & ~1ULL));
        case 3: return cpu->memory[addr];
        default: return 0;
    }
}

void mem_write(XDP64 *cpu, uint64_t addr, uint64_t val, uint8_t w) {
    addr &= ADDR_MASK;
    if (addr < 2048) {
        uint64_t reg_idx = addr >> 3;
        if (w == 0) cpu->A[reg_idx] = val;
        else if (w == 1) cpu->A[reg_idx] = (cpu->A[reg_idx] & 0xFFFFFFFF00000000ULL) | (val & 0xFFFFFFFF);
        else if (w == 2) cpu->A[reg_idx] = (cpu->A[reg_idx] & 0xFFFFFFFFFFFF0000ULL) | (val & 0xFFFF);
        else if (w == 3) cpu->A[reg_idx] = (cpu->A[reg_idx] & 0xFFFFFFFFFFFFFF00ULL) | (val & 0xFF);
        return;
    }
    if (addr >= MEMORY_SIZE) { trigger_exception(cpu, 1); return; }
    switch (w) {
        case 0: *(uint64_t*)(cpu->memory + (addr & ~7ULL)) = val; break;
        case 1: *(uint32_t*)(cpu->memory + (addr & ~3ULL)) = (uint32_t)val; break;
        case 2: *(uint16_t*)(cpu->memory + (addr & ~1ULL)) = (uint16_t)val; break;
        case 3: cpu->memory[addr] = (uint8_t)val; break;
    }
}

void trigger_exception(XDP64 *cpu, int exception_num) {
    if (exception_num == 0) set_fpe(cpu, 1);
    uint64_t addr = (cpu->ETB + (exception_num * 8)) & ADDR_MASK;
    if (addr >= MEMORY_SIZE) { cpu->halted = 1; return; }
    uint64_t target = *(uint64_t*)(cpu->memory + (addr & ~7ULL));
    DO_JMP(target, 1);
}

static double f16_to_f64(uint16_t h) {
    uint32_t sign = (h >> 15) & 1;
    uint32_t exp = (h >> 10) & 0x1F;
    uint32_t mant = h & 0x3FF;
    if (exp == 0) { if (mant == 0) return sign ? -0.0 : 0.0; }
    uint32_t f32 = 0;
    if (exp == 0x1F) f32 = (sign << 31) | (0xFF << 23) | (mant << 13);
    else if (exp == 0) f32 = (sign << 31) | (0 << 23) | (mant << 13);
    else f32 = (sign << 31) | ((exp - 15 + 127) << 23) | (mant << 13);
    float f; memcpy(&f, &f32, 4); return (double)f;
}

static uint16_t f64_to_f16(double d) {
    float f = (float)d; uint32_t f32; memcpy(&f32, &f, 4);
    uint32_t sign = (f32 >> 16) & 0x8000;
    int32_t exp = ((f32 >> 23) & 0xFF) - 127 + 15;
    uint32_t mant = (f32 >> 13) & 0x3FF;
    if (exp <= 0) return sign;
    if (exp >= 0x1F) return sign | 0x7C00;
    return sign | (exp << 10) | mant;
}

static double f8_to_f64(uint8_t b) {
    uint32_t sign = (b >> 7) & 1;
    int32_t exp = (b >> 3) & 0xF;
    uint32_t mant = b & 0x7;

    if (exp == 0xF) {
        if (mant == 0) return sign ? -INFINITY : INFINITY;
        else return NAN;
    }
    if (exp == 0 && mant == 0) return sign ? -0.0 : 0.0;

    double v = mant;
    if (exp == 0) {
        v /= 8.0;
        v *= 0.015625;
    } else {
        v = 1.0 + (v / 8.0);
        double p = 1.0;
        int e = exp - 7;
        if (e > 0) while (e--) p *= 2.0;
        else if (e < 0) while (e++) p /= 2.0;
        v *= p;
    }
    return sign ? -v : v;
}

static uint8_t f64_to_f8(double d) {
    if (d != d) return 0x79;

    uint8_t sign = (d < 0.0 || (d == 0.0 && 1.0/d < 0.0)) ? 1 : 0;
    if (d < 0) d = -d;
    if (d == INFINITY) return (sign << 7) | 0x78;
    if (d == 0.0) return (sign << 7);

    int exp;
    double mant = frexp(d, &exp);
    mant *= 2.0;
    exp -= 1;

    int stored_exp = exp + 7;
    if (stored_exp >= 0xF) return (sign << 7) | 0x78;

    if (stored_exp <= 0) {
        mant = d / 0.015625;
        uint32_t m = (uint32_t)(mant * 8.0 + 0.5);
        if (m >= 8) return (sign << 7) | (1 << 3) | 0;
        return (sign << 7) | m;
    }

    uint32_t m = (uint32_t)((mant - 1.0) * 8.0 + 0.5);
    if (m >= 8) { m = 0; stored_exp++; if (stored_exp >= 0xF) return (sign << 7) | 0x78; }
    return (sign << 7) | (stored_exp << 3) | m;
}

double get_float(uint64_t val, uint8_t w) {
    if (w == 0) { double d; memcpy(&d, &val, 8); return d; }
    if (w == 1) { float f; uint32_t v = (uint32_t)val; memcpy(&f, &v, 4); return f; }
    if (w == 2) return f16_to_f64(val & 0xFFFF);
    if (w == 3) return f8_to_f64(val & 0xFF);
    return 0;
}

uint64_t pack_float(double d, uint8_t w) {
    if (w == 0) { uint64_t v; memcpy(&v, &d, 8); return v; }
    if (w == 1) { float f = (float)d; uint32_t v; memcpy(&v, &f, 4); return v; }
    if (w == 2) return f64_to_f16(d);
    if (w == 3) return f64_to_f8(d);
    return 0;
}

uint64_t get_ea(XDP64 *cpu, uint32_t m, uint8_t x, uint8_t r, uint8_t p, uint8_t i, uint8_t w) {
    uint64_t ea = m;
    uint64_t width = (w == 0) ? 8 : (w == 1) ? 4 : (w == 2) ? 2 : 1;
    if (x != 0) {
        if (p == 1) cpu->A[x] += width;
        ea = (ea + (uint32_t)(cpu->A[x] & 0xFFFFFFFF)) & 0xFFFFFFFF;
        if (p == 2) cpu->A[x] -= width;
        if (p == 3 && cpu->A[x] == 0) cpu->PC += 8;
    }
    if (r) ea = (ea + get_pc(cpu)) & ADDR_MASK;
    else ea = (ea + cpu->BASE) & ADDR_MASK;
    if (i) {
        uint64_t iw = mem_read(cpu, ea & ~7ULL, 0);
        uint8_t ix1 = (iw >> 56) & 0xFF;
        uint8_t ix2 = (iw >> 48) & 0xFF;
        ea = iw & ADDR_MASK;
        if (ix1) ea = (ea + (uint32_t)(cpu->A[ix1] & 0xFFFFFFFF)) & ADDR_MASK;
        if (ix2) ea = (ea + (uint32_t)(cpu->A[ix2] & 0xFFFFFFFF)) & ADDR_MASK;
    }

    if (w == 0) ea &= ~7ULL;
    else if (w == 1) ea &= ~3ULL;
    else if (w == 2) ea &= ~1ULL;
    return ea;
}

void poll_network(XDP64 *cpu) {

    while (_kbhit()) {
        int c = _getch();

        if (c == 0 || c == 224) {
            if (_kbhit()) _getch();

            continue;
        }

        if (c == 5) {

            cpu->halted = 1;
            printf("\nBreak at %010llX\n", get_pc(cpu));
            continue;
        }

        if (cpu->esc_state[0] == 1) {
            if (c == '[' || c == 'O') cpu->esc_state[0] = 2;
            else cpu->esc_state[0] = 0;
            continue;
        }
        if (cpu->esc_state[0] == 2) {
            if ((c >= 'A' && c <= 'Z') || c == '~') cpu->esc_state[0] = 0;
            continue;
        }
        if (c == 27) {

            cpu->esc_state[0] = 1;
            continue;
        }

        if (c == '\r') {
            cpu->last_was_cr[0] = 1;
            c = '\n';
            printf("\r\n");

        } else if (c == '\n') {
            if (cpu->last_was_cr[0]) {
                cpu->last_was_cr[0] = 0;
                continue;

            }
            printf("\r\n");

        } else if (c == '\b' || c == 0x7F) {
            if (cpu->input_len[0] > 0) {
                cpu->input_len[0]--;
                printf("\b \b");
            }
            continue;
        } else {
            cpu->last_was_cr[0] = 0;
            putchar(c);
        }

        if (cpu->input_len[0] < 1023) {
            cpu->input_buffer[0][cpu->input_len[0]++] = (char)c;
        }
    }

    if (cpu->listen_socket != 0 && cpu->listen_socket != INVALID_SOCKET) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(cpu->listen_socket, &readfds);
        struct timeval tv = {0, 0};
        if (select(0, &readfds, NULL, NULL, &tv) > 0) {
            SOCKET client = accept(cpu->listen_socket, NULL, NULL);
            if (client != INVALID_SOCKET) {
                int assigned = 0;
                for (int i = 1; i < 16; i++) {
                    if (cpu->client_sockets[i] == 0) {
                        cpu->client_sockets[i] = client;
                        cpu->input_len[i] = 0;
                        cpu->esc_state[i] = 0;
                        cpu->last_was_cr[i] = 0;
                        assigned = 1;
                        break;
                    }
                }
                if (!assigned) {
                    char *msg = "Terminal cluster full.\r\n";
                    send(client, msg, strlen(msg), 0);
                    closesocket(client);
                }
            }
        }
    }

    for (int i = 1; i < 16; i++) {
        if (cpu->client_sockets[i] != 0) {
            u_long bytes_available = 0;
            ioctlsocket(cpu->client_sockets[i], FIONREAD, &bytes_available);
            while (bytes_available > 0) {
                char c;
                int res = recv(cpu->client_sockets[i], &c, 1, 0);
                if (res <= 0) {
                    closesocket(cpu->client_sockets[i]);
                    cpu->client_sockets[i] = 0;
                    cpu->input_len[i] = 0;
                    break;
                }
                bytes_available--;

                if (c == '\0') continue;

                if ((unsigned char)c == 0xFF) {
                    if (bytes_available >= 2) {
                        recv(cpu->client_sockets[i], &c, 1, 0);
                        recv(cpu->client_sockets[i], &c, 1, 0);
                        bytes_available -= 2;
                    } else if (bytes_available == 1) {
                        recv(cpu->client_sockets[i], &c, 1, 0);
                        bytes_available -= 1;
                    }
                    continue;
                }

                if (cpu->esc_state[i] == 1) {
                    if (c == '[' || c == 'O') cpu->esc_state[i] = 2;
                    else cpu->esc_state[i] = 0;
                    continue;
                }
                if (cpu->esc_state[i] == 2) {
                    if ((c >= 'A' && c <= 'Z') || c == '~') cpu->esc_state[i] = 0;
                    continue;
                }
                if (c == 27) {
                    cpu->esc_state[i] = 1;
                    continue;
                }

                if (c == '\r') {
                    cpu->last_was_cr[i] = 1;
                    c = '\n';
                    send(cpu->client_sockets[i], "\r\n", 2, 0);
                } else if (c == '\n') {
                    if (cpu->last_was_cr[i]) {
                        cpu->last_was_cr[i] = 0;
                        continue;

                    }
                    send(cpu->client_sockets[i], "\r\n", 2, 0);
                } else if (c == '\b' || c == 0x7F) {
                    if (cpu->input_len[i] > 0) {
                        cpu->input_len[i]--;
                        send(cpu->client_sockets[i], "\b \b", 3, 0);
                    }
                    continue;
                } else {
                    cpu->last_was_cr[i] = 0;
                    send(cpu->client_sockets[i], &c, 1, 0);
                }

                if (cpu->input_len[i] < 1023) {
                    cpu->input_buffer[i][cpu->input_len[i]++] = c;
                }
            }
        }
    }
}

void handle_io(XDP64 *cpu, uint64_t instr) {
    uint8_t dev = (instr >> 50) & 0xFF;
    uint64_t data = instr & 0x3FFFFFFFFFFFFULL;

    if (dev == 0x00) {

        uint8_t op = (data >> 42) & 0xFF;
        if (op == 0) {

            uint8_t sp_reg = (data >> 34) & 0xFF;
            uint8_t mode = (data >> 32) & 0x3;
            uint32_t imm = (uint32_t)(data & 0xFFFFFFFF);
            uint64_t prev = 0;
            if (sp_reg == 0) prev = cpu->BASE;
            else if (sp_reg == 1) prev = cpu->TTB;
            else if (sp_reg == 2) prev = cpu->ETB;

            uint64_t n_val = prev;
            if (mode == 0) n_val = (prev & 0xFFFFFFFF00000000ULL) | imm;
            else if (mode == 1) n_val = (prev & 0x00000000FFFFFFFFULL) | ((uint64_t)imm << 32);
            else if (mode == 2) n_val = ((uint64_t)imm << 32) | imm;

            if (sp_reg == 0) cpu->BASE = n_val & ADDR_MASK;
            else if (sp_reg == 1) cpu->TTB = n_val & ADDR_MASK;
            else if (sp_reg == 2) cpu->ETB = n_val & ADDR_MASK;
        } else if (op == 1) {

            uint8_t sp_reg = (data >> 34) & 0xFF;
            uint8_t a_reg = (data >> 26) & 0xFF;
            if (sp_reg == 0) cpu->A[a_reg] = cpu->BASE;
            else if (sp_reg == 1) cpu->A[a_reg] = cpu->TTB;
            else if (sp_reg == 2) cpu->A[a_reg] = cpu->ETB;
        } else if (op == 2) {

            uint8_t a_reg = (data >> 34) & 0xFF;
            uint8_t sp_reg = (data >> 26) & 0xFF;
            if (sp_reg == 0) cpu->BASE = cpu->A[a_reg] & ADDR_MASK;
            else if (sp_reg == 1) cpu->TTB = cpu->A[a_reg] & ADDR_MASK;
            else if (sp_reg == 2) cpu->ETB = cpu->A[a_reg] & ADDR_MASK;
        }
    } else if (dev == 0x02) {

        uint8_t io_op = (data >> 46) & 0xF;
        uint8_t t     = (data >> 42) & 0xF;
        uint8_t r     = (data >> 41) & 0x1;
        uint8_t i_sel = (data >> 40) & 0x1;
        uint8_t x     = (data >> 32) & 0xFF;
        uint32_t m    = (uint32_t)(data & 0xFFFFFFFF);

        uint8_t actual_t = i_sel ? (uint8_t)(cpu->A[t] & 0x0F) : (t & 0x0F);

        if (io_op == 0) {

            uint32_t addr = get_ea(cpu, m, x, r, 0, 0, 3);
            while (addr < MEMORY_SIZE) {
                char c = cpu->memory[addr++];
                if (c == 0) break;
                if (actual_t == 0) {
                    putchar(c);
                } else if (cpu->client_sockets[actual_t]) {
                    if (c == '\n') send(cpu->client_sockets[actual_t], "\r\n", 2, 0);
                    else send(cpu->client_sockets[actual_t], &c, 1, 0);
                }
            }
        } else if (io_op == 1) {

            uint32_t addr = get_ea(cpu, m, x, r, 0, 0, 3);
            char b[256];
            size_t len = 0;

            int i = 0;
            int line_end = -1;
            for (int j=0; j < cpu->input_len[actual_t]; j++) {
                char c = cpu->input_buffer[actual_t][j];
                if (c == '\n') {
                    line_end = j;
                    break;
                }
                if (i < 255) b[i++] = c;

            }

            if (line_end != -1) {
                b[i] = 0;

                len = i;
                int remaining = cpu->input_len[actual_t] - (line_end + 1);
                if (remaining > 0) {
                    memmove(cpu->input_buffer[actual_t], &cpu->input_buffer[actual_t][line_end + 1], remaining);
                }
                cpu->input_len[actual_t] = remaining;
            } else {
                b[0] = 0; len = 0;
            }

            for (size_t j=0; j<=len; j++) if(addr+j < MEMORY_SIZE) cpu->memory[addr+j] = b[j];
            cpu->A[255] = (uint64_t)len;

        } else if (io_op == 2) {

            uint8_t c1 = x;
            uint32_t m4 = m;
            if (c1) {
                if (actual_t == 0) putchar(c1);
                else if (cpu->client_sockets[actual_t]) {
                    if (c1 == '\n') send(cpu->client_sockets[actual_t], "\r\n", 2, 0);
                    else send(cpu->client_sockets[actual_t], (char*)&c1, 1, 0);
                }
            }
            for (int j=0; j<4; j++) {
                char c = (char)((m4 >> (24 - j*8)) & 0xFF);
                if (c == 0) break;
                if (actual_t == 0) putchar(c);
                else if (cpu->client_sockets[actual_t]) {
                    if (c == '\n') send(cpu->client_sockets[actual_t], "\r\n", 2, 0);
                    else send(cpu->client_sockets[actual_t], &c, 1, 0);
                }
            }
        } else if (io_op == 3) {

            int has_data = 0;
            int is_connected = 0;

            if (actual_t == 0) {
                is_connected = 1;

                for(int j = 0; j < cpu->input_len[actual_t]; j++) {
                    if (cpu->input_buffer[actual_t][j] == '\n') {
                        has_data = 1; break;
                    }
                }
            } else {
                if (cpu->client_sockets[actual_t] != 0 && cpu->client_sockets[actual_t] != INVALID_SOCKET) {
                    is_connected = 1;
                    for(int j = 0; j < cpu->input_len[actual_t]; j++) {
                        if (cpu->input_buffer[actual_t][j] == '\n') {
                            has_data = 1; break;
                        }
                    }
                }
            }

            set_os1(cpu, has_data);
            set_os2(cpu, is_connected);
        }
        fflush(stdout);
    } else if (dev == 0x03) {

        uint8_t io_op = (data >> 42) & 0xFF;
        uint8_t src_reg = (data >> 34) & 0xFF;
        uint8_t dst_reg = (data >> 26) & 0xFF;
        uint8_t w = (data >> 24) & 0x03;

        if (io_op == 0) {

            int64_t val = (int64_t)cpu->A[src_reg];
            if (w == 1) val = (int64_t)(int32_t)val;
            else if (w == 2) val = (int64_t)(int16_t)val;
            else if (w == 3) val = (int64_t)(int8_t)val;
            char buf[64]; sprintf(buf, "%lld", val);
            uint32_t addr = cpu->A[dst_reg] & ADDR_MASK;
            size_t len = strlen(buf);
            for (size_t j=0; j<=len; j++) if(addr+j < MEMORY_SIZE) cpu->memory[addr+j] = buf[j];
            cpu->A[(dst_reg + 1) & 255] = len;
        } else if (io_op == 1) {

            uint32_t addr = cpu->A[src_reg] & ADDR_MASK;
            char buf[256]; size_t i = 0;
            while(i < 255 && addr+i < MEMORY_SIZE) {
                buf[i] = cpu->memory[addr+i]; if (buf[i] == 0) break; i++;
            }
            buf[i] = 0;
            int64_t val = (int64_t)strtoll(buf, NULL, 10);
            if (w == 1) val = (int64_t)(int32_t)val;
            else if (w == 2) val = (int64_t)(int16_t)val;
            else if (w == 3) val = (int64_t)(int8_t)val;
            cpu->A[dst_reg] = (uint64_t)val;
        } else if (io_op == 2) {

            double val = get_float(cpu->A[src_reg], w);
            char buf[64]; sprintf(buf, "%g", val);
            uint32_t addr = cpu->A[dst_reg] & ADDR_MASK;
            size_t len = strlen(buf);
            for (size_t j=0; j<=len; j++) if(addr+j < MEMORY_SIZE) cpu->memory[addr+j] = buf[j];
            cpu->A[(dst_reg + 1) & 255] = len;
        } else if (io_op == 3) {

            uint32_t addr = cpu->A[src_reg] & ADDR_MASK;
            char buf[256]; size_t i = 0;
            while(i < 255 && addr+i < MEMORY_SIZE) {
                buf[i] = cpu->memory[addr+i]; if (buf[i] == 0) break; i++;
            }
            buf[i] = 0;
            double val = strtod(buf, NULL);
            cpu->A[dst_reg] = pack_float(val, w);
        }
    } else if (dev == 0x04) {

        uint8_t io_op = (data >> 42) & 0xFF;
        uint8_t ind = (data >> 41) & 0x1;
        uint8_t tape_id = (data >> 38) & 0x7;
        uint8_t acc = (data >> 30) & 0xFF;
        uint8_t w = (data >> 28) & 0x3;
        uint8_t idx = (data >> 20) & 0xFF;
        uint32_t m_addr = data & 0xFFFFF;

        if (tape_id > 3) return;

        uint32_t tape_addr = (m_addr + (uint32_t)(cpu->A[idx] & 0xFFFFF)) & 0xFFFFF;

        char filename[256];
        if (cpu->tape_files[tape_id][0] != '\0') {
            strncpy(filename, cpu->tape_files[tape_id], 255);
            filename[255] = '\0';
        } else {
            sprintf(filename, "tape%d.bin", tape_id);

        }

        FILE *f = fopen(filename, "r+b");
        if (!f) {
            f = fopen(filename, "w+b");
            if (f) {
                fseek(f, 1024*1024 - 1, SEEK_SET);
                fputc(0, f);
            }
        }

        if (f) {
            fseek(f, tape_addr, SEEK_SET);
            int bytes = (w==0)?8:(w==1)?4:(w==2)?2:1;
            if (io_op == 0) {

                uint64_t w_data = ind ? mem_read(cpu, cpu->A[acc] & ADDR_MASK, w) : cpu->A[acc];
                fwrite(&w_data, 1, bytes, f);
            } else if (io_op == 1) {

                uint64_t r_data = 0;
                fread(&r_data, 1, bytes, f);
                if (ind) mem_write(cpu, cpu->A[acc] & ADDR_MASK, r_data, w);
                else {
                    if (w == 0) cpu->A[acc] = r_data;
                    else if (w == 1) cpu->A[acc] = (cpu->A[acc] & 0xFFFFFFFF00000000ULL) | (r_data & 0xFFFFFFFF);
                    else if (w == 2) cpu->A[acc] = (cpu->A[acc] & 0xFFFFFFFFFFFF0000ULL) | (r_data & 0xFFFF);
                    else cpu->A[acc] = (cpu->A[acc] & 0xFFFFFFFFFFFFFF00ULL) | (r_data & 0xFF);
                }
            }
            fclose(f);
        }
    }
}

void step(XDP64 *cpu) {
    if (cpu->step_count % 128 == 0) poll_network(cpu);

    uint64_t pc_val = get_pc(cpu);
    uint64_t instr = mem_read(cpu, pc_val, 0);

    if (cpu->log_file) {
        fprintf(cpu->log_file, "[Step %08llu] PC: %010llX | Instr: %016llX | Opcode: %llu\n",
                cpu->step_count, pc_val, instr, (instr >> 54) & 0x3FF);
        fflush(cpu->log_file);
    }

    cpu->PC = (cpu->PC & SYS_MASK) | ((pc_val + 8) & ADDR_MASK);
    cpu->step_count++;

    if ((instr >> 58) == 0x3F) {
        handle_io(cpu, instr);
        return;
    }

    uint16_t op = (instr >> 54) & 0x3FF;

    if (op == 64) {

        uint8_t reg = (instr >> 46) & 0xFF;
        uint8_t mode = (instr >> 44) & 0x3;
        uint32_t imm = (uint32_t)(instr & 0xFFFFFFFF);
        if (mode == 0) cpu->A[reg] = (cpu->A[reg] & 0xFFFFFFFF00000000ULL) | imm;
        else if (mode == 1) cpu->A[reg] = (cpu->A[reg] & 0x00000000FFFFFFFFULL) | ((uint64_t)imm << 32);
        else if (mode == 2) cpu->A[reg] = ((uint64_t)imm << 32) | imm;
        return;
    }
    if (op == 65) {

        uint8_t a = (instr >> 46) & 0xFF;
        uint8_t t = (instr >> 45) & 1;
        if (t == 0) {

            uint8_t imm8 = instr & 0xFF;
            cpu->A[a] -= 8;
            mem_write(cpu, cpu->A[a] & ADDR_MASK, get_pc(cpu), 0);
            uint64_t target = mem_read(cpu, (cpu->TTB + (imm8 * 8)) & ADDR_MASK, 0);
            DO_JMP(target, 1);
        } else {

            uint64_t rv = mem_read(cpu, cpu->A[a] & ADDR_MASK, 0);
            cpu->A[a] += 8;
            DO_JMP(rv, 1);
        }
        return;
    }
    if (op == 66) {

        uint8_t a = (instr >> 46) & 0xFF;
        uint8_t h = (instr >> 45) & 1;
        uint32_t imm32 = (uint32_t)(instr & 0xFFFFFFFF);
        if (h) cpu->A[a] += ((uint64_t)imm32 << 32);
        else cpu->A[a] += imm32;
        return;
    }

    uint8_t  a  = (instr >> 46) & 0xFF;
    uint8_t  i  = (instr >> 45) & 0x1;
    uint8_t  x  = (instr >> 37) & 0xFF;
    uint8_t  w  = (instr >> 35) & 0x3;
    uint8_t  r  = (instr >> 34) & 0x1;
    uint8_t  p  = (instr >> 32) & 0x3;
    uint32_t m  = (uint32_t)(instr & 0xFFFFFFFF);

    uint64_t ea = get_ea(cpu, m, x, r, p, i, w);
    uint64_t val = mem_read(cpu, ea, w);
    uint64_t w_sz = (w == 0) ? 8 : (w == 1) ? 4 : (w == 2) ? 2 : 1;

    switch (op) {
        case 0:  break;

        case 1:  cpu->halted = 1; break;

        case 2:  cpu->A[a] = val; break;

        case 3:  mem_write(cpu, ea, cpu->A[a], w); break;

        case 4:  { uint64_t t = cpu->A[a]; cpu->A[a] = val; mem_write(cpu, ea, t, w); } break;

        case 5:  mem_write(cpu, ea, cpu->A[a] | val, w); break;

        case 6:  mem_write(cpu, ea, cpu->A[a] & val, w); break;

        case 7:  mem_write(cpu, ea, ~cpu->A[a], w); break;

        case 8:  { uint64_t s = val + cpu->A[a]; mem_write(cpu, ea, s, w); set_ovf(cpu, s < val); } break;

        case 9:  mem_write(cpu, ea, val - cpu->A[a], w); break;

        case 10: {

            cpu->A[a] -= 8;
            mem_write(cpu, cpu->A[a] & ADDR_MASK, val, 0);
        } break;

        case 11: {

            uint64_t v = mem_read(cpu, cpu->A[a] & ADDR_MASK, 0);
            mem_write(cpu, ea, v, w);
            cpu->A[a] += 8;
        } break;

        case 12: if(cpu->A[a] == val) cpu->PC += 8; break;

        case 13: if(cpu->A[a] != val) cpu->PC += 8; break;

        case 14: if(cpu->A[a] >  val) cpu->PC += 8; break;

        case 15: if(cpu->A[a] <  val) cpu->PC += 8; break;

        case 16: if(cpu->A[a] >= val) cpu->PC += 8; break;

        case 17: if(cpu->A[a] <= val) cpu->PC += 8; break;

        case 18: DO_JMP(ea, i); break;

        case 19: if(cpu->A[a] == 0) DO_JMP(ea, i); break;

        case 20: if(cpu->A[a] != 0) DO_JMP(ea, i); break;

        case 21: if(cpu->A[a] & 0x8000000000000000ULL) DO_JMP(ea, i); break;

        case 22: if(!(cpu->A[a] & 0x8000000000000000ULL)) DO_JMP(ea, i); break;

        case 23: if(!(cpu->A[a] & 0x8000000000000000ULL) && cpu->A[a] != 0) DO_JMP(ea, i); break;

        case 24: { cpu->A[a] -= 8; mem_write(cpu, cpu->A[a] & ADDR_MASK, get_pc(cpu), 0); DO_JMP(ea, i); } break;

        case 25: { uint64_t rv = mem_read(cpu, cpu->A[a] & ADDR_MASK, 0); cpu->A[a] += 8; if(rv != 0) DO_JMP(rv, 1); } break;

        case 26: { if((get_st_low8(cpu) & a) == a) DO_JMP(ea, i); } break;

        case 27: { uint64_t mt = cpu->A[a] * val; mem_write(cpu, ea, mt, w); set_ovf(cpu, val != 0 && (mt / val != cpu->A[a])); } break;

        case 28: {

            cpu->PC |= ((uint64_t)a << 40);
            DO_JMP(ea, i);
        } break;

        case 29: { uint64_t r0 = val + 1; mem_write(cpu, ea, r0, w); if(a) cpu->A[a] = r0; } break;

        case 30: { uint64_t r0 = val + 1; mem_write(cpu, ea, r0, w); if(a) cpu->A[a] = r0; if((int64_t)r0 < 0) cpu->PC += 8; } break;

        case 31: { uint64_t r0 = val + 1; mem_write(cpu, ea, r0, w); if(a) cpu->A[a] = r0; if((int64_t)r0 <= 0) cpu->PC += 8; } break;

        case 32: { uint64_t r0 = val + 1; mem_write(cpu, ea, r0, w); if(a) cpu->A[a] = r0; if(r0 == 0) cpu->PC += 8; } break;

        case 33: { uint64_t r0 = val + 1; mem_write(cpu, ea, r0, w); if(a) cpu->A[a] = r0; if(r0 != 0) cpu->PC += 8; } break;

        case 34: { uint64_t r0 = val + 1; mem_write(cpu, ea, r0, w); if(a) cpu->A[a] = r0; if((int64_t)r0 > 0) cpu->PC += 8; } break;

        case 35: { uint64_t r0 = val + 1; mem_write(cpu, ea, r0, w); if(a) cpu->A[a] = r0; if((int64_t)r0 >= 0) cpu->PC += 8; } break;

        case 36: { uint64_t r0 = val + 1; mem_write(cpu, ea, r0, w); if(a) cpu->A[a] = r0; cpu->PC += 8; } break;

        case 37: { uint64_t r0 = val - 1; mem_write(cpu, ea, r0, w); if(a) cpu->A[a] = r0; } break;

        case 38: { uint64_t r0 = val - 1; mem_write(cpu, ea, r0, w); if(a) cpu->A[a] = r0; if((int64_t)r0 < 0) cpu->PC += 8; } break;

        case 39: { uint64_t r0 = val - 1; mem_write(cpu, ea, r0, w); if(a) cpu->A[a] = r0; if((int64_t)r0 <= 0) cpu->PC += 8; } break;

        case 40: { uint64_t r0 = val - 1; mem_write(cpu, ea, r0, w); if(a) cpu->A[a] = r0; if(r0 == 0) cpu->PC += 8; } break;

        case 41: { uint64_t r0 = val - 1; mem_write(cpu, ea, r0, w); if(a) cpu->A[a] = r0; if(r0 != 0) cpu->PC += 8; } break;

        case 42: { uint64_t r0 = val - 1; mem_write(cpu, ea, r0, w); if(a) cpu->A[a] = r0; if((int64_t)r0 > 0) cpu->PC += 8; } break;

        case 43: { uint64_t r0 = val - 1; mem_write(cpu, ea, r0, w); if(a) cpu->A[a] = r0; if((int64_t)r0 >= 0) cpu->PC += 8; } break;

        case 44: { uint64_t r0 = val - 1; mem_write(cpu, ea, r0, w); if(a) cpu->A[a] = r0; cpu->PC += 8; } break;

        case 45: mem_write(cpu, ea, cpu->A[a] ^ val, w); break;

        case 46: {

            uint64_t v = cpu->A[a];
            if (w == 0) v = SWAP64(v);
            else if (w == 1) v = SWAP32(v);
            else if (w == 2) v = SWAP16(v);
            mem_write(cpu, ea, v, w);
        } break;
        case 47: {

            if (val == 0) { trigger_exception(cpu, 0); break; }
            uint64_t q = cpu->A[a] / val;
            uint64_t rem = cpu->A[a] % val;
            mem_write(cpu, ea, q, w);
            mem_write(cpu, (ea + w_sz) & ADDR_MASK, rem, w);
        } break;
        case 48: cpu->A[a] = cpu->A[a] << (ea & 63); break;

        case 49: cpu->A[a] = cpu->A[a] >> (ea & 63); break;

        case 50: cpu->A[a] = cpu->A[a] << (val & 63); break;

        case 51: cpu->A[a] = cpu->A[a] >> (val & 63); break;

        case 52: cpu->A[a] = cpu->A[a] << (ea & 63); break;

        case 53: cpu->A[a] = (uint64_t)(((int64_t)cpu->A[a]) >> (ea & 63)); break;

        case 54: cpu->A[a] = cpu->A[a] << (val & 63); break;

        case 55: cpu->A[a] = (uint64_t)(((int64_t)cpu->A[a]) >> (val & 63)); break;

        case 56: { uint8_t s=ea&63; cpu->A[a] = (cpu->A[a]<<s) | (cpu->A[a]>>(64-s)); } break;

        case 57: { uint8_t s=ea&63; cpu->A[a] = (cpu->A[a]>>s) | (cpu->A[a]<<(64-s)); } break;

        case 58: { uint8_t s=val&63; cpu->A[a] = (cpu->A[a]<<s) | (cpu->A[a]>>(64-s)); } break;

        case 59: { uint8_t s=val&63; cpu->A[a] = (cpu->A[a]>>s) | (cpu->A[a]<<(64-s)); } break;

        case 60:

        case 61:

        case 62:

        case 63: {

            double d_reg = get_float(cpu->A[a], w);
            double d_mem = get_float(val, w);
            double res = 0;
            if (op == 60) res = d_reg + d_mem;
            else if (op == 61) res = d_reg - d_mem;
            else if (op == 62) res = d_reg * d_mem;
            else if (op == 63) {
                if (d_mem == 0.0) { trigger_exception(cpu, 0); break; }
                res = d_reg / d_mem;
            }
            if (isnan(res) || isinf(res)) { trigger_exception(cpu, 0); break; }
            mem_write(cpu, ea, pack_float(res, w), w);
        } break;

        case 67: {

            cpu->PC &= ~((uint64_t)a << 40);
            DO_JMP(ea, i);
        } break;

        case 68: {

            if ((get_st_low8(cpu) & a) == a) {
                cpu->PC &= ~((uint64_t)a << 40);
                DO_JMP(ea, i);
            }
        } break;

        case 69: {

            if (get_st_low8(cpu) == a) DO_JMP(ea, i);
        } break;

        default: printf("\nUndefined opcode %d at %010llX\n", op, pc_val); cpu->halted = 1; break;
    }
}

void load_file(XDP64 *cpu, const char *path) {
    if (strstr(path, ".ini") || strstr(path, ".INI")) {
        FILE *f = fopen(path, "r");
        if (!f) { printf("INI Error: %s\n", strerror(errno)); return; }
        char buf[256]; int sec = 0;
        while (fgets(buf, 256, f)) {
            if (buf[0] == '[' ) {
                if (strstr(buf, "REG")) sec = 1; else if (strstr(buf, "MEM")) sec = 2;
            } else if (strchr(buf, '=')) {
                char *k = strtok(buf, "= "), *v = strtok(NULL, "= \n");
                uint64_t val = strtoull(v, NULL, 16);
                if (sec == 1) {
                    if (k[0] == 'A') cpu->A[atoi(k+1)] = val;
                    else if (!strcmp(k, "PC")) cpu->PC = (cpu->PC & SYS_MASK) | (val & ADDR_MASK);
                    else if (!strcmp(k, "BASE")) cpu->BASE = val & ADDR_MASK;
                    else if (!strcmp(k, "TTB")) cpu->TTB = val & ADDR_MASK;
                    else if (!strcmp(k, "ETB")) cpu->ETB = val & ADDR_MASK;
                } else if (sec == 2) mem_write(cpu, strtoull(k, NULL, 16), val, 0);
            }
        }
        fclose(f); printf("INI loaded: %s\n", path);
    } else {
        FILE *f = fopen(path, "rb");
        if (!f) { printf("Load Error: %s\n", strerror(errno)); return; }
        fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
        size_t n = fread(cpu->memory, 1, sz > MEMORY_SIZE ? MEMORY_SIZE : sz, f);
        fclose(f); printf("Loaded %zu bytes from %s\n", n, path);
    }
}

void scp(XDP64 *cpu) {
    char cmd[256];
    printf("\nsim> ");
    while (fgets(cmd, 256, stdin)) {
        char *t = strtok(cmd, " \n\t");
        if (!t) { printf("sim> "); continue; }
        if (!_stricmp(t, "EXIT") || !_stricmp(t, "Q")) exit(0);
        if (!_stricmp(t, "RUN") || !_stricmp(t, "G")) { cpu->halted = 0; return; }

        if (!_stricmp(t, "LISTEN")) {
            char *port_str = strtok(NULL, " \n\t");
            if (port_str) {
                int port = atoi(port_str);
                WSADATA wsa;
                WSAStartup(MAKEWORD(2,2), &wsa);
                cpu->listen_socket = socket(AF_INET, SOCK_STREAM, 0);
                struct sockaddr_in addr;
                addr.sin_family = AF_INET;
                addr.sin_addr.s_addr = INADDR_ANY;
                addr.sin_port = htons(port);

                if (bind(cpu->listen_socket, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
                    listen(cpu->listen_socket, 15);
                    printf("Listening for Telnet connections on port %d...\n", port);
                } else {
                    printf("Failed to bind to port %d.\n", port);
                    closesocket(cpu->listen_socket);
                    cpu->listen_socket = 0;
                }
            } else {
                printf("Usage: LISTEN <port>\n");
            }
            printf("sim> "); continue;
        }

        if (!_stricmp(t, "LOG")) {
            if (cpu->log_file) {
                fclose(cpu->log_file);
                cpu->log_file = NULL;
                printf("Logging disabled.\n");
            } else {
                cpu->log_file = fopen("log.txt", "w");
                if (cpu->log_file) printf("Logging enabled to log.txt.\n");
                else printf("Failed to open log.txt for writing.\n");
            }
            printf("sim> "); continue;
        }

        if (!_stricmp(t, "ATTACH") || !_stricmp(t, "AT")) {
            char *dev_name = strtok(NULL, " \n\t");
            char *file_name = strtok(NULL, " \n\t");
            if (dev_name && file_name) {
                if (!_strnicmp(dev_name, "TAP", 3)) {
                    int tid = dev_name[3] - '0';
                    if (tid >= 0 && tid <= 3) {
                        strncpy(cpu->tape_files[tid], file_name, 255);
                        cpu->tape_files[tid][255] = '\0';
                        FILE *f = fopen(file_name, "r+b");
                        if (!f) {
                            f = fopen(file_name, "w+b");
                            if (f) {
                                fseek(f, 1024*1024 - 1, SEEK_SET);
                                fputc(0, f);
                                printf("Created new 1MB tape file: %s\n", file_name);
                            } else {
                                printf("Error: Could not create %s\n", file_name);
                            }
                        }
                        if (f) fclose(f);
                        printf("TAP%d attached to %s\n", tid, file_name);
                    } else {
                        printf("Invalid tape drive. Use TAP0 to TAP3.\n");
                    }
                } else {
                    printf("Unknown device. Try TAP0 to TAP3.\n");
                }
            } else {
                printf("Usage: ATTACH <TAP0-TAP3> <filename>\n");
            }
            printf("sim> ");
            continue;
        }
        if (!_stricmp(t, "STEP") || !_stricmp(t, "S")) {
            char *count = strtok(NULL, " "); int n = count ? atoi(count) : 1;
            for (int i=0; i<n && !cpu->halted; i++) step(cpu);
            printf("Stopped at %010llX\n", get_pc(cpu));
        }
        if (!_stricmp(t, "LOAD") || !_stricmp(t, "L")) {
            char *p = strtok(NULL, " \n\t"); if(p) load_file(cpu, p);
        }
        if (!_stricmp(t, "EXAMINE") || !_stricmp(t, "E")) {
            char *p = strtok(NULL, " ");
            if (!p) printf("PC: %010llX  ST: %05llX  BASE: %010llX  TTB: %010llX  ETB: %010llX\n", get_pc(cpu), (cpu->PC >> 40) & 0xFFFFF, cpu->BASE, cpu->TTB, cpu->ETB);
            else if (p[0] == 'A') { int i = atoi(p+1); printf("A%d: %016llX\n", i, cpu->A[i]); }
            else printf("%010llX: %016llX\n", strtoull(p, NULL, 16), mem_read(cpu, strtoull(p, NULL, 16), 0));
        }
        if (!_stricmp(t, "DEPOSIT") || !_stricmp(t, "D")) {
            char *p = strtok(NULL, " "), *v = strtok(NULL, " ");
            if (p && v) {
                uint64_t val = strtoull(v, NULL, 16);
                if (p[0] == 'A') cpu->A[atoi(p+1)] = val;
                else if (!strcmp(p, "PC")) cpu->PC = (cpu->PC & SYS_MASK) | (val & ADDR_MASK);
                else if (!strcmp(p, "BASE")) cpu->BASE = val & ADDR_MASK;
                else if (!strcmp(p, "TTB")) cpu->TTB = val & ADDR_MASK;
                else if (!strcmp(p, "ETB")) cpu->ETB = val & ADDR_MASK;
                else mem_write(cpu, strtoull(p, NULL, 16), val, 0);
            }
        }
        printf("sim> ");
    }
}

int main(int argc, char **argv) {
    XDP64 *cpu = calloc(1, sizeof(XDP64));
    cpu->memory = calloc(MEMORY_SIZE, 1);
    cpu->halted = 1;
    printf("XDP64 Simulation System\nType CTRL-E to break.\n");

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-l") == 0) {
            cpu->log_file = fopen("log.txt", "w");
            if (cpu->log_file) printf("Logging enabled to log.txt\n");
            else printf("Failed to open log.txt for writing.\n");
        } else {
            load_file(cpu, argv[i]);
        }
    }

    while (1) {
        if (cpu->halted) scp(cpu);
        else {
            step(cpu);
        }
    }
    return 0;
}

