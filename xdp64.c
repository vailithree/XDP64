#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <winsock2.h> // MUST BE FIRST
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

// --- Spec Alignment: PC is 40-bits. ST is the High 24 bits of the 64-bit word! ---
#define ST_MASK     0xFFFFFF0000000000ULL
#define SYS_MASK    0xFFFFFFFF00000000ULL // High 32 bits (preserved on Direct Jumps)

#define OVF_BIT     (1ULL << 40) // ST[0]
#define OS1_BIT     (1ULL << 41) // ST[1]
#define OS2_BIT     (1ULL << 42) // ST[2]
#define OS3_BIT     (1ULL << 43) // ST[3]
#define FPE_BIT     (1ULL << 44) // ST[4]
#define PRIV_BIT    (1ULL << 45) // ST[5]
#define MMU_BIT     (1ULL << 48) // ST[8]

// --- MMU Page Table Flags (Bits 40-63 of a 64-bit Table Entry) ---
#define PTE_PRESENT  (1ULL << 40)
#define PTE_EXEC     (1ULL << 41)
#define PTE_DIRTY    (1ULL << 42)
#define PTE_ACCESSED (1ULL << 43)
#define PTE_KERNEL   (1ULL << 44)
#define PTE_READ     (1ULL << 45)
#define PTE_WRITE    (1ULL << 46)

#define SWAP16(x) ((uint16_t)((((x) >> 8) & 0xff) | (((x) & 0xff) << 8)))
#define SWAP32(x) ((((x) & 0xff000000u) >> 24) | (((x) & 0x00ff0000u) >> 8) | (((x) & 0x0000ff00u) << 8) | (((x) & 0x000000ffu) << 24))
#define SWAP64(x) ((((x) & 0xff00000000000000ull) >> 56) | (((x) & 0x00ff000000000000ull) >> 40) | (((x) & 0x0000ff0000000000ull) >> 24) | (((x) & 0x000000ff00000000ull) >> 8) | (((x) & 0x00000000ff000000ull) << 8) | (((x) & 0x0000000000ff0000ull) << 24) | (((x) & 0x000000000000ff00ull) << 40) | (((x) & 0x00000000000000ffull) << 56))

typedef struct {
    uint64_t A[2048];
    uint64_t PC;
    uint64_t BASE;
    uint64_t TTB;
    uint64_t ETB;
    uint64_t ERS;
    uint64_t VIB;
    uint32_t EXCLK;
    uint32_t hidden_exclk;
    uint64_t CTCLK;
    uint32_t TST;
    uint64_t CTCLKI;
    uint8_t  CRB;
    uint8_t  estck; // Enforced Stack Register

    // MMU Registers
    uint64_t UBT;
    uint64_t KBT;
    uint64_t UKS;
    uint32_t CURAPP;

    // Graphics State
    uint64_t vbase[16];
    uint8_t  vmode[16];
    SOCKET   udp_socket;
    struct sockaddr_in gpu_clients[16];
    uint64_t gpu_last_ping[16];

    // Loop Buffer
    uint64_t loop_buffer[32];
    uint32_t rep_count;
    uint32_t rep_len;
    uint32_t rep_idx;

    uint8_t *memory;
    int halted;
    uint64_t step_count;
    char tape_files[4][256];
    char disk_files[16][256];
    FILE *log_file;

    // Networking
    SOCKET listen_socket;
    SOCKET client_sockets[16];
    char input_buffer[16][1024];
    int input_len[16];
    int esc_state[16];
    int last_was_cr[16];

    int in_exception;
    uint64_t current_instr;
    uint64_t last_time;
} XDP64;

#define ACC(cpu, reg) ((cpu)->A[(reg) == 0 ? 0 : (((cpu)->CRB << 8) + (reg))])

static inline uint64_t get_pc(XDP64 *cpu) { return cpu->PC & ADDR_MASK; }
static inline uint32_t get_pc32(XDP64 *cpu) { return (uint32_t)(cpu->PC & 0xFFFFFFFFULL); }
static inline uint8_t  get_st_low8(XDP64 *cpu) { return (uint8_t)((cpu->PC >> 40) & 0xFF); }
static inline void     set_ovf(XDP64 *cpu, int v) { if (v) cpu->PC |= OVF_BIT; else cpu->PC &= ~OVF_BIT; }
static inline void     set_os1(XDP64 *cpu, int v) { if (v) cpu->PC |= OS1_BIT; else cpu->PC &= ~OS1_BIT; }
static inline void     set_os2(XDP64 *cpu, int v) { if (v) cpu->PC |= OS2_BIT; else cpu->PC &= ~OS2_BIT; }
static inline void     set_fpe(XDP64 *cpu, int v) { if (v) cpu->PC |= FPE_BIT; else cpu->PC &= ~FPE_BIT; }

#define DO_JMP(target_ea, is_indirect) do { \
uint64_t tgt = (target_ea) & ~7ULL; \
if (is_indirect) cpu->PC = (cpu->PC & ST_MASK) | (tgt & PC_MASK); \
    else cpu->PC = (cpu->PC & SYS_MASK) | (tgt & 0x00000000FFFFFFF8ULL); \
        cpu->rep_count = 0; \
} while(0)

uint64_t mem_read(XDP64 *cpu, uint64_t ea, uint8_t w, int is_indirect, int access_type);
void mem_write(XDP64 *cpu, uint64_t ea, uint64_t val, uint8_t w, int is_indirect);
void trigger_exception(XDP64 *cpu, int exception_num);

void trigger_exception(XDP64 *cpu, int exception_num) {
    if (cpu->in_exception) {
        cpu->halted = 1;
        printf("\n[Hardware] Double Fault Exception (%d)! CPU Halted.\n", exception_num);
        return;
    }

    if (exception_num == 0) set_fpe(cpu, 1);

    cpu->ERS = cpu->PC;
    cpu->VIB = cpu->current_instr;
    cpu->in_exception = 1;

    uint64_t addr = (cpu->ETB + (exception_num * 8)) & ADDR_MASK;
    if (addr >= MEMORY_SIZE) { cpu->halted = 1; return; }

    uint64_t target = mem_read(cpu, addr, 0, 1, 0);
    DO_JMP(target, 1);
}

// --- Physical Memory Interface ---
uint64_t mem_read_phys(XDP64 *cpu, uint64_t addr, uint8_t w) {
    addr &= ADDR_MASK;
    if (addr < 16384) {
        uint64_t reg_idx = addr >> 3;
        if (reg_idx == 0 || reg_idx == (uint64_t)(cpu->CRB << 8)) return 0;
        uint64_t val = cpu->A[reg_idx];
        uint8_t shift = (addr & 7) * 8;
        val >>= shift;
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

void mem_write_phys(XDP64 *cpu, uint64_t addr, uint64_t val, uint8_t w) {
    addr &= ADDR_MASK;
    if (addr < 16384) {
        uint64_t reg_idx = addr >> 3;
        if (reg_idx == 0 || reg_idx == (uint64_t)(cpu->CRB << 8)) return;
        uint8_t shift = (addr & 7) * 8;
        if (w == 0) cpu->A[reg_idx] = val;
        else if (w == 1) cpu->A[reg_idx] = (cpu->A[reg_idx] & ~(0xFFFFFFFFULL << shift)) | ((val & 0xFFFFFFFFULL) << shift);
        else if (w == 2) cpu->A[reg_idx] = (cpu->A[reg_idx] & ~(0xFFFFULL << shift)) | ((val & 0xFFFFULL) << shift);
        else if (w == 3) cpu->A[reg_idx] = (cpu->A[reg_idx] & ~(0xFFULL << shift)) | ((val & 0xFFULL) << shift);
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

// --- MMU Translation Interface ---
int check_pte(XDP64 *cpu, uint64_t pte, int access_type) {
    if (!(pte & PTE_PRESENT)) return 0;
    int is_user = !(cpu->PC & PRIV_BIT);
    if (is_user && (pte & PTE_KERNEL)) return 0;
    if (access_type == 0 && !(pte & PTE_READ)) return 0;
    if (access_type == 1 && !(pte & PTE_WRITE)) return 0;
    if (access_type == 2 && !(pte & PTE_EXEC)) return 0;
    return 1;
}

uint64_t translate_address(XDP64 *cpu, uint64_t ea, int is_indirect, int access_type) {
    if (!(cpu->PC & MMU_BIT)) return (ea + (is_indirect ? 0 : cpu->BASE)) & ADDR_MASK;

    uint64_t offset = ea & 0xFFFFF;
    uint64_t group_idx = is_indirect ? ((ea >> 30) & 0x3FF) : ((ea >> 26) & 0x3F);
    uint64_t seg_idx = is_indirect ? ((ea >> 20) & 0x3FF) : ((ea >> 20) & 0x3F);
    uint64_t group_base, segment_base, segment_entry;

    if (ea < cpu->UKS) {
        uint64_t app_entry = mem_read_phys(cpu, (cpu->UBT + cpu->CURAPP * 8) & ADDR_MASK, 0);
        if (!check_pte(cpu, app_entry, access_type)) return 0xFFFFFFFFFFFFFFFFULL;

        uint64_t group_entry = mem_read_phys(cpu, ((app_entry & ADDR_MASK) + group_idx * 8) & ADDR_MASK, 0);
        if (!check_pte(cpu, group_entry, access_type)) return 0xFFFFFFFFFFFFFFFFULL;

        group_base = group_entry & ADDR_MASK;
    } else {
        uint64_t group_entry = mem_read_phys(cpu, (cpu->KBT + group_idx * 8) & ADDR_MASK, 0);
        if (!check_pte(cpu, group_entry, access_type)) return 0xFFFFFFFFFFFFFFFFULL;

        group_base = group_entry & ADDR_MASK;
    }

    segment_entry = mem_read_phys(cpu, (group_base + seg_idx * 8) & ADDR_MASK, 0);
    if (!check_pte(cpu, segment_entry, access_type)) return 0xFFFFFFFFFFFFFFFFULL;

    return (segment_entry & ADDR_MASK) + offset;
}

uint64_t mem_read(XDP64 *cpu, uint64_t ea, uint8_t w, int is_indirect, int access_type) {
    if (ea < 16384) return mem_read_phys(cpu, ea, w);
    uint64_t phys = translate_address(cpu, ea, is_indirect, access_type);
    if (phys == 0xFFFFFFFFFFFFFFFFULL) { trigger_exception(cpu, 1); return 0; }
    return mem_read_phys(cpu, phys, w);
}

void mem_write(XDP64 *cpu, uint64_t ea, uint64_t val, uint8_t w, int is_indirect) {
    if (ea < 16384) { mem_write_phys(cpu, ea, val, w); return; }
    uint64_t phys = translate_address(cpu, ea, is_indirect, 1);
    if (phys == 0xFFFFFFFFFFFFFFFFULL) { trigger_exception(cpu, 1); return; }
    mem_write_phys(cpu, phys, val, w);
}

// --- Floating Point Conversion Helpers ---
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
    if (d != d) return 0x79; // NaN
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

// --- Address Calculation ---
uint64_t get_ea(XDP64 *cpu, uint32_t m, uint8_t x, uint8_t r, uint8_t p, uint8_t i, uint8_t w, uint64_t current_pc) {
    uint64_t ea = m;
    uint64_t width = (w == 0) ? 8 : (w == 1) ? 4 : (w == 2) ? 2 : 1;

    if (x != 0) {
        if (p == 1) { ACC(cpu, x) += width; }
        ea = (ea + (uint32_t)(ACC(cpu, x) & 0xFFFFFFFF)) & 0xFFFFFFFF;
        if (p == 2) { ACC(cpu, x) -= width; }
        if (p == 3 && ACC(cpu, x) == 0) cpu->PC += 8;
    }

    if (r) {
        ea = (ea + get_pc(cpu)) & ADDR_MASK;
    }

    if (i) {
        uint64_t iw = mem_read(cpu, ea & ~7ULL, 0, 0, 0);
        if (cpu->PC != current_pc) return ea;
        uint8_t ix1 = (iw >> 56) & 0xFF;
        uint8_t ix2 = (iw >> 48) & 0xFF;
        ea = iw & ADDR_MASK;
        if (ix1) ea = (ea + (uint32_t)(ACC(cpu, ix1) & 0xFFFFFFFF)) & ADDR_MASK;
        if (ix2) ea = (ea + (uint32_t)(ACC(cpu, ix2) & 0xFFFFFFFF)) & ADDR_MASK;
    }

    if (w == 0) ea &= ~7ULL;
    else if (w == 1) ea &= ~3ULL;
    else if (w == 2) ea &= ~1ULL;
    return ea;
}

// --- GPU Network Transfer ---
void send_vframe(XDP64 *cpu, uint8_t s_id) {
    if (cpu->udp_socket == 0 || cpu->udp_socket == INVALID_SOCKET) return;
    if (GetTickCount64() - cpu->gpu_last_ping[s_id] > 5000) return;

    uint8_t mode = cpu->vmode[s_id];
    if (mode == 0) return;

    uint32_t payload_size = (mode == 1) ? 9600 : 38400;
    uint32_t packet_size = payload_size + 2;

    static uint8_t packet[40000];
    packet[0] = s_id;
    packet[1] = mode;

    uint64_t base = cpu->vbase[s_id];
    for (uint32_t i = 0; i < payload_size; i++) {
        packet[i+2] = mem_read_phys(cpu, (base + i) & ADDR_MASK, 3);
    }

    sendto(cpu->udp_socket, (const char*)packet, packet_size, 0,
           (struct sockaddr*)&cpu->gpu_clients[s_id], sizeof(struct sockaddr_in));
}

// --- Asynchronous Network Polling ---
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
        if (c == 27) { cpu->esc_state[0] = 1; continue; }

        if (c == '\r') {
            cpu->last_was_cr[0] = 1; c = '\n'; printf("\r\n");
        } else if (c == '\n') {
            if (cpu->last_was_cr[0]) { cpu->last_was_cr[0] = 0; continue; }
            printf("\r\n");
        } else if (c == '\b' || c == 0x7F) {
            if (cpu->input_len[0] > 0) { cpu->input_len[0]--; printf("\b \b"); }
            continue;
        } else {
            cpu->last_was_cr[0] = 0; putchar(c);
        }

        if (cpu->input_len[0] < 1023) cpu->input_buffer[0][cpu->input_len[0]++] = (char)c;
    }

    if (cpu->listen_socket != 0 && cpu->listen_socket != INVALID_SOCKET) {
        fd_set readfds; FD_ZERO(&readfds); FD_SET(cpu->listen_socket, &readfds);
        struct timeval tv = {0, 0};
        if (select(0, &readfds, NULL, NULL, &tv) > 0) {
            SOCKET client = accept(cpu->listen_socket, NULL, NULL);
            if (client != INVALID_SOCKET) {
                int assigned = 0;
                for (int i = 1; i < 16; i++) {
                    if (cpu->client_sockets[i] == 0) {
                        cpu->client_sockets[i] = client;
                        cpu->input_len[i] = 0; cpu->esc_state[i] = 0; cpu->last_was_cr[i] = 0;
                        assigned = 1; break;
                    }
                }
                if (!assigned) { char *msg = "Terminal cluster full.\r\n"; send(client, msg, strlen(msg), 0); closesocket(client); }
            }
        }
    }

    for (int i = 1; i < 16; i++) {
        if (cpu->client_sockets[i] != 0) {
            u_long bytes_available = 0;
            ioctlsocket(cpu->client_sockets[i], FIONREAD, &bytes_available);
            while (bytes_available > 0) {
                char c; int res = recv(cpu->client_sockets[i], &c, 1, 0);
                if (res <= 0) { closesocket(cpu->client_sockets[i]); cpu->client_sockets[i] = 0; cpu->input_len[i] = 0; break; }
                bytes_available--;
                if (c == '\0') continue;
                if ((unsigned char)c == 0xFF) {
                    if (bytes_available >= 2) { recv(cpu->client_sockets[i], &c, 1, 0); recv(cpu->client_sockets[i], &c, 1, 0); bytes_available -= 2; }
                    else if (bytes_available == 1) { recv(cpu->client_sockets[i], &c, 1, 0); bytes_available -= 1; }
                    continue;
                }
                if (cpu->esc_state[i] == 1) {
                    if (c == '[' || c == 'O') cpu->esc_state[i] = 2; else cpu->esc_state[i] = 0; continue;
                }
                if (cpu->esc_state[i] == 2) {
                    if ((c >= 'A' && c <= 'Z') || c == '~') cpu->esc_state[i] = 0; continue;
                }
                if (c == 27) { cpu->esc_state[i] = 1; continue; }

                if (c == '\r') { cpu->last_was_cr[i] = 1; c = '\n'; send(cpu->client_sockets[i], "\r\n", 2, 0); }
                else if (c == '\n') { if (cpu->last_was_cr[i]) { cpu->last_was_cr[i] = 0; continue; } send(cpu->client_sockets[i], "\r\n", 2, 0); }
                else if (c == '\b' || c == 0x7F) { if (cpu->input_len[i] > 0) { cpu->input_len[i]--; send(cpu->client_sockets[i], "\b \b", 3, 0); } continue; }
                else { cpu->last_was_cr[i] = 0; send(cpu->client_sockets[i], &c, 1, 0); }

                if (cpu->input_len[i] < 1023) cpu->input_buffer[i][cpu->input_len[i]++] = c;
            }
        }
    }

    if (cpu->udp_socket != 0 && cpu->udp_socket != INVALID_SOCKET) {
        u_long bytes_available = 0;
        ioctlsocket(cpu->udp_socket, FIONREAD, &bytes_available);
        while (bytes_available > 0) {
            char buf[16]; struct sockaddr_in sender; int sender_len = sizeof(sender);
            int res = recvfrom(cpu->udp_socket, buf, sizeof(buf), 0, (struct sockaddr*)&sender, &sender_len);
            if (res > 0) {
                uint8_t screen_id = buf[0];
                if (screen_id < 16) { cpu->gpu_clients[screen_id] = sender; cpu->gpu_last_ping[screen_id] = GetTickCount64(); }
            }
            ioctlsocket(cpu->udp_socket, FIONREAD, &bytes_available);
        }
    }
}

// --- I/O Dispatches ---
void handle_io(XDP64 *cpu, uint64_t instr, uint64_t current_pc) {
    uint8_t dev = (instr >> 50) & 0xFF;
    uint64_t data = instr & 0x3FFFFFFFFFFFFULL;

    if (dev == 0x00) { // Computer Internal
        uint8_t op = (data >> 42) & 0xFF;
        if (op == 0) { // LSP
            uint8_t sp_reg = (data >> 34) & 0xFF;
            uint8_t mode = (data >> 32) & 0x3;
            uint32_t imm = (uint32_t)(data & 0xFFFFFFFF);
            uint64_t prev = 0;

            if (sp_reg == 0) prev = cpu->BASE;
            else if (sp_reg == 1) prev = cpu->TTB;
            else if (sp_reg == 2) prev = cpu->ETB;
            else if (sp_reg == 3) prev = cpu->VIB;
            else if (sp_reg == 4) prev = cpu->EXCLK;
            else if (sp_reg == 5) prev = cpu->CTCLK;
            else if (sp_reg == 6) prev = cpu->TST;
            else if (sp_reg == 7) prev = cpu->CTCLKI;
            else if (sp_reg == 8) prev = cpu->CRB;
            else if (sp_reg == 9) prev = cpu->UBT;
            else if (sp_reg == 10) prev = cpu->KBT;
            else if (sp_reg == 11) prev = cpu->UKS;
            else if (sp_reg == 12) prev = cpu->CURAPP;

            uint64_t n_val = prev;
            if (mode == 0) {
                n_val = (prev & 0xFFFFFFFF00000000ULL) | imm;
            } else if (mode == 1) {
                if (sp_reg <= 2 || (sp_reg >= 9 && sp_reg <= 11)) n_val = (prev & 0x00000000FFFFFFFFULL) | (((uint64_t)imm & 0xFF) << 32);
                else if (sp_reg == 3 || sp_reg == 5 || sp_reg == 7) n_val = (prev & 0x00000000FFFFFFFFULL) | ((uint64_t)imm << 32);
            } else if (mode == 2) {
                if (sp_reg <= 2 || (sp_reg >= 9 && sp_reg <= 11)) n_val = (((uint64_t)imm & 0xFF) << 32) | imm;
                else if (sp_reg == 3 || sp_reg == 5 || sp_reg == 7) n_val = ((uint64_t)imm << 32) | imm;
                else n_val = imm;
            }

            if (sp_reg == 0) cpu->BASE = n_val & ADDR_MASK;
            else if (sp_reg == 1) cpu->TTB = n_val & ADDR_MASK;
            else if (sp_reg == 2) cpu->ETB = n_val & ADDR_MASK;
            else if (sp_reg == 3) cpu->VIB = n_val;
            else if (sp_reg == 4) { cpu->EXCLK = (uint32_t)n_val; cpu->hidden_exclk = cpu->EXCLK; }
            else if (sp_reg == 5) cpu->CTCLK = n_val;
            else if (sp_reg == 6) cpu->TST = (uint32_t)n_val;
            else if (sp_reg == 7) cpu->CTCLKI = n_val;
            else if (sp_reg == 8) cpu->CRB = n_val & 0x7;
            else if (sp_reg == 9) cpu->UBT = n_val & ADDR_MASK;
            else if (sp_reg == 10) cpu->KBT = n_val & ADDR_MASK;
            else if (sp_reg == 11) cpu->UKS = n_val & ADDR_MASK;
            else if (sp_reg == 12) cpu->CURAPP = (uint32_t)n_val;

        } else if (op == 1) { // LFS
            uint8_t sp_reg = (data >> 34) & 0xFF;
            uint8_t a_reg = (data >> 26) & 0xFF;
            if (a_reg == 0) return;
            if (sp_reg == 0) ACC(cpu, a_reg) = cpu->BASE;
            else if (sp_reg == 1) ACC(cpu, a_reg) = cpu->TTB;
            else if (sp_reg == 2) ACC(cpu, a_reg) = cpu->ETB;
            else if (sp_reg == 3) ACC(cpu, a_reg) = cpu->VIB;
            else if (sp_reg == 4) ACC(cpu, a_reg) = cpu->EXCLK;
            else if (sp_reg == 5) ACC(cpu, a_reg) = cpu->CTCLK;
            else if (sp_reg == 6) ACC(cpu, a_reg) = cpu->TST;
            else if (sp_reg == 7) ACC(cpu, a_reg) = cpu->CTCLKI;
            else if (sp_reg == 8) ACC(cpu, a_reg) = cpu->CRB;
            else if (sp_reg == 9) ACC(cpu, a_reg) = cpu->UBT;
            else if (sp_reg == 10) ACC(cpu, a_reg) = cpu->KBT;
            else if (sp_reg == 11) ACC(cpu, a_reg) = cpu->UKS;
            else if (sp_reg == 12) ACC(cpu, a_reg) = cpu->CURAPP;

        } else if (op == 2) { // LSA
            uint8_t a_reg = (data >> 34) & 0xFF;
            uint8_t sp_reg = (data >> 26) & 0xFF;
            if (sp_reg == 0) cpu->BASE = ACC(cpu, a_reg) & ADDR_MASK;
            else if (sp_reg == 1) cpu->TTB = ACC(cpu, a_reg) & ADDR_MASK;
            else if (sp_reg == 2) cpu->ETB = ACC(cpu, a_reg) & ADDR_MASK;
            else if (sp_reg == 3) cpu->VIB = ACC(cpu, a_reg);
            else if (sp_reg == 4) { cpu->EXCLK = (uint32_t)ACC(cpu, a_reg); cpu->hidden_exclk = cpu->EXCLK; }
            else if (sp_reg == 5) cpu->CTCLK = ACC(cpu, a_reg);
            else if (sp_reg == 6) cpu->TST = (uint32_t)ACC(cpu, a_reg);
            else if (sp_reg == 7) cpu->CTCLKI = ACC(cpu, a_reg);
            else if (sp_reg == 8) cpu->CRB = ACC(cpu, a_reg) & 0x7;
            else if (sp_reg == 9) cpu->UBT = ACC(cpu, a_reg) & ADDR_MASK;
            else if (sp_reg == 10) cpu->KBT = ACC(cpu, a_reg) & ADDR_MASK;
            else if (sp_reg == 11) cpu->UKS = ACC(cpu, a_reg) & ADDR_MASK;
            else if (sp_reg == 12) cpu->CURAPP = (uint32_t)ACC(cpu, a_reg);

        } else if (op == 3) { // ERET
            cpu->PC = cpu->ERS;
            cpu->in_exception = 0;

        } else if (op == 4) { // EFLSH
            cpu->ERS = 0;

        } else if (op == 5) { // ESTCK
            cpu->estck = (data >> 34) & 0xFF;
        }

    } else if (dev == 0x01) { // MMU
        uint8_t op = (data >> 42) & 0xFF;
        if (op == 0) cpu->PC |= MMU_BIT;
        else if (op == 1) cpu->PC &= ~MMU_BIT;

    } else if (dev == 0x02) { // Teletype/Console
        uint8_t io_op = (data >> 46) & 0xF;
        uint8_t t     = (data >> 42) & 0xF;
        uint8_t r     = (data >> 41) & 0x1;
        uint8_t i_sel = (data >> 40) & 0x1;
        uint8_t x     = (data >> 32) & 0xFF;
        uint32_t m    = (uint32_t)(data & 0xFFFFFFFF);

        uint8_t actual_t = i_sel ? (uint8_t)(ACC(cpu, t) & 0x0F) : (t & 0x0F);

        if (io_op == 0) { // PRINTS
            uint64_t addr = get_ea(cpu, m, x, r, 0, 0, 3, current_pc);
            if (cpu->PC != current_pc) return;
            while (addr < MEMORY_SIZE) {
                char c = mem_read(cpu, addr++, 3, 1, 0);
                if (cpu->PC != current_pc) return;
                if (c == 0) break;
                if (actual_t == 0) putchar(c);
                else if (cpu->client_sockets[actual_t]) {
                    if (c == '\n') send(cpu->client_sockets[actual_t], "\r\n", 2, 0);
                    else send(cpu->client_sockets[actual_t], &c, 1, 0);
                }
            }
        } else if (io_op == 1) { // INPUT
            uint64_t addr = get_ea(cpu, m, x, r, 0, 0, 3, current_pc);
            if (cpu->PC != current_pc) return;
            char b[256];
            size_t len = 0;

            int i = 0, line_end = -1;
            for (int j=0; j < cpu->input_len[actual_t]; j++) {
                char c = cpu->input_buffer[actual_t][j];
                if (c == '\n') { line_end = j; break; }
                if (i < 255) b[i++] = c;
            }

            if (line_end != -1) {
                b[i] = 0; len = i;
                int remaining = cpu->input_len[actual_t] - (line_end + 1);
                if (remaining > 0) memmove(cpu->input_buffer[actual_t], &cpu->input_buffer[actual_t][line_end + 1], remaining);
                cpu->input_len[actual_t] = remaining;
            } else {
                b[0] = 0; len = 0;
            }

            for (size_t j=0; j<=len; j++) {
                mem_write(cpu, addr+j, b[j], 3, 1);
                if (cpu->PC != current_pc) return;
            }
            ACC(cpu, 255) = (uint64_t)len;

        } else if (io_op == 2) { // PRINTI
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
        } else if (io_op == 3) { // TSTAT
            int has_data = 0, is_connected = 0;
            if (actual_t == 0) {
                is_connected = 1;
                for(int j = 0; j < cpu->input_len[actual_t]; j++) {
                    if (cpu->input_buffer[actual_t][j] == '\n') { has_data = 1; break; }
                }
            } else {
                if (cpu->client_sockets[actual_t] != 0 && cpu->client_sockets[actual_t] != INVALID_SOCKET) {
                    is_connected = 1;
                    for(int j = 0; j < cpu->input_len[actual_t]; j++) {
                        if (cpu->input_buffer[actual_t][j] == '\n') { has_data = 1; break; }
                    }
                }
            }
            set_os1(cpu, has_data);
            set_os2(cpu, is_connected);
        }
        fflush(stdout);

    } else if (dev == 0x03) { // Extra Fast Tools
        uint8_t io_op = (data >> 42) & 0xFF;
        uint8_t src_reg = (data >> 34) & 0xFF;
        uint8_t dst_reg = (data >> 26) & 0xFF;
        uint8_t len_dst_reg = (data >> 18) & 0xFF;
        uint8_t w = (data >> 16) & 0x03;

        if (io_op == 0) { // ITOA
            int64_t val = (int64_t)ACC(cpu, src_reg);
            if (w == 1) val = (int64_t)(int32_t)val;
            else if (w == 2) val = (int64_t)(int16_t)val;
            else if (w == 3) val = (int64_t)(int8_t)val;

            char buf[64]; sprintf(buf, "%lld", val);
            uint64_t addr = ACC(cpu, dst_reg) & ADDR_MASK;
            size_t len = strlen(buf);

            for (size_t j=0; j<=len; j++) {
                mem_write(cpu, addr+j, buf[j], 3, 1);
                if (cpu->PC != current_pc) return;
            }
            if(len_dst_reg != 0) ACC(cpu, len_dst_reg) = len;

        } else if (io_op == 1) { // ATOI
            uint64_t addr = ACC(cpu, src_reg) & ADDR_MASK;
            char buf[256]; size_t i = 0;
            while(i < 255) {
                buf[i] = mem_read(cpu, addr+i, 3, 1, 0);
                if (cpu->PC != current_pc) return;
                if (buf[i] == 0) break;
                i++;
            }
            buf[i] = 0;
            int64_t val = (int64_t)strtoll(buf, NULL, 10);

            if (w == 1) val = (int64_t)(int32_t)val;
            else if (w == 2) val = (int64_t)(int16_t)val;
            else if (w == 3) val = (int64_t)(int8_t)val;
            if(dst_reg != 0) ACC(cpu, dst_reg) = (uint64_t)val;

        } else if (io_op == 2) { // FTOA
            double val = get_float(ACC(cpu, src_reg), w);
            char buf[64]; sprintf(buf, "%g", val);
            uint64_t addr = ACC(cpu, dst_reg) & ADDR_MASK;
            size_t len = strlen(buf);

            for (size_t j=0; j<=len; j++) {
                mem_write(cpu, addr+j, buf[j], 3, 1);
                if (cpu->PC != current_pc) return;
            }
            if(len_dst_reg != 0) ACC(cpu, len_dst_reg) = len;

        } else if (io_op == 3) { // ATOF
            uint64_t addr = ACC(cpu, src_reg) & ADDR_MASK;
            char buf[256]; size_t i = 0;
            while(i < 255) {
                buf[i] = mem_read(cpu, addr+i, 3, 1, 0);
                if (cpu->PC != current_pc) return;
                if (buf[i] == 0) break;
                i++;
            }
            buf[i] = 0;
            double val = strtod(buf, NULL);
            if(dst_reg != 0) ACC(cpu, dst_reg) = pack_float(val, w);

        } else if (io_op == 4) { // SPSP
            uint8_t c_reg = (data >> 8) & 0xFF;
            uint8_t y_flag = (data >> 7) & 0x1;
            uint64_t target_word = y_flag ? c_reg : ACC(cpu, c_reg);

            uint64_t src_addr = ACC(cpu, src_reg) & ADDR_MASK;
            uint64_t dst_addr = ACC(cpu, dst_reg) & ADDR_MASK;
            uint64_t current_word = 0;
            int in_word = 0, char_idx = 0, ext_len = 0;
            char extracted[256] = {0};

            while (char_idx < 4096) {
                char c = mem_read(cpu, src_addr + char_idx, 3, 1, 0);
                if (cpu->PC != current_pc) return;
                if (c == 0) break;

                if (c == ' ') {
                    if (in_word) {
                        in_word = 0;
                        if (current_word == target_word) break;
                        current_word++;
                    }
                } else {
                    if (!in_word) in_word = 1;
                    if (current_word == target_word && ext_len < 255) {
                        extracted[ext_len++] = c;
                    }
                }
                char_idx++;
            }
            extracted[ext_len] = '\0';
            for (int j = 0; j <= ext_len; j++) {
                mem_write(cpu, dst_addr + j, extracted[j], 3, 1);
                if (cpu->PC != current_pc) return;
            }
        }

    } else if (dev == 0x04) { // Tape Drive
        uint8_t io_op = (data >> 42) & 0xFF;
        uint8_t ind = (data >> 41) & 0x1;
        uint8_t tape_id = (data >> 38) & 0x7;
        uint8_t acc = (data >> 30) & 0xFF;
        uint8_t w = (data >> 28) & 0x3;
        uint8_t idx = (data >> 20) & 0xFF;
        uint32_t m_addr = data & 0xFFFFF;
        if (tape_id > 3) return;

        uint32_t tape_addr = (m_addr + (uint32_t)(ACC(cpu, idx) & 0xFFFFF)) & 0xFFFFF;
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
            if (f) { fseek(f, 1024*1024 - 1, SEEK_SET); fputc(0, f); }
        }

        if (f) {
            fseek(f, tape_addr, SEEK_SET);
            int bytes = (w==0)?8:(w==1)?4:(w==2)?2:1;

            if (io_op == 0) { // TWRITE
                uint64_t w_data = ind ? mem_read(cpu, ACC(cpu, acc) & ADDR_MASK, w, 1, 0) : ACC(cpu, acc);
                if (cpu->PC != current_pc) { fclose(f); return; }
                fwrite(&w_data, 1, bytes, f);
            } else if (io_op == 1) { // TREAD
                uint64_t r_data = 0;
                fread(&r_data, 1, bytes, f);

                if (ind) {
                    mem_write(cpu, ACC(cpu, acc) & ADDR_MASK, r_data, w, 1);
                    if (cpu->PC != current_pc) { fclose(f); return; }
                } else if (acc != 0) {
                    if (w == 0) ACC(cpu, acc) = r_data;
                    else if (w == 1) ACC(cpu, acc) = (ACC(cpu, acc) & 0xFFFFFFFF00000000ULL) | (r_data & 0xFFFFFFFF);
                    else if (w == 2) ACC(cpu, acc) = (ACC(cpu, acc) & 0xFFFFFFFFFFFF0000ULL) | (r_data & 0xFFFF);
                    else ACC(cpu, acc) = (ACC(cpu, acc) & 0xFFFFFFFFFFFFFF00ULL) | (r_data & 0xFF);
                }
            }
            fclose(f);
        }

    } else if (dev == 0x05) { // Disk Drive
        uint8_t w = (data >> 48) & 0x3;
        uint8_t d_op = (data >> 44) & 0xF;
        uint8_t a = (data >> 36) & 0xFF;
        uint8_t ind = (data >> 35) & 0x1;
        uint8_t d = (data >> 27) & 0xFF;
        uint8_t r = (data >> 26) & 0x1;
        uint8_t l = (data >> 18) & 0xFF;

        uint8_t disk_id = r ? (d & 0xF) : (ACC(cpu, d) & 0xF);
        uint64_t loc = ACC(cpu, l) & 0xFFFFFFFFULL;

        char filename[256];
        if (cpu->disk_files[disk_id][0] != '\0') {
            strncpy(filename, cpu->disk_files[disk_id], 255);
            filename[255] = '\0';
        } else {
            sprintf(filename, "disk%d.img", disk_id);
        }

        FILE *f = fopen(filename, "r+b");
        if (!f) f = fopen(filename, "w+b");

        if (f) {
            fseek(f, loc, SEEK_SET);
            int bytes = (w==0)?8:(w==1)?4:(w==2)?2:1;

            if (d_op == 0) { // READ
                uint64_t r_data = 0;
                fread(&r_data, 1, bytes, f);

                if (ind) {
                    mem_write(cpu, ACC(cpu, a) & ADDR_MASK, r_data, w, 1);
                    if (cpu->PC != current_pc) { fclose(f); return; }
                } else if (a != 0) {
                    if (w == 0) ACC(cpu, a) = r_data;
                    else if (w == 1) ACC(cpu, a) = (ACC(cpu, a) & 0xFFFFFFFF00000000ULL) | (r_data & 0xFFFFFFFF);
                    else if (w == 2) ACC(cpu, a) = (ACC(cpu, a) & 0xFFFFFFFFFFFF0000ULL) | (r_data & 0xFFFF);
                    else ACC(cpu, a) = (ACC(cpu, a) & 0xFFFFFFFFFFFFFF00ULL) | (r_data & 0xFF);
                }
            } else if (d_op == 1) { // WRITE
                uint64_t w_data = ind ? mem_read(cpu, ACC(cpu, a) & ADDR_MASK, w, 1, 0) : ACC(cpu, a);
                if (cpu->PC != current_pc) { fclose(f); return; }
                fwrite(&w_data, 1, bytes, f);
            }
            fclose(f);
        }

    } else if (dev == 0x07) { // Graphics Network VDP
        uint8_t o_op = (data >> 46) & 0xF;
        uint8_t s_id = (data >> 42) & 0xF;
        uint8_t a_reg = (data >> 34) & 0xFF;
        uint8_t i_flag = (data >> 33) & 0x1;
        uint64_t arg_val = i_flag ? a_reg : ACC(cpu, a_reg);

        if (o_op == 0) cpu->vbase[s_id] = arg_val & ADDR_MASK;
        else if (o_op == 1) cpu->vmode[s_id] = (uint8_t)(arg_val & 0x3);
        else if (o_op == 2) send_vframe(cpu, s_id);
        else if (o_op == 3) ACC(cpu, a_reg) = (GetTickCount64() - cpu->gpu_last_ping[s_id] < 5000) ? 1 : 0;
    }
}

// --- SIMD Lane Helpers ---
static inline uint64_t extract_lane(uint64_t vec, uint8_t w, int k) {
    if (w == 0) return vec;
    if (w == 1) return (vec >> (32 * k)) & 0xFFFFFFFFULL;
    if (w == 2) return (vec >> (16 * k)) & 0xFFFFULL;
    return (vec >> (8 * k)) & 0xFFULL;
}

// --- Execution Core ---
void step(XDP64 *cpu) {
    if (cpu->step_count % 128 == 0) poll_network(cpu);

    ACC(cpu, 0) = 0;

    uint64_t pc_val = get_pc(cpu);
    uint64_t instr;

    int is_user = (cpu->PC & MMU_BIT) && (pc_val < cpu->UKS);
    int priv_allowed = !is_user || (cpu->PC & PRIV_BIT);
    uint64_t current_pc = cpu->PC;

    if (cpu->rep_count > 0) {
        instr = cpu->loop_buffer[cpu->rep_idx++];
        if (cpu->rep_idx >= cpu->rep_len) {
            cpu->rep_idx = 0;
            cpu->rep_count--;
        }
    } else {
        instr = mem_read(cpu, pc_val, 0, 1, 2);
        if (cpu->PC != current_pc) return;
        cpu->PC = (cpu->PC & SYS_MASK) | ((pc_val + 8) & ADDR_MASK);
        current_pc = cpu->PC;
    }

    cpu->current_instr = instr;

    if (cpu->log_file) {
        fprintf(cpu->log_file, "[Step %08llu] PC: %010llX | Instr: %016llX | Opcode: %llu\n",
                cpu->step_count, pc_val, instr, (instr >> 54) & 0x3FF);
        fflush(cpu->log_file);
    }

    cpu->step_count++;

    if ((instr >> 58) == 0x3F) {
        uint8_t dev = (instr >> 50) & 0xFF;
        if ((dev == 0 || dev == 1 || dev == 2 || dev == 5 || dev == 6 || dev == 7) && !priv_allowed) {
            trigger_exception(cpu, 5);
            return;
        }
        handle_io(cpu, instr, current_pc);
    } else {
        uint16_t op = (instr >> 54) & 0x3FF;

        if (op == 1 && !priv_allowed) { trigger_exception(cpu, 5); return; }

        if (op == 64) { // LDI
            uint8_t reg = (instr >> 46) & 0xFF;
            if (reg != 0) {
                uint8_t mode = (instr >> 44) & 0x3;
                uint32_t imm = (uint32_t)(instr & 0xFFFFFFFF);
                if (mode == 0) ACC(cpu, reg) = (ACC(cpu, reg) & 0xFFFFFFFF00000000ULL) | imm;
                else if (mode == 1) ACC(cpu, reg) = (ACC(cpu, reg) & 0x00000000FFFFFFFFULL) | ((uint64_t)imm << 32);
                else if (mode == 2) ACC(cpu, reg) = ((uint64_t)imm << 32) | imm;
            }
        }
        else if (op == 65) { // TRAP / TRET
            uint8_t a = (instr >> 46) & 0xFF;
            uint8_t t = (instr >> 45) & 1;

            if (t == 0) { // TRAP
                if ((cpu->PC & MMU_BIT) && cpu->estck != 0 && a != cpu->estck) {
                    a = cpu->estck;
                }
                uint8_t imm8 = instr & 0xFF;
                ACC(cpu, a) -= 8;
                if(a == 0) ACC(cpu, 0) = 0;

                mem_write(cpu, ACC(cpu, a) & ADDR_MASK, get_pc(cpu), 0, 1);
                if (cpu->PC != current_pc) return;

                uint64_t target = mem_read(cpu, (cpu->TTB + (imm8 * 8)) & ADDR_MASK, 0, 1, 0);
                if (cpu->PC != current_pc) return;

                DO_JMP(target, 1);
            } else { // TRET
                uint64_t rv = mem_read(cpu, ACC(cpu, a) & ADDR_MASK, 0, 1, 0);
                if (cpu->PC != current_pc) return;

                ACC(cpu, a) += 8;
                if(a == 0) ACC(cpu, 0) = 0;

                DO_JMP(rv, 1);
            }
        }
        else if (op == 66) { // ADI
            uint8_t a = (instr >> 46) & 0xFF;
            if (a != 0) {
                uint8_t h = (instr >> 45) & 1;
                uint32_t imm32 = (uint32_t)(instr & 0xFFFFFFFF);
                if (h) ACC(cpu, a) += ((uint64_t)imm32 << 32);
                else ACC(cpu, a) += imm32;
            }
        }
        else if (op == 88) { // REP
            uint8_t r = (instr >> 46) & 0xFF, i_flag = (instr >> 45) & 1;
            uint8_t a_reg = (instr >> 37) & 0xFF, f_flag = (instr >> 36) & 1;
            uint64_t count = i_flag ? r : ACC(cpu, r);
            uint64_t len = f_flag ? a_reg : ACC(cpu, a_reg);

            if (len > 32) len = 32;

            if (len > 0 && count > 0) {
                for (uint32_t k = 0; k < len; k++) {
                    cpu->loop_buffer[k] = mem_read(cpu, get_pc(cpu) + k*8, 0, 1, 2);
                    if (cpu->PC != current_pc) return;
                }
                cpu->PC = (cpu->PC & SYS_MASK) | ((get_pc(cpu) + len*8) & ADDR_MASK);
                cpu->rep_count = count;
                cpu->rep_len = len;
                cpu->rep_idx = 0;
            } else if (len > 0) {
                cpu->PC = (cpu->PC & SYS_MASK) | ((get_pc(cpu) + len*8) & ADDR_MASK);
            }
        }
        else if (op == 89) { // BCOPY
            uint8_t w_b = (instr >> 52) & 0x3, a_reg = (instr >> 44) & 0xFF;
            uint8_t b_reg = (instr >> 36) & 0xFF, c_reg = (instr >> 28) & 0xFF, i_flag = (instr >> 27) & 1;
            uint64_t count = i_flag ? c_reg : ACC(cpu, c_reg);
            uint64_t bytes = (w_b == 0) ? 8 : (w_b == 1) ? 4 : (w_b == 2) ? 2 : 1;

            for (uint64_t k = 0; k < count; k++) {
                uint64_t src_addr = ACC(cpu, a_reg) + k*bytes;
                uint64_t dst_addr = ACC(cpu, b_reg) + k*bytes;
                uint64_t v = mem_read(cpu, src_addr, w_b, 1, 0);
                if (cpu->PC != current_pc) return;

                mem_write(cpu, dst_addr, v, w_b, 1);
                if (cpu->PC != current_pc) return;
            }
        }
        else if (op == 90) { // BSET
            uint8_t a_val = (instr >> 46) & 0xFF, b_reg = (instr >> 38) & 0xFF;
            uint8_t c_reg = (instr >> 30) & 0xFF, i_flag = (instr >> 29) & 1;
            uint64_t count = i_flag ? c_reg : ACC(cpu, c_reg);

            for (uint64_t k = 0; k < count; k++) {
                uint64_t dst_addr = ACC(cpu, b_reg) + k;
                mem_write(cpu, dst_addr, a_val, 3, 1);
                if (cpu->PC != current_pc) return;
            }
        }
        else if (op == 94) { // BSTR
            uint8_t w_b = (instr >> 52) & 0x3, a_reg = (instr >> 44) & 0xFF;
            uint8_t b_reg = (instr >> 36) & 0xFF, c_reg = (instr >> 28) & 0xFF, i_flag = (instr >> 27) & 1;
            uint64_t count = i_flag ? c_reg : ACC(cpu, c_reg);
            uint64_t bytes = (w_b == 0) ? 8 : (w_b == 1) ? 4 : (w_b == 2) ? 2 : 1;
            uint64_t val = ACC(cpu, a_reg);

            for (uint64_t k = 0; k < count; k++) {
                uint64_t dst_addr = ACC(cpu, b_reg) + k*bytes;
                mem_write(cpu, dst_addr, val, w_b, 1);
                if (cpu->PC != current_pc) return;
            }
        }
        else if (op == 95) { // 3OPMATH
            uint8_t op3 = (instr >> 49) & 0x1F, w_b = (instr >> 47) & 0x3;
            uint8_t a = (instr >> 39) & 0xFF, b = (instr >> 31) & 0xFF;
            uint8_t c = (instr >> 23) & 0xFF, d = (instr >> 15) & 0xFF;

            uint64_t va = ACC(cpu, a);
            uint64_t vb = ACC(cpu, b);

            if (op3 == 0) { // TADD
                ACC(cpu, c) = va + vb;
            } else if (op3 == 1) { // TSUB
                ACC(cpu, c) = va - vb;
            } else if (op3 == 2) { // TMUL
                ACC(cpu, c) = va * vb;
            } else if (op3 == 3) { // TDIV
                if (vb == 0) { trigger_exception(cpu, 0); return; }
                ACC(cpu, c) = va / vb;
                ACC(cpu, d) = va % vb;
            } else if (op3 == 4) { // TFAD
                ACC(cpu, c) = pack_float(get_float(va, w_b) + get_float(vb, w_b), w_b);
            } else if (op3 == 5) { // TFSB
                ACC(cpu, c) = pack_float(get_float(va, w_b) - get_float(vb, w_b), w_b);
            } else if (op3 == 6) { // TFML
                ACC(cpu, c) = pack_float(get_float(va, w_b) * get_float(vb, w_b), w_b);
            } else if (op3 == 7) { // TFDV
                double fb = get_float(vb, w_b);
                if (fb == 0.0) { trigger_exception(cpu, 0); return; }
                ACC(cpu, c) = pack_float(get_float(va, w_b) / fb, w_b);
            } else if (op3 == 8) { // TXP
                uint64_t base = va, exp = vb, res = 1;
                while (exp > 0) {
                    if (exp % 2 == 1) res *= base;
                    base *= base;
                    exp /= 2;
                }
                ACC(cpu, c) = res;
            } else if (op3 == 9) { // TFXP
                ACC(cpu, c) = pack_float(pow(get_float(va, w_b), get_float(vb, w_b)), w_b);
            }
        }
        else if (op == 96) { // SIMD
            uint8_t sop = (instr >> 48) & 0x3F;
            uint8_t w_b = (instr >> 46) & 0x3;
            uint8_t a = (instr >> 38) & 0xFF;
            uint8_t b = (instr >> 30) & 0xFF;
            uint8_t c = (instr >> 22) & 0xFF;

            uint8_t iii = (instr >> 19) & 0x7;
            int ia = (iii >> 2) & 1;
            int ib = (iii >> 1) & 1;
            int ic = iii & 1;

            uint64_t va = ia ? mem_read(cpu, ACC(cpu, a) & ~7ULL, 0, 1, 0) : ACC(cpu, a);
            uint64_t vb = ib ? mem_read(cpu, ACC(cpu, b) & ~7ULL, 0, 1, 0) : ACC(cpu, b);
            if (cpu->PC != current_pc) return;

            uint64_t vc = 0;
            int lanes = (w_b == 0) ? 1 : (w_b == 1) ? 2 : (w_b == 2) ? 4 : 8;
            uint64_t mask = (w_b == 0) ? 0xFFFFFFFFFFFFFFFFULL : (w_b == 1) ? 0xFFFFFFFFULL : (w_b == 2) ? 0xFFFFULL : 0xFFULL;

            if (sop >= 14 && sop <= 17) {
                if (sop == 14) vc = va & vb; // VAND
                else if (sop == 15) vc = va | vb; // VOR
                else if (sop == 16) vc = va ^ vb; // VXOR
                else if (sop == 17) vc = ~va; // VNOT
            } else {
                double fsum = 0.0;
                int64_t isum = 0;

                for (int k = 0; k < lanes; k++) {
                    int shift = ((w_b == 0) ? 0 : (w_b == 1) ? 32 : (w_b == 2) ? 16 : 8) * k;
                    uint64_t la = (va >> shift) & mask;
                    uint64_t lb = (vb >> shift) & mask;
                    uint64_t lc = 0;

                    if (sop == 0) { // VFAD
                        lc = pack_float(get_float(la, w_b) + get_float(lb, w_b), w_b);
                    } else if (sop == 1) { // VFSB
                        lc = pack_float(get_float(la, w_b) - get_float(lb, w_b), w_b);
                    } else if (sop == 2) { // VFML
                        lc = pack_float(get_float(la, w_b) * get_float(lb, w_b), w_b);
                    } else if (sop == 3) { // VFDV
                        double flb = get_float(lb, w_b);
                        if (flb == 0.0) { trigger_exception(cpu, 0); return; }
                        lc = pack_float(get_float(la, w_b) / flb, w_b);
                    } else if (sop == 4) { // VADD
                        lc = la + lb;
                    } else if (sop == 5) { // VSUB
                        lc = la - lb;
                    } else if (sop == 6) { // VDOT
                        int64_t sla = la, slb = lb;
                        if (w_b == 1) { sla = (int32_t)la; slb = (int32_t)lb; }
                        else if (w_b == 2) { sla = (int16_t)la; slb = (int16_t)lb; }
                        else if (w_b == 3) { sla = (int8_t)la; slb = (int8_t)lb; }
                        isum += sla * slb;
                    } else if (sop == 7) { // VFDOT
                        fsum += get_float(la, w_b) * get_float(lb, w_b);
                    } else if (sop == 8 || sop == 9) { // VLRP, VFLRP
                        double t = get_float(ACC(cpu, 255), w_b);
                        if (sop == 8) lc = (uint64_t)((double)la + ((double)lb - (double)la) * t);
                        else lc = pack_float(get_float(la, w_b) + (get_float(lb, w_b) - get_float(la, w_b)) * t, w_b);
                    } else if (sop == 10) { // VFMAX
                        lc = pack_float(fmax(get_float(la, w_b), get_float(lb, w_b)), w_b);
                    } else if (sop == 11) { // VMAX
                        int64_t sla = la, slb = lb;
                        if (w_b == 1) { sla = (int32_t)la; slb = (int32_t)lb; }
                        else if (w_b == 2) { sla = (int16_t)la; slb = (int16_t)lb; }
                        else if (w_b == 3) { sla = (int8_t)la; slb = (int8_t)lb; }
                        lc = (sla > slb) ? la : lb;
                    } else if (sop == 12) { // VFMIN
                        lc = pack_float(fmin(get_float(la, w_b), get_float(lb, w_b)), w_b);
                    } else if (sop == 13) { // VMIN
                        int64_t sla = la, slb = lb;
                        if (w_b == 1) { sla = (int32_t)la; slb = (int32_t)lb; }
                        else if (w_b == 2) { sla = (int16_t)la; slb = (int16_t)lb; }
                        else if (w_b == 3) { sla = (int8_t)la; slb = (int8_t)lb; }
                        lc = (sla < slb) ? la : lb;
                    } else if (sop == 18) { // VCEQ
                        lc = (la == lb) ? mask : 0;
                    } else if (sop == 19) { // VCGT
                        int64_t sla = la, slb = lb;
                        if (w_b == 1) { sla = (int32_t)la; slb = (int32_t)lb; }
                        else if (w_b == 2) { sla = (int16_t)la; slb = (int16_t)lb; }
                        else if (w_b == 3) { sla = (int8_t)la; slb = (int8_t)lb; }
                        lc = (sla > slb) ? mask : 0;
                    } else if (sop == 20) { // VCLT
                        int64_t sla = la, slb = lb;
                        if (w_b == 1) { sla = (int32_t)la; slb = (int32_t)lb; }
                        else if (w_b == 2) { sla = (int16_t)la; slb = (int16_t)lb; }
                        else if (w_b == 3) { sla = (int8_t)la; slb = (int8_t)lb; }
                        lc = (sla < slb) ? mask : 0;
                    } else if (sop == 21) { // VBRD
                        lc = va & mask;
                    } else if (sop == 22) { // VSHF
                        int idx = lb % lanes;
                        int s2 = ((w_b == 0) ? 0 : (w_b == 1) ? 32 : (w_b == 2) ? 16 : 8) * idx;
                        lc = (va >> s2) & mask;
                    }

                    if (sop == 6) { // Accum VDOT
                        vc = isum;
                    } else if (sop == 7) { // Accum VFDOT
                        vc = pack_float(fsum, w_b);
                    } else if (sop != 23) { // Pack standard result
                        vc |= (lc & mask) << shift;
                    }
                }

                if (sop == 23) { // VPACK
                    uint8_t out_w = (w_b == 0) ? 1 : (w_b == 1) ? 2 : 3;
                    int in_shift = (w_b == 0) ? 0 : (w_b == 1) ? 32 : (w_b == 2) ? 16 : 8;
                    int out_shift = (out_w == 1) ? 32 : (out_w == 2) ? 16 : 8;
                    uint64_t out_mask = (out_w == 1) ? 0xFFFFFFFFULL : (out_w == 2) ? 0xFFFFULL : 0xFFULL;

                    for(int k = 0; k < lanes; k++) {
                        uint64_t la = (va >> (k * in_shift)) & mask;
                        uint64_t lb = (vb >> (k * in_shift)) & mask;
                        vc |= (la & out_mask) << (k * out_shift);
                        vc |= (lb & out_mask) << ((k + lanes) * out_shift);
                    }
                }
            }

            if (ic) {
                mem_write(cpu, ACC(cpu, c) & ~7ULL, vc, 0, 1);
            } else {
                ACC(cpu, c) = vc;
            }
        }
        else {
            uint8_t  a  = (instr >> 46) & 0xFF, i  = (instr >> 45) & 0x1, x  = (instr >> 37) & 0xFF;
            uint8_t  w  = (instr >> 35) & 0x3, r  = (instr >> 34) & 0x1, p  = (instr >> 32) & 0x3;
            uint32_t m  = (uint32_t)(instr & 0xFFFFFFFF);

            uint64_t ea = get_ea(cpu, m, x, r, p, i, w, current_pc);
            if (cpu->PC != current_pc) return;

            uint64_t val = mem_read(cpu, ea, w, i, 0);
            if (cpu->PC != current_pc) return;
            uint64_t w_sz = (w == 0) ? 8 : (w == 1) ? 4 : (w == 2) ? 2 : 1;

            switch (op) {
                case 0:  break;                  // NOP
                case 1:  cpu->halted = 1; break; // HLT
                case 2:  if(a!=0) ACC(cpu, a) = val; break; // LDR
                case 3:  mem_write(cpu, ea, ACC(cpu, a), w, i); break; // STR
                case 4:  { uint64_t t = ACC(cpu, a); if(a!=0) ACC(cpu, a) = val; mem_write(cpu, ea, t, w, i); } break; // XCH
                case 5:  mem_write(cpu, ea, ACC(cpu, a) | val, w, i); break; // ORL
                case 6:  mem_write(cpu, ea, ACC(cpu, a) & val, w, i); break; // AND
                case 7:  mem_write(cpu, ea, ~ACC(cpu, a), w, i); break;      // NOT
                case 8:  { uint64_t s = val + ACC(cpu, a); mem_write(cpu, ea, s, w, i); set_ovf(cpu, s < val); } break; // ADD
                case 9:  mem_write(cpu, ea, val - ACC(cpu, a), w, i); break; // SUB
                case 10: { ACC(cpu, a) -= 8; if(a==0) ACC(cpu, 0)=0; mem_write(cpu, ACC(cpu, a) & ADDR_MASK, val, 0, 1); } break; // PUSH
                case 11: { uint64_t v = mem_read(cpu, ACC(cpu, a) & ADDR_MASK, 0, 1, 0); if (cpu->PC != current_pc) return; mem_write(cpu, ea, v, w, i); ACC(cpu, a) += 8; if(a==0) ACC(cpu, 0)=0; } break; // POP

                // Skips
                case 12: if(ACC(cpu, a) == val) cpu->PC += 8; break; // SKE
                case 13: if(ACC(cpu, a) != val) cpu->PC += 8; break; // SNE
                case 14: if(ACC(cpu, a) >  val) cpu->PC += 8; break; // SGT
                case 15: if(ACC(cpu, a) <  val) cpu->PC += 8; break; // SLT
                case 16: if(ACC(cpu, a) >= val) cpu->PC += 8; break; // SGE
                case 17: if(ACC(cpu, a) <= val) cpu->PC += 8; break; // SLE

                // Jumps
                case 18: DO_JMP(ea, i); break; // JMP
                case 19: if(ACC(cpu, a) == 0) DO_JMP(ea, i); break; // JIZ
                case 20: if(ACC(cpu, a) != 0) DO_JMP(ea, i); break; // JNZ
                case 21: if(ACC(cpu, a) & 0x8000000000000000ULL) DO_JMP(ea, i); break; // JIN
                case 22: if(!(ACC(cpu, a) & 0x8000000000000000ULL)) DO_JMP(ea, i); break; // JIP
                case 23: if(!(ACC(cpu, a) & 0x8000000000000000ULL) && ACC(cpu, a) != 0) DO_JMP(ea, i); break; // JGZ
                case 24: { ACC(cpu, a) -= 8; if(a==0) ACC(cpu, 0)=0; mem_write(cpu, ACC(cpu, a) & ADDR_MASK, get_pc(cpu), 0, 1); if (cpu->PC == current_pc) DO_JMP(ea, i); } break; // PUSHJ
                case 25: { uint64_t rv = mem_read(cpu, ACC(cpu, a) & ADDR_MASK, 0, 1, 0); if (cpu->PC != current_pc) return; ACC(cpu, a) += 8; if(a==0) ACC(cpu, 0)=0; if(rv != 0) DO_JMP(rv, 1); } break; // POPJ
                case 26: { if((get_st_low8(cpu) & a) == a) DO_JMP(ea, i); } break; // JIC
                case 27: { uint64_t mt = ACC(cpu, a) * val; mem_write(cpu, ea, mt, w, i); set_ovf(cpu, val != 0 && (mt / val != ACC(cpu, a))); } break; // MUL
                case 28: { cpu->PC |= (((uint64_t)a & 0xFF) << 40); DO_JMP(ea, i); } break; // JAS

                // Arithmetic Skips
                case 29: { uint64_t r0 = val + ACC(cpu, a); mem_write(cpu, ea, r0, w, i); if(a) ACC(cpu, a) = r0; } break;
                case 30: { uint64_t r0 = val + ACC(cpu, a); mem_write(cpu, ea, r0, w, i); if(a) ACC(cpu, a) = r0; if((int64_t)r0 < 0) cpu->PC += 8; } break;
                case 31: { uint64_t r0 = val + ACC(cpu, a); mem_write(cpu, ea, r0, w, i); if(a) ACC(cpu, a) = r0; if((int64_t)r0 <= 0) cpu->PC += 8; } break;
                case 32: { uint64_t r0 = val + ACC(cpu, a); mem_write(cpu, ea, r0, w, i); if(a) ACC(cpu, a) = r0; if(r0 == 0) cpu->PC += 8; } break;
                case 33: { uint64_t r0 = val + ACC(cpu, a); mem_write(cpu, ea, r0, w, i); if(a) ACC(cpu, a) = r0; if(r0 != 0) cpu->PC += 8; } break;
                case 34: { uint64_t r0 = val + ACC(cpu, a); mem_write(cpu, ea, r0, w, i); if(a) ACC(cpu, a) = r0; if((int64_t)r0 > 0) cpu->PC += 8; } break;
                case 35: { uint64_t r0 = val + ACC(cpu, a); mem_write(cpu, ea, r0, w, i); if(a) ACC(cpu, a) = r0; if((int64_t)r0 >= 0) cpu->PC += 8; } break;
                case 36: { uint64_t r0 = val + ACC(cpu, a); mem_write(cpu, ea, r0, w, i); if(a) ACC(cpu, a) = r0; cpu->PC += 8; } break;

                // Skip/Decrement Skips
                case 37: { uint64_t r0 = val - ACC(cpu, a); mem_write(cpu, ea, r0, w, i); if(a) ACC(cpu, a) = r0; } break;
                case 38: { uint64_t r0 = val - ACC(cpu, a); mem_write(cpu, ea, r0, w, i); if(a) ACC(cpu, a) = r0; if((int64_t)r0 < 0) cpu->PC += 8; } break;
                case 39: { uint64_t r0 = val - ACC(cpu, a); mem_write(cpu, ea, r0, w, i); if(a) ACC(cpu, a) = r0; if((int64_t)r0 <= 0) cpu->PC += 8; } break;
                case 40: { uint64_t r0 = val - ACC(cpu, a); mem_write(cpu, ea, r0, w, i); if(a) ACC(cpu, a) = r0; if(r0 == 0) cpu->PC += 8; } break;
                case 41: { uint64_t r0 = val - ACC(cpu, a); mem_write(cpu, ea, r0, w, i); if(a) ACC(cpu, a) = r0; if(r0 != 0) cpu->PC += 8; } break;
                case 42: { uint64_t r0 = val - ACC(cpu, a); mem_write(cpu, ea, r0, w, i); if(a) ACC(cpu, a) = r0; if((int64_t)r0 > 0) cpu->PC += 8; } break;
                case 43: { uint64_t r0 = val - ACC(cpu, a); mem_write(cpu, ea, r0, w, i); if(a) ACC(cpu, a) = r0; if((int64_t)r0 >= 0) cpu->PC += 8; } break;
                case 44: { uint64_t r0 = val - ACC(cpu, a); mem_write(cpu, ea, r0, w, i); if(a) ACC(cpu, a) = r0; cpu->PC += 8; } break;

                // ISA Expansions
                case 45: mem_write(cpu, ea, ACC(cpu, a) ^ val, w, i); break; // XOR
                case 46: { uint64_t v = ACC(cpu, a); if (w == 0) v = SWAP64(v); else if (w == 1) v = SWAP32(v); else if (w == 2) v = SWAP16(v); mem_write(cpu, ea, v, w, i); } break; // EDS
                case 47: { if (val == 0) { trigger_exception(cpu, 0); break; } mem_write(cpu, ea, ACC(cpu, a) / val, w, i); if (cpu->PC == current_pc) mem_write(cpu, (ea + w_sz) & ADDR_MASK, ACC(cpu, a) % val, w, i); } break; // DIV
                case 48: if(a) ACC(cpu, a) = ACC(cpu, a) << (ea & 63); break; // LSLI
                case 49: if(a) ACC(cpu, a) = ACC(cpu, a) >> (ea & 63); break; // LSRI
                case 50: if(a) ACC(cpu, a) = ACC(cpu, a) << (val & 63); break; // LSL
                case 51: if(a) ACC(cpu, a) = ACC(cpu, a) >> (val & 63); break; // LSR
                case 52: if(a) ACC(cpu, a) = ACC(cpu, a) << (ea & 63); break; // ASLI
                case 53: if(a) ACC(cpu, a) = (uint64_t)(((int64_t)ACC(cpu, a)) >> (ea & 63)); break; // ASRI
                case 54: if(a) ACC(cpu, a) = ACC(cpu, a) << (val & 63); break; // ASL
                case 55: if(a) ACC(cpu, a) = (uint64_t)(((int64_t)ACC(cpu, a)) >> (val & 63)); break; // ASR
                case 56: { uint8_t s=ea&63; if(a) ACC(cpu, a) = (ACC(cpu, a)<<s) | (ACC(cpu, a)>>(64-s)); } break; // ROLI
                case 57: { uint8_t s=ea&63; if(a) ACC(cpu, a) = (ACC(cpu, a)>>s) | (ACC(cpu, a)<<(64-s)); } break; // RORI
                case 58: { uint8_t s=val&63; if(a) ACC(cpu, a) = (ACC(cpu, a)<<s) | (ACC(cpu, a)>>(64-s)); } break; // ROL
                case 59: { uint8_t s=val&63; if(a) ACC(cpu, a) = (ACC(cpu, a)>>s) | (ACC(cpu, a)<<(64-s)); } break; // ROR

                case 60: case 61: case 62: case 63: { // FLOAT MATH
                    double res = 0, d_reg = get_float(ACC(cpu, a), w), d_mem = get_float(val, w);
                    if (op == 60) res = d_reg + d_mem;
                    else if (op == 61) res = d_reg - d_mem;
                    else if (op == 62) res = d_reg * d_mem;
                    else if (op == 63) { if (d_mem == 0.0) { trigger_exception(cpu, 0); break; } res = d_reg / d_mem; }

                    if (isnan(res) || isinf(res)) { trigger_exception(cpu, 0); break; }
                    mem_write(cpu, ea, pack_float(res, w), w, i);
                } break;

                case 67: { cpu->PC &= ~(((uint64_t)a & 0xFF) << 40); DO_JMP(ea, i); } break; // JAC
                case 68: { if ((get_st_low8(cpu) & a) == a) { cpu->PC &= ~(((uint64_t)a & 0xFF) << 40); DO_JMP(ea, i); } } break; // JCC
                case 69: { if (get_st_low8(cpu) == a) DO_JMP(ea, i); } break; // JISC

                // --- MATH & FPU EXPANSIONS ---
                case 70: mem_write(cpu, ea, pack_float(sin(get_float(ACC(cpu, a), w)), w), w, i); break; // SIN
                case 71: mem_write(cpu, ea, pack_float(cos(get_float(ACC(cpu, a), w)), w), w, i); break; // COS
                case 72: mem_write(cpu, ea, pack_float(tan(get_float(ACC(cpu, a), w)), w), w, i); break; // TAN
                case 73: { double d = get_float(ACC(cpu, a), w); if (d < 0) trigger_exception(cpu, 0); else mem_write(cpu, ea, pack_float(sqrt(d), w), w, i); } break; // SQRT
                case 74: { if (val == 0) trigger_exception(cpu, 0); else mem_write(cpu, ea, ACC(cpu, a) % val, w, i); } break; // MOD
                case 75: { double fM = get_float(val, w); if (fM == 0.0) trigger_exception(cpu, 0); else mem_write(cpu, ea, pack_float(fmod(get_float(ACC(cpu, a), w), fM), w), w, i); } break; // FMOD
                case 76: mem_write(cpu, ea, pack_float(floor(get_float(ACC(cpu, a), w)), w), w, i); break; // FLOOR
                case 77: mem_write(cpu, ea, pack_float(ceil(get_float(ACC(cpu, a), w)), w), w, i); break; // CEIL
                case 78: { uint64_t v = ACC(cpu, a); mem_write(cpu, ea, v * v * v, w, i); } break; // CUBE
                case 79: { uint64_t v = ACC(cpu, a); mem_write(cpu, ea, v * v, w, i); } break; // SQ
                case 80: { double v = get_float(ACC(cpu, a), w); mem_write(cpu, ea, pack_float(v * v * v, w), w, i); } break; // FCUB
                case 81: { double v = get_float(ACC(cpu, a), w); mem_write(cpu, ea, pack_float(v * v, w), w, i); } break; // FSQ
                case 82: { double v = get_float(ACC(cpu, a), w); if(w <= 1) v = nextafter(v, INFINITY); else if(w == 2) v += 0.001; else v += 0.015625; mem_write(cpu, ea, pack_float(v, w), w, i); } break; // FINC
                case 83: { double v = get_float(ACC(cpu, a), w); if(w <= 1) v = nextafter(v, -INFINITY); else if(w == 2) v -= 0.001; else v -= 0.015625; mem_write(cpu, ea, pack_float(v, w), w, i); } break; // FDEC
                case 84: { int64_t sa = ACC(cpu, a), sv = val; if (w == 1) { sa = (int32_t)sa; sv = (int32_t)sv; } else if (w == 2) { sa = (int16_t)sa; sv = (int16_t)sv; } else if (w == 3) { sa = (int8_t)sa; sv = (int8_t)sv; } mem_write(cpu, ea, (sa > sv) ? ACC(cpu, a) : val, w, i); } break; // MAX
                case 85: mem_write(cpu, ea, pack_float(fmax(get_float(ACC(cpu, a), w), get_float(val, w)), w), w, i); break; // FMAX
                case 86: { int64_t sa = ACC(cpu, a), sv = val; if (w == 1) { sa = (int32_t)sa; sv = (int32_t)sv; } else if (w == 2) { sa = (int16_t)sa; sv = (int16_t)sv; } else if (w == 3) { sa = (int8_t)sa; sv = (int8_t)sv; } mem_write(cpu, ea, (sa < sv) ? ACC(cpu, a) : val, w, i); } break; // MIN
                case 87: mem_write(cpu, ea, pack_float(fmin(get_float(ACC(cpu, a), w), get_float(val, w)), w), w, i); break; // FMIN

                // --- BIT MANIPULATION ---
                case 91: { int count = 0; if (w == 0) count = __builtin_popcountll(ACC(cpu, a)); else if (w == 1) count = __builtin_popcount((uint32_t)ACC(cpu, a)); else if (w == 2) count = __builtin_popcount((uint16_t)ACC(cpu, a)); else if (w == 3) count = __builtin_popcount((uint8_t)ACC(cpu, a)); mem_write(cpu, ea, count, w, i); } break; // POPCNT
                case 92: { int count = 0; if (w == 0) count = (ACC(cpu, a) == 0) ? 64 : __builtin_clzll(ACC(cpu, a)); else if (w == 1) count = ((uint32_t)ACC(cpu, a) == 0) ? 32 : __builtin_clz((uint32_t)ACC(cpu, a)); else if (w == 2) count = ((uint16_t)ACC(cpu, a) == 0) ? 16 : __builtin_clz((uint16_t)ACC(cpu, a)) - 16; else if (w == 3) count = ((uint8_t)ACC(cpu, a) == 0) ? 8 : __builtin_clz((uint8_t)ACC(cpu, a)) - 24; mem_write(cpu, ea, count, w, i); } break; // CLZ
                case 93: { int count = 0; if (w == 0) count = (ACC(cpu, a) == 0) ? 64 : __builtin_ctzll(ACC(cpu, a)); else if (w == 1) count = ((uint32_t)ACC(cpu, a) == 0) ? 32 : __builtin_ctz((uint32_t)ACC(cpu, a)); else if (w == 2) count = ((uint16_t)ACC(cpu, a) == 0) ? 16 : __builtin_ctz((uint16_t)ACC(cpu, a)); else if (w == 3) count = ((uint8_t)ACC(cpu, a) == 0) ? 8 : __builtin_ctz((uint8_t)ACC(cpu, a)); mem_write(cpu, ea, count, w, i); } break; // CTZ

                default: printf("\nUndefined opcode %d at %010llX\n", op, pc_val); cpu->halted = 1; break;
            }
        }
    }

    ACC(cpu, 0) = 0; // Final scrub

    // --- Timers & Exceptions ---
    if (cpu->EXCLK > 0) {
        if (cpu->hidden_exclk > 0) cpu->hidden_exclk--;
        if (cpu->hidden_exclk == 0 && !cpu->in_exception) { trigger_exception(cpu, 3); cpu->hidden_exclk = cpu->EXCLK; }
    }

    uint64_t now = GetTickCount64();
    uint64_t elapsed = now - cpu->last_time;
    if (elapsed >= 1000) {
        uint64_t seconds_passed = elapsed / 1000;
        cpu->last_time += seconds_passed * 1000;
        cpu->CTCLK += seconds_passed;
        if (cpu->CTCLKI != 0 && cpu->CTCLK >= cpu->CTCLKI && !cpu->in_exception) trigger_exception(cpu, 4);
    }
}

// --- SIMH Console Interface ---
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
                    if (k[0] == 'A') ACC(cpu, atoi(k+1)) = val;
                    else if (!strcmp(k, "PC")) cpu->PC = (cpu->PC & SYS_MASK) | (val & ADDR_MASK);
                    else if (!strcmp(k, "BASE")) cpu->BASE = val & ADDR_MASK;
                    else if (!strcmp(k, "TTB")) cpu->TTB = val & ADDR_MASK;
                    else if (!strcmp(k, "ETB")) cpu->ETB = val & ADDR_MASK;
                    else if (!strcmp(k, "CRB")) cpu->CRB = val & 0x7;
                } else if (sec == 2) mem_write_phys(cpu, strtoull(k, NULL, 16), val, 0);
            }
        }
        fclose(f); printf("INI loaded: %s\n", path);
    } else {
        FILE *f = fopen(path, "rb");
        if (!f) { printf("Load Error: %s\n", strerror(errno)); return; }
        fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);

        size_t max_load = sz > MEMORY_SIZE ? MEMORY_SIZE : sz;
        uint8_t *tmp = malloc(max_load);
        if (!tmp) { printf("Memory allocation failed!\n"); fclose(f); return; }

        size_t n = fread(tmp, 1, max_load, f);
        for (size_t i = 0; i < n; i++) mem_write_phys(cpu, i, tmp[i], 3);

        free(tmp); fclose(f);
        printf("Loaded %zu bytes from %s\n", n, path);
    }
}

void scp(XDP64 *cpu) {
    char cmd[256];
    printf("\nsim> ");
    while (fgets(cmd, 256, stdin)) {
        char *t = strtok(cmd, " \n\t");
        if (!t) { printf("sim> "); continue; }
        if (!_stricmp(t, "EXIT") || !_stricmp(t, "Q")) exit(0);
        if (!_stricmp(t, "RUN") || !_stricmp(t, "G")) {
            cpu->halted = 0;
            while (_kbhit()) _getch();
            return;
        }

        if (!_stricmp(t, "HELP") || !_stricmp(t, "H")) {
            printf("XDP64 Simulator Commands:\n");
            printf("  RUN / G               - Start execution\n");
            printf("  STEP / S [n]          - Execute [n] instructions (default 1)\n");
            printf("  LOAD / L <file>       - Load a .bin or .ini file\n");
            printf("  EXAMINE / E <loc>     - Examine memory/register (e.g., E 100, E 0x1A, E A1)\n");
            printf("  DEPOSIT / D <loc> <v> - Deposit value (e.g., D A1 1337, D CRB 1)\n");
            printf("  ATTACH / AT <dev> ... - Attach device (TTY <port>, GPU <port>, TAPx <f>, DSKx <f>)\n");
            printf("  LOG                   - Toggle execution logging (log.txt)\n");
            printf("  EXIT / Q              - Quit simulator\n");
            printf("sim> "); continue;
        }

        if (!_stricmp(t, "LOG")) {
            if (cpu->log_file) {
                fclose(cpu->log_file); cpu->log_file = NULL; printf("Logging disabled.\n");
            } else {
                cpu->log_file = fopen("log.txt", "w");
                if (cpu->log_file) printf("Logging enabled to log.txt.\n");
                else printf("Failed to open log.txt for writing.\n");
            }
            printf("sim> "); continue;
        }

        if (!_stricmp(t, "ATTACH") || !_stricmp(t, "AT")) {
            char *dev_name = strtok(NULL, " \n\t");
            char *arg2 = strtok(NULL, " \n\t");
            if (dev_name && arg2) {
                if (!_stricmp(dev_name, "TTY")) {
                    int port = atoi(arg2); WSADATA wsa; WSAStartup(MAKEWORD(2,2), &wsa);
                    cpu->listen_socket = socket(AF_INET, SOCK_STREAM, 0);
                    struct sockaddr_in addr; addr.sin_family = AF_INET; addr.sin_addr.s_addr = INADDR_ANY; addr.sin_port = htons(port);
                    if (bind(cpu->listen_socket, (struct sockaddr*)&addr, sizeof(addr)) == 0) { listen(cpu->listen_socket, 15); printf("Listening for Telnet connections on port %d...\n", port); }
                    else { printf("Failed to bind to port %d.\n", port); closesocket(cpu->listen_socket); cpu->listen_socket = 0; }
                } else if (!_stricmp(dev_name, "GPU")) {
                    int port = atoi(arg2); WSADATA wsa; WSAStartup(MAKEWORD(2,2), &wsa);
                    cpu->udp_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
                    struct sockaddr_in addr; addr.sin_family = AF_INET; addr.sin_addr.s_addr = INADDR_ANY; addr.sin_port = htons(port);
                    bind(cpu->udp_socket, (struct sockaddr*)&addr, sizeof(addr));
                    u_long mode = 1; ioctlsocket(cpu->udp_socket, FIONBIO, &mode);
                    printf("GPU UDP Server listening on port %d...\n", port);
                } else if (!_strnicmp(dev_name, "TAP", 3)) {
                    int tid = dev_name[3] - '0';
                    if (tid >= 0 && tid <= 3) {
                        strncpy(cpu->tape_files[tid], arg2, 255); cpu->tape_files[tid][255] = '\0';
                        FILE *f = fopen(arg2, "r+b"); if (!f) { f = fopen(arg2, "w+b"); if (f) { fseek(f, 1024*1024 - 1, SEEK_SET); fputc(0, f); } } if (f) fclose(f);
                        printf("TAP%d attached to %s\n", tid, arg2);
                    } else printf("Invalid tape drive. Use TAP0 to TAP3.\n");
                } else if (!_strnicmp(dev_name, "DSK", 3)) {
                    int did = atoi(dev_name + 3);
                    if (did >= 0 && did <= 15) {
                        strncpy(cpu->disk_files[did], arg2, 255); cpu->disk_files[did][255] = '\0';
                        FILE *f = fopen(arg2, "r+b"); if (!f) { f = fopen(arg2, "w+b"); if (f) { printf("Created new disk file: %s\n", arg2); } else { printf("Error: Could not create %s\n", arg2); } } if (f) fclose(f);
                        printf("DSK%d attached to %s\n", did, arg2);
                    } else printf("Invalid disk drive. Use DSK0 to DSK15.\n");
                } else printf("Unknown device. Try TTY, GPU, TAP0-TAP3 or DSK0-DSK15.\n");
            } else printf("Usage: ATTACH <TTY|GPU|TAP0-TAP3|DSK0-DSK15> <port/filename>\n");
            printf("sim> "); continue;
        }
        if (!_stricmp(t, "STEP") || !_stricmp(t, "S")) {
            char *count = strtok(NULL, " "); int n = count ? atoi(count) : 1;
            for (int i=0; i<n && !cpu->halted; i++) step(cpu);
            printf("Stopped at %010llX\n", get_pc(cpu));
        }
        if (!_stricmp(t, "LOAD") || !_stricmp(t, "L")) { char *p = strtok(NULL, " \n\t"); if(p) load_file(cpu, p); }
        if (!_stricmp(t, "EXAMINE") || !_stricmp(t, "E")) {
            char *p = strtok(NULL, " \n\t");
            if (!p) printf("PC: %010llX  ST: %05llX  BASE: %010llX  TTB: %010llX  ETB: %010llX  CRB: %d\n", get_pc(cpu), (cpu->PC >> 44) & 0xFFFFF, cpu->BASE, cpu->TTB, cpu->ETB, cpu->CRB);
            else if (p[0] == 'A') { int i = atoi(p+1); printf("A%d [Block %d]: %016llX\n", i, cpu->CRB, ACC(cpu, i)); }
            else printf("%010llX: %016llX\n", strtoull(p, NULL, 0), mem_read_phys(cpu, strtoull(p, NULL, 0), 0));
        }
        if (!_stricmp(t, "DEPOSIT") || !_stricmp(t, "D")) {
            char *p = strtok(NULL, " \n\t"), *v = strtok(NULL, " \n\t");
            if (p && v) {
                uint64_t val = strtoull(v, NULL, 0);
                if (p[0] == 'A') ACC(cpu, atoi(p+1)) = val;
                else if (!strcmp(p, "PC")) cpu->PC = (cpu->PC & SYS_MASK) | (val & ADDR_MASK);
                else if (!strcmp(p, "BASE")) cpu->BASE = val & ADDR_MASK;
                else if (!strcmp(p, "TTB")) cpu->TTB = val & ADDR_MASK;
                else if (!strcmp(p, "ETB")) cpu->ETB = val & ADDR_MASK;
                else if (!strcmp(p, "CRB")) cpu->CRB = val & 0x7;
                else mem_write_phys(cpu, strtoull(p, NULL, 0), val, 0);
            }
        }
        printf("sim> ");
    }
}

int main(int argc, char **argv) {
    XDP64 *cpu = calloc(1, sizeof(XDP64));
    cpu->memory = calloc(MEMORY_SIZE, 1);
    cpu->halted = 1;
    cpu->last_time = GetTickCount64();

    printf("XDP64 Simulation System\nType HELP for info or CTRL-E to break.\n");

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-l") == 0) {
            cpu->log_file = fopen("log.txt", "w");
            if (cpu->log_file) printf("Logging enabled to log.txt\n");
            else printf("Failed to open log.txt for writing.\n");
        } else load_file(cpu, argv[i]);
    }

    while (1) { if (cpu->halted) scp(cpu); else step(cpu); }
    return 0;
}
