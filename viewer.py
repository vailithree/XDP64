import socket
import pygame
import sys
import time

# XDP64 GPU Emulator settings
UDP_IP = "127.0.0.1"
UDP_PORT = 5900
SCREEN_ID = 0

pygame.init()
screen = pygame.display.set_mode((320, 240), pygame.SCALED)
pygame.display.set_caption(f"XDP64 Display Terminal {SCREEN_ID}")

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setblocking(False)

# 4-bit EGA Hardware Palette
palette = [
    (0,0,0), (0,0,170), (0,170,0), (0,170,170),
    (170,0,0), (170,0,170), (170,85,0), (170,170,170),
    (85,85,85), (85,85,255), (85,255,85), (85,255,255),
    (255,85,85), (255,85,255), (255,255,85), (255,255,255)
]

last_ping = 0
current_mode = -1
total_expected_chunks = 0
chunks_received = {}

while True:
    for event in pygame.event.get():
        if event.type == pygame.QUIT:
            sys.exit()

    # Heartbeat ping to let the emulator know we are alive!
    now = time.time()
    if now - last_ping > 1.0:
        sock.sendto(bytes([SCREEN_ID, 1]), (UDP_IP, UDP_PORT))
        last_ping = now

    try:
        while True:  # Drain all packets in the OS buffer
            data, addr = sock.recvfrom(65536)

            # Use the new 4-byte chunking header structure
            if len(data) >= 4 and data[0] == SCREEN_ID:
                mode = data[1]
                chunk_idx = data[2]
                total_chunks = data[3]
                payload = data[4:]

                # If mode changes or total chunks alter, reset the frame accumulator
                if mode != current_mode or total_expected_chunks != total_chunks:
                    current_mode = mode
                    total_expected_chunks = total_chunks
                    chunks_received.clear()

                chunks_received[chunk_idx] = payload

                # Have we received all the chunks for this frame?
                if len(chunks_received) == total_expected_chunks:
                    # Assemble the full frame buffer
                    full_payload = bytearray()
                    for i in range(total_expected_chunks):
                        full_payload.extend(chunks_received.get(i, b''))

                    chunks_received.clear() # Reset for the next frame

                    surf = pygame.Surface((320, 240))
                    pxarray = pygame.PixelArray(surf)

                    # --- Mode 1: 1-Bit Monochrome ---
                    if mode == 1 and len(full_payload) >= 9600:
                        idx = 0
                        for y in range(240):
                            for x in range(0, 320, 8):
                                b = full_payload[idx]; idx += 1
                                for bit in range(8):
                                    color = (255,255,255) if (b & (1 << (7-bit))) else (0,0,0)
                                    pxarray[x+bit, y] = color

                    # --- Mode 2: 4-Bit Color ---
                    elif mode == 2 and len(full_payload) >= 38400:
                        idx = 0
                        for y in range(240):
                            for x in range(0, 320, 2):
                                b = full_payload[idx]; idx += 1
                                c1 = (b >> 4) & 0xF   # Left pixel
                                c2 = b & 0xF          # Right pixel
                                pxarray[x, y] = palette[c1]
                                pxarray[x+1, y] = palette[c2]

                    # --- Mode 3: 8-Bit Color (R2, G3, B2, L1) ---
                    elif mode == 3 and len(full_payload) >= 76800:
                        idx = 0
                        for y in range(240):
                            for x in range(320):
                                b = full_payload[idx]; idx += 1
                                r = (b >> 6) & 0x3
                                g = (b >> 3) & 0x7
                                b_col = (b >> 1) & 0x3
                                l = b & 0x1

                                # Scale up to 0-255 bounds
                                R = r * 85
                                G = int(g * 36.4)
                                B = b_col * 85

                                # If Brightness bit is set, boost everything
                                if l == 1:
                                    R = min(255, R + 40)
                                    G = min(255, G + 40)
                                    B = min(255, B + 40)

                                pxarray[x, y] = (R, G, B)

                    # --- Mode 4: 16-Bit Color (R5, G6, B5) ---
                    elif mode == 4 and len(full_payload) >= 153600:
                        idx = 0
                        for y in range(240):
                            for x in range(320):
                                b1 = full_payload[idx]; idx += 1
                                b2 = full_payload[idx]; idx += 1
                                val = b1 | (b2 << 8) # Little-endian construction

                                r = (val >> 11) & 0x1F
                                g = (val >> 5) & 0x3F
                                b_col = val & 0x1F

                                pxarray[x, y] = ((r * 255) // 31, (g * 255) // 63, (b_col * 255) // 31)

                    # --- Mode 5: 32-Bit Color (R10, G10, B10, L2) ---
                    elif mode == 5 and len(full_payload) >= 307200:
                        idx = 0
                        for y in range(240):
                            for x in range(320):
                                b1 = full_payload[idx]; idx += 1
                                b2 = full_payload[idx]; idx += 1
                                b3 = full_payload[idx]; idx += 1
                                b4 = full_payload[idx]; idx += 1
                                val = b1 | (b2 << 8) | (b3 << 16) | (b4 << 24)

                                r = (val >> 22) & 0x3FF
                                g = (val >> 12) & 0x3FF
                                b_col = (val >> 2) & 0x3FF
                                l = val & 0x3

                                # Convert 10-bit down to 8-bit for viewing
                                R = r >> 2
                                G = g >> 2
                                B = b_col >> 2

                                # Brightness Scaling (L2 bit gives 4 levels)
                                if l > 0:
                                    boost = l * 15
                                    R = min(255, R + boost)
                                    G = min(255, G + boost)
                                    B = min(255, B + boost)

                                pxarray[x, y] = (R, G, B)

                    pxarray.close()
                    screen.blit(surf, (0,0))
                    pygame.display.flip()

    except BlockingIOError:
        pass
    except Exception as e:
        pass

    time.sleep(0.005)
