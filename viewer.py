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

while True:
    for event in pygame.event.get():
        if event.type == pygame.QUIT:
            sys.exit()

    now = time.time()
    if now - last_ping > 1.0:
        sock.sendto(bytes([SCREEN_ID, 1]), (UDP_IP, UDP_PORT))
        last_ping = now

    try:
        data, addr = sock.recvfrom(65536)
        if len(data) >= 2 and data[0] == SCREEN_ID:
            mode = data[1]
            payload = data[2:]

            surf = pygame.Surface((320, 240))
            pxarray = pygame.PixelArray(surf)

            if mode == 1 and len(payload) >= 9600:
                idx = 0
                for y in range(240):
                    for x in range(0, 320, 8):
                        b = payload[idx]; idx += 1
                        for bit in range(8):
                            color = (255,255,255) if (b & (1 << (7-bit))) else (0,0,0)
                            pxarray[x+bit, y] = color

            elif mode == 2 and len(payload) >= 38400:
                idx = 0
                for y in range(240):
                    for x in range(0, 320, 2):
                        b = payload[idx]; idx += 1
                        c1 = (b >> 4) & 0xF   # Left pixel
                        c2 = b & 0xF          # Right pixel
                        pxarray[x, y] = palette[c1]
                        pxarray[x+1, y] = palette[c2]

            pxarray.close()
            screen.blit(surf, (0,0))
            pygame.display.flip()

    except BlockingIOError: pass
    except Exception as e: pass

    time.sleep(0.005)
