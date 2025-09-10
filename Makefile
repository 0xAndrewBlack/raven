CC     = gcc
CFLAGS = -O2 -g -Wall
WD     = testdata/wayland

BINS = $(WD)/demo1_shm $(WD)/demo2_egl $(WD)/demo3_sdl_soft \
       $(WD)/demo4_sdl_ogl $(WD)/demo5_shm_anim

all: $(BINS)

$(WD)/xdg-shell-protocol.o: $(WD)/xdg-shell-protocol.c
	$(CC) $(CFLAGS) -c $< -o $@

$(WD)/demo1_shm: $(WD)/demo1_shm.c $(WD)/xdg-shell-protocol.o
	$(CC) $(CFLAGS) -I$(WD) $^ -o $@ -lwayland-client

$(WD)/demo2_egl: $(WD)/demo2_egl.c $(WD)/xdg-shell-protocol.o
	$(CC) $(CFLAGS) -I$(WD) $^ -o $@ -lwayland-client -lwayland-egl -lEGL -lGLESv2

$(WD)/demo3_sdl_soft: $(WD)/demo3_sdl_soft.c
	$(CC) $(CFLAGS) $^ -o $@ $(shell pkg-config --libs sdl2)

$(WD)/demo4_sdl_ogl: $(WD)/demo4_sdl_ogl.c
	$(CC) $(CFLAGS) $^ -o $@ $(shell pkg-config --libs sdl2) -lGLESv2

$(WD)/demo5_shm_anim: $(WD)/demo5_shm_anim.c $(WD)/xdg-shell-protocol.o
	$(CC) $(CFLAGS) -I$(WD) $^ -o $@ -lwayland-client

clean:
	rm -f $(BINS) $(WD)/xdg-shell-protocol.o

.PHONY: all clean
