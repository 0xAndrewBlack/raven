CC     = gcc
CFLAGS = -O2 -g -Wall
WD     = testdata/wayland
BUILD_DIR ?= build/wayland

BINS = $(BUILD_DIR)/demo1_shm $(BUILD_DIR)/demo2_egl $(BUILD_DIR)/demo3_sdl_soft \
       $(BUILD_DIR)/demo4_sdl_ogl $(BUILD_DIR)/demo5_shm_anim

all: $(BINS)

$(BUILD_DIR):
	mkdir -p $@

$(BUILD_DIR)/xdg-shell-protocol.o: $(WD)/xdg-shell-protocol.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/demo1_shm: $(WD)/demo1_shm.c $(BUILD_DIR)/xdg-shell-protocol.o
	$(CC) $(CFLAGS) -I$(WD) $^ -o $@ -lwayland-client

$(BUILD_DIR)/demo2_egl: $(WD)/demo2_egl.c $(BUILD_DIR)/xdg-shell-protocol.o
	$(CC) $(CFLAGS) -I$(WD) $^ -o $@ -lwayland-client -lwayland-egl -lEGL -lGLESv2

$(BUILD_DIR)/demo3_sdl_soft: $(WD)/demo3_sdl_soft.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $^ -o $@ $(shell pkg-config --libs sdl2)

$(BUILD_DIR)/demo4_sdl_ogl: $(WD)/demo4_sdl_ogl.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $^ -o $@ $(shell pkg-config --libs sdl2) -lGLESv2

$(BUILD_DIR)/demo5_shm_anim: $(WD)/demo5_shm_anim.c $(BUILD_DIR)/xdg-shell-protocol.o
	$(CC) $(CFLAGS) -I$(WD) $^ -o $@ -lwayland-client

clean:
	rm -f $(BINS) $(BUILD_DIR)/xdg-shell-protocol.o

.PHONY: all clean
