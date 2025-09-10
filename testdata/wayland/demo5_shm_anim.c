// Demo 5: Wayland + wl_shm con animazione (frame callback)
// A bar moves left to right and changes colour.
// Tests: frame callbacks, wl_callback, buffer ping-pong, continuous rendering.
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <wayland-client.h>
#include "xdg-shell-client-protocol.h"

#define WIDTH  400
#define HEIGHT 300

static struct wl_display    *display;
static struct wl_compositor *compositor;
static struct wl_shm        *shm;
static struct xdg_wm_base   *wm_base;
static struct wl_surface    *surface;
static struct xdg_surface   *xdg_surf;
static struct xdg_toplevel  *toplevel;
static int running = 1, configured = 0;
static int frame_count = 0;

// Double-buffered SHM
static uint32_t *pixels[2];
static struct wl_buffer *buffers[2];
static int cur_buf = 0;

static void buf_release(void *data, struct wl_buffer *buf) {
    // buffer released by compositor, can reuse
}
static const struct wl_buffer_listener buf_listener = { buf_release };

static void alloc_buffers(void) {
    int stride = WIDTH * 4;
    int size   = stride * HEIGHT * 2;
    int fd = memfd_create("demo5", MFD_CLOEXEC);
    ftruncate(fd, size);
    uint32_t *base = mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    pixels[0] = base;
    pixels[1] = base + WIDTH * HEIGHT;
    struct wl_shm_pool *pool = wl_shm_create_pool(shm, fd, size);
    close(fd);
    for (int i = 0; i < 2; i++) {
        buffers[i] = wl_shm_pool_create_buffer(pool, i * stride * HEIGHT,
                                                WIDTH, HEIGHT, stride,
                                                WL_SHM_FORMAT_XRGB8888);
        wl_buffer_add_listener(buffers[i], &buf_listener, NULL);
    }
    wl_shm_pool_destroy(pool);
}

static void draw_frame(uint32_t *px, int frame) {
    int bar = (frame * 4) % WIDTH;
    uint32_t bg = 0xFF101020;
    uint32_t fg = 0xFF00FF80;
    for (int y = 0; y < HEIGHT; y++)
        for (int x = 0; x < WIDTH; x++)
            px[y * WIDTH + x] = (x >= bar && x < bar + 40) ? fg : bg;
}

static void frame_done(void *data, struct wl_callback *cb, uint32_t time);
static const struct wl_callback_listener frame_listener = { frame_done };

static void render_and_request(void) {
    cur_buf ^= 1;
    draw_frame(pixels[cur_buf], frame_count++);
    wl_surface_attach(surface, buffers[cur_buf], 0, 0);
    wl_surface_damage(surface, 0, 0, WIDTH, HEIGHT);
    struct wl_callback *cb = wl_surface_frame(surface);
    wl_callback_add_listener(cb, &frame_listener, NULL);
    wl_surface_commit(surface);
    if (frame_count % 60 == 0)
        fprintf(stderr, "[demo5] frame %d\n", frame_count);
}

static void frame_done(void *data, struct wl_callback *cb, uint32_t time) {
    wl_callback_destroy(cb);
    if (running) render_and_request();
}

static void xdg_configure(void *d, struct xdg_surface *xs, uint32_t serial) {
    xdg_surface_ack_configure(xs, serial); configured = 1;
}
static const struct xdg_surface_listener xsl = { xdg_configure };
static void tl_configure(void *d, struct xdg_toplevel *t, int32_t w, int32_t h, struct wl_array *s) {}
static void tl_close(void *d, struct xdg_toplevel *t) { running = 0; }
static void tl_bounds(void *d, struct xdg_toplevel *t, int32_t w, int32_t h) {}
static void tl_caps(void *d, struct xdg_toplevel *t, struct wl_array *c) {}
static const struct xdg_toplevel_listener tll = { tl_configure, tl_close, tl_bounds, tl_caps };
static void wm_ping(void *d, struct xdg_wm_base *b, uint32_t s) { xdg_wm_base_pong(b, s); }
static const struct xdg_wm_base_listener wml = { wm_ping };

static void registry_global(void *d, struct wl_registry *r, uint32_t name,
                             const char *iface, uint32_t ver) {
    if (!strcmp(iface, wl_compositor_interface.name))
        compositor = wl_registry_bind(r, name, &wl_compositor_interface, 4);
    else if (!strcmp(iface, wl_shm_interface.name))
        shm = wl_registry_bind(r, name, &wl_shm_interface, 1);
    else if (!strcmp(iface, xdg_wm_base_interface.name)) {
        wm_base = wl_registry_bind(r, name, &xdg_wm_base_interface, 1);
        xdg_wm_base_add_listener(wm_base, &wml, NULL);
    }
}
static void registry_remove(void *d, struct wl_registry *r, uint32_t n) {}
static const struct wl_registry_listener rl = { registry_global, registry_remove };

int main(void) {
    display = wl_display_connect(NULL);
    if (!display) { fprintf(stderr, "[demo5] cannot connect\n"); return 1; }
    fprintf(stderr, "[demo5] connected\n");

    struct wl_registry *reg = wl_display_get_registry(display);
    wl_registry_add_listener(reg, &rl, NULL);
    wl_display_roundtrip(display);

    if (!compositor || !shm || !wm_base) {
        fprintf(stderr, "[demo5] missing globals\n"); return 1;
    }
    alloc_buffers();

    surface  = wl_compositor_create_surface(compositor);
    xdg_surf = xdg_wm_base_get_xdg_surface(wm_base, surface);
    xdg_surface_add_listener(xdg_surf, &xsl, NULL);
    toplevel = xdg_surface_get_toplevel(xdg_surf);
    xdg_toplevel_add_listener(toplevel, &tll, NULL);
    xdg_toplevel_set_title(toplevel, "demo5-anim");
    wl_surface_commit(surface);
    wl_display_roundtrip(display);

    render_and_request();
    fprintf(stderr, "[demo5] event loop started\n");

    while (running && wl_display_dispatch(display) != -1) {}
    return 0;
}
