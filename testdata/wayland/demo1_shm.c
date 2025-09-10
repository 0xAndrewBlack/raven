// Demo 1: Pure Wayland + wl_shm, NO EGL/GL/SDL
// Draws a solid red 400x300 window using shared memory buffers.
// Tests: basic Wayland protocol, wl_shm, xdg-shell, event loop.
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <errno.h>
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
static int running = 1;
static int configured = 0;

static void xdg_surface_configure(void *data, struct xdg_surface *xs, uint32_t serial) {
    xdg_surface_ack_configure(xs, serial);
    configured = 1;
}
static const struct xdg_surface_listener xdg_surf_listener = { xdg_surface_configure };

static void toplevel_configure(void *data, struct xdg_toplevel *tl,
                               int32_t w, int32_t h, struct wl_array *states) {}
static void toplevel_close(void *data, struct xdg_toplevel *tl) { running = 0; }
static void toplevel_configure_bounds(void *data, struct xdg_toplevel *tl, int32_t w, int32_t h) {}
static void toplevel_wm_capabilities(void *data, struct xdg_toplevel *tl, struct wl_array *caps) {}
static const struct xdg_toplevel_listener toplevel_listener = {
    toplevel_configure, toplevel_close, toplevel_configure_bounds, toplevel_wm_capabilities
};

static void wm_base_ping(void *data, struct xdg_wm_base *base, uint32_t serial) {
    xdg_wm_base_pong(base, serial);
}
static const struct xdg_wm_base_listener wm_base_listener = { wm_base_ping };

static void registry_global(void *data, struct wl_registry *reg, uint32_t name,
                             const char *iface, uint32_t version) {
    if (strcmp(iface, wl_compositor_interface.name) == 0)
        compositor = wl_registry_bind(reg, name, &wl_compositor_interface, 4);
    else if (strcmp(iface, wl_shm_interface.name) == 0)
        shm = wl_registry_bind(reg, name, &wl_shm_interface, 1);
    else if (strcmp(iface, xdg_wm_base_interface.name) == 0) {
        wm_base = wl_registry_bind(reg, name, &xdg_wm_base_interface, 1);
        xdg_wm_base_add_listener(wm_base, &wm_base_listener, NULL);
    }
}
static void registry_global_remove(void *data, struct wl_registry *reg, uint32_t name) {}
static const struct wl_registry_listener registry_listener = { registry_global, registry_global_remove };

static struct wl_buffer *make_shm_buffer(void) {
    int stride = WIDTH * 4;
    int size   = stride * HEIGHT;

    int fd = memfd_create("wl-shm", MFD_CLOEXEC);
    if (fd < 0) { perror("memfd_create"); return NULL; }
    if (ftruncate(fd, size) < 0) { perror("ftruncate"); close(fd); return NULL; }

    uint32_t *data = mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    if (data == MAP_FAILED) { perror("mmap"); close(fd); return NULL; }

    // Fill solid red (XRGB8888)
    for (int i = 0; i < WIDTH * HEIGHT; i++)
        data[i] = 0xFFFF0000;
    munmap(data, size);

    struct wl_shm_pool *pool = wl_shm_create_pool(shm, fd, size);
    close(fd);
    struct wl_buffer *buf = wl_shm_pool_create_buffer(pool, 0, WIDTH, HEIGHT,
                                                       stride, WL_SHM_FORMAT_XRGB8888);
    wl_shm_pool_destroy(pool);
    return buf;
}

int main(void) {
    display = wl_display_connect(NULL);
    if (!display) { fprintf(stderr, "cannot connect to Wayland\n"); return 1; }
    fprintf(stderr, "[demo1] connected to Wayland\n");

    struct wl_registry *reg = wl_display_get_registry(display);
    wl_registry_add_listener(reg, &registry_listener, NULL);
    wl_display_roundtrip(display);

    if (!compositor || !shm || !wm_base) {
        fprintf(stderr, "[demo1] missing globals: compositor=%p shm=%p wm_base=%p\n",
                compositor, shm, wm_base);
        return 1;
    }
    fprintf(stderr, "[demo1] got globals OK\n");

    surface  = wl_compositor_create_surface(compositor);
    xdg_surf = xdg_wm_base_get_xdg_surface(wm_base, surface);
    xdg_surface_add_listener(xdg_surf, &xdg_surf_listener, NULL);
    toplevel = xdg_surface_get_toplevel(xdg_surf);
    xdg_toplevel_add_listener(toplevel, &toplevel_listener, NULL);
    xdg_toplevel_set_title(toplevel, "demo1-shm");
    wl_surface_commit(surface);
    wl_display_roundtrip(display);

    struct wl_buffer *buf = make_shm_buffer();
    if (!buf) { fprintf(stderr, "[demo1] buffer alloc failed\n"); return 1; }
    fprintf(stderr, "[demo1] buffer created OK\n");

    wl_surface_attach(surface, buf, 0, 0);
    wl_surface_damage(surface, 0, 0, WIDTH, HEIGHT);
    wl_surface_commit(surface);
    wl_display_flush(display);
    fprintf(stderr, "[demo1] first frame committed\n");

    int ret;
    while (running && (ret = wl_display_dispatch(display)) != -1)
        fprintf(stderr, "[demo1] dispatch ret=%d\n", ret);

    int wl_err = wl_display_get_error(display);
    fprintf(stderr, "[demo1] exiting: wl_error=%d errno=%d (%s)\n",
            wl_err, errno, strerror(errno));
    return 0;
}
