// Demo 2: Wayland + EGL + OpenGL ES 2.0 (forza software via env)
// Disegna uno sfondo verde con GL.
// Tests: EGL init, swrast path, wl_egl_window, GL rendering.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <wayland-client.h>
#include <wayland-egl.h>
#include <EGL/egl.h>
#include <GLES2/gl2.h>
#include "xdg-shell-client-protocol.h"

#define WIDTH  400
#define HEIGHT 300

static struct wl_display    *display;
static struct wl_compositor *compositor;
static struct xdg_wm_base   *wm_base;
static struct wl_surface    *surface;
static struct xdg_surface   *xdg_surf;
static struct xdg_toplevel  *toplevel;
static int running = 1, configured = 0;

static void xdg_surface_configure(void *d, struct xdg_surface *xs, uint32_t serial) {
    xdg_surface_ack_configure(xs, serial); configured = 1;
}
static const struct xdg_surface_listener xsl = { xdg_surface_configure };
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
    else if (!strcmp(iface, xdg_wm_base_interface.name)) {
        wm_base = wl_registry_bind(r, name, &xdg_wm_base_interface, 1);
        xdg_wm_base_add_listener(wm_base, &wml, NULL);
    }
}
static void registry_remove(void *d, struct wl_registry *r, uint32_t n) {}
static const struct wl_registry_listener rl = { registry_global, registry_remove };

int main(void) {
    display = wl_display_connect(NULL);
    if (!display) { fprintf(stderr, "[demo2] cannot connect\n"); return 1; }
    fprintf(stderr, "[demo2] connected\n");

    struct wl_registry *reg = wl_display_get_registry(display);
    wl_registry_add_listener(reg, &rl, NULL);
    wl_display_roundtrip(display);

    surface  = wl_compositor_create_surface(compositor);
    xdg_surf = xdg_wm_base_get_xdg_surface(wm_base, surface);
    xdg_surface_add_listener(xdg_surf, &xsl, NULL);
    toplevel = xdg_surface_get_toplevel(xdg_surf);
    xdg_toplevel_add_listener(toplevel, &tll, NULL);
    xdg_toplevel_set_title(toplevel, "demo2-egl");
    wl_surface_commit(surface);
    wl_display_roundtrip(display);

    // EGL setup
    EGLDisplay egl_dpy = eglGetDisplay((EGLNativeDisplayType)display);
    EGLint major, minor;
    if (!eglInitialize(egl_dpy, &major, &minor)) {
        fprintf(stderr, "[demo2] eglInitialize failed: 0x%x\n", eglGetError()); return 1;
    }
    fprintf(stderr, "[demo2] EGL %d.%d OK\n", major, minor);

    EGLint attribs[] = { EGL_SURFACE_TYPE, EGL_WINDOW_BIT,
                         EGL_RENDERABLE_TYPE, EGL_OPENGL_ES2_BIT,
                         EGL_RED_SIZE,4, EGL_GREEN_SIZE,4, EGL_BLUE_SIZE,4, EGL_NONE };
    EGLConfig cfg; EGLint ncfg;
    eglChooseConfig(egl_dpy, attribs, &cfg, 1, &ncfg);
    if (!ncfg) { fprintf(stderr, "[demo2] no EGL config\n"); return 1; }

    struct wl_egl_window *egl_win = wl_egl_window_create(surface, WIDTH, HEIGHT);
    EGLSurface egl_surf = eglCreateWindowSurface(egl_dpy, cfg, (EGLNativeWindowType)egl_win, NULL);
    if (egl_surf == EGL_NO_SURFACE) {
        fprintf(stderr, "[demo2] eglCreateWindowSurface failed: 0x%x\n", eglGetError()); return 1;
    }
    fprintf(stderr, "[demo2] EGL surface OK\n");

    EGLint ctx_attribs[] = { EGL_CONTEXT_CLIENT_VERSION, 2, EGL_NONE };
    EGLContext ctx = eglCreateContext(egl_dpy, cfg, EGL_NO_CONTEXT, ctx_attribs);
    eglMakeCurrent(egl_dpy, egl_surf, egl_surf, ctx);

    glViewport(0, 0, WIDTH, HEIGHT);
    glClearColor(0.0f, 0.8f, 0.2f, 1.0f);
    glClear(GL_COLOR_BUFFER_BIT);
    eglSwapBuffers(egl_dpy, egl_surf);
    fprintf(stderr, "[demo2] first frame rendered (green)\n");
    wl_display_flush(display);

    while (running && wl_display_dispatch(display) != -1) {
        glClear(GL_COLOR_BUFFER_BIT);
        eglSwapBuffers(egl_dpy, egl_surf);
    }
    return 0;
}
