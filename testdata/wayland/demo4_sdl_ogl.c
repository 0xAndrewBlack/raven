// Demo 4: SDL2 + OpenGL ES 2.0 via EGL (Wayland)
// Sfondo giallo con GLES2.
// Tests: SDL2 EGL context creation, GL rendering via SDL.
#include <stdio.h>
#include <SDL2/SDL.h>
#include <SDL2/SDL_opengles2.h>

int main(void) {
    SDL_SetHint(SDL_HINT_OPENGL_ES_DRIVER, "1");
    if (SDL_Init(SDL_INIT_VIDEO) != 0) {
        fprintf(stderr, "[demo4] SDL_Init: %s\n", SDL_GetError()); return 1;
    }
    fprintf(stderr, "[demo4] driver: %s\n", SDL_GetCurrentVideoDriver());

    SDL_GL_SetAttribute(SDL_GL_CONTEXT_PROFILE_MASK, SDL_GL_CONTEXT_PROFILE_ES);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_MAJOR_VERSION, 2);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_MINOR_VERSION, 0);
    SDL_GL_SetAttribute(SDL_GL_DOUBLEBUFFER, 1);

    SDL_Window *win = SDL_CreateWindow("demo4-sdl-gl",
        SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED,
        400, 300, SDL_WINDOW_SHOWN | SDL_WINDOW_OPENGL);
    if (!win) { fprintf(stderr, "[demo4] window: %s\n", SDL_GetError()); return 1; }
    fprintf(stderr, "[demo4] window created\n");

    SDL_GLContext ctx = SDL_GL_CreateContext(win);
    if (!ctx) { fprintf(stderr, "[demo4] GL context: %s\n", SDL_GetError()); return 1; }
    fprintf(stderr, "[demo4] GL context: %s\n", (const char*)glGetString(GL_RENDERER));

    glViewport(0, 0, 400, 300);
    glClearColor(1.0f, 0.9f, 0.0f, 1.0f);
    glClear(GL_COLOR_BUFFER_BIT);
    SDL_GL_SwapWindow(win);
    fprintf(stderr, "[demo4] first frame (yellow) swapped\n");

    SDL_Event e;
    while (1) {
        while (SDL_PollEvent(&e)) {
            if (e.type == SDL_QUIT) goto done;
            if (e.type == SDL_KEYDOWN && e.key.keysym.sym == SDLK_ESCAPE) goto done;
        }
        glClear(GL_COLOR_BUFFER_BIT);
        SDL_GL_SwapWindow(win);
        SDL_Delay(16);
    }
done:
    SDL_GL_DeleteContext(ctx);
    SDL_DestroyWindow(win);
    SDL_Quit();
    return 0;
}
