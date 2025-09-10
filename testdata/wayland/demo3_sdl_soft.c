// Demo 3: SDL2 + software renderer (no OpenGL/EGL)
// Blue window using SDL_RENDERER_SOFTWARE.
// Tests: SDL2 Wayland backend init, software rendering, event loop.
#include <stdio.h>
#include <SDL2/SDL.h>

int main(void) {
    if (SDL_Init(SDL_INIT_VIDEO) != 0) {
        fprintf(stderr, "[demo3] SDL_Init failed: %s\n", SDL_GetError());
        return 1;
    }
    fprintf(stderr, "[demo3] SDL_Init OK, driver: %s\n", SDL_GetCurrentVideoDriver());

    SDL_Window *win = SDL_CreateWindow("demo3-sdl-soft",
        SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED,
        400, 300, SDL_WINDOW_SHOWN);
    if (!win) { fprintf(stderr, "[demo3] CreateWindow: %s\n", SDL_GetError()); return 1; }
    fprintf(stderr, "[demo3] window created\n");

    SDL_Renderer *ren = SDL_CreateRenderer(win, -1, SDL_RENDERER_SOFTWARE);
    if (!ren) { fprintf(stderr, "[demo3] CreateRenderer: %s\n", SDL_GetError()); return 1; }
    fprintf(stderr, "[demo3] renderer created (software)\n");

    SDL_SetRenderDrawColor(ren, 30, 80, 200, 255);
    SDL_RenderClear(ren);
    SDL_RenderPresent(ren);
    fprintf(stderr, "[demo3] first frame (blue) presented\n");

    SDL_Event e;
    while (1) {
        while (SDL_PollEvent(&e)) {
            if (e.type == SDL_QUIT) goto done;
            if (e.type == SDL_KEYDOWN && e.key.keysym.sym == SDLK_ESCAPE) goto done;
        }
        SDL_SetRenderDrawColor(ren, 30, 80, 200, 255);
        SDL_RenderClear(ren);
        SDL_RenderPresent(ren);
        SDL_Delay(16);
    }
done:
    SDL_DestroyRenderer(ren);
    SDL_DestroyWindow(win);
    SDL_Quit();
    return 0;
}
