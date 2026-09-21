/* What a game finds after the DirectX redistributable of June 2010 has installed: its libraries load from the system directory and work.
 * The shader compiler compiles a pixel shader, D3DX multiplies two matrices, X3DAudio initializes for stereo, and the XAudio2 and
 * XInput libraries load. Built for both widths; the entry returns the number of the first check that failed. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

typedef struct Blob Blob;
typedef struct {
	HRESULT (WINAPI *QueryInterface)(Blob *, const GUID *, void **);
	ULONG (WINAPI *AddRef)(Blob *);
	ULONG (WINAPI *Release)(Blob *);
	void *(WINAPI *GetBufferPointer)(Blob *);
	SIZE_T (WINAPI *GetBufferSize)(Blob *);
} BlobMethods;
struct Blob {
	const BlobMethods *methods;
};

typedef HRESULT (WINAPI *Compile)(const void *, SIZE_T, const char *, const void *, void *, const char *, const char *, UINT, UINT, Blob **,
	Blob **);
typedef float *(WINAPI *Multiply)(float *, const float *, const float *);
/* Version 1.7 of X3DAudio returns nothing; it fills the handle in. */
typedef void (__cdecl *Initialize)(UINT32, float, BYTE *);

static const char shader[] = "float4 main() : SV_Target { return float4(1, 0.5, 0.25, 1); }";

int raven_entry(void)
{
	HMODULE compiler = LoadLibraryA("d3dcompiler_43.dll");
	if (!compiler)
		return 1;
	const Compile compile = (Compile)GetProcAddress(compiler, "D3DCompile");
	if (!compile)
		return 2;
	Blob *code = NULL, *errors = NULL;
	if (compile(shader, sizeof shader - 1, "check", NULL, NULL, "main", "ps_4_0", 0, 0, &code, &errors) != S_OK || !code)
		return 3;
	/* The bytecode is a DXBC container. */
	const unsigned char *bytes = code->methods->GetBufferPointer(code);
	if (code->methods->GetBufferSize(code) < 32 || bytes[0] != 'D' || bytes[1] != 'X' || bytes[2] != 'B' || bytes[3] != 'C')
		return 4;
	code->methods->Release(code);

	HMODULE d3dx = LoadLibraryA("d3dx9_43.dll");
	if (!d3dx)
		return 5;
	const Multiply multiply = (Multiply)GetProcAddress(d3dx, "D3DXMatrixMultiply");
	if (!multiply)
		return 6;
	/* A scale by two followed by a translation of (3, 4, 5), in D3DX's row-vector order. */
	float scale[16] = {2, 0, 0, 0, 0, 2, 0, 0, 0, 0, 2, 0, 0, 0, 0, 1}, move[16] = {1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 3, 4, 5, 1}, result[16];
	if (multiply(result, scale, move) != result || result[0] != 2 || result[5] != 2 || result[10] != 2 || result[12] != 3 || result[13] != 4 ||
		result[14] != 5 || result[15] != 1)
		return 7;

	HMODULE audio = LoadLibraryA("X3DAudio1_7.dll");
	if (!audio)
		return 8;
	const Initialize initialize = (Initialize)GetProcAddress(audio, "X3DAudioInitialize");
	BYTE handle[20] = {0};
	if (!initialize)
		return 9;
	initialize(3, 343.5f, handle);
	BOOL filled = FALSE;
	for (int index = 0; index < 20; ++index)
		filled |= handle[index] != 0;
	if (!filled)
		return 12;
	if (!LoadLibraryA("XAudio2_7.dll"))
		return 10;
	if (!LoadLibraryA("xinput1_3.dll"))
		return 11;
	return 0;
}
