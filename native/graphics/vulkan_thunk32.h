#pragma once

#include <cstdint>
#include <span>
#include <string_view>

namespace raven::thunk32 {

// How one member of a Vulkan structure crosses from the 32-bit layout a 32-bit program uses to the 64-bit layout the bridge reads.
enum class Field : uint8_t {
	scalar,                   // same bytes in both layouts
	dhandle,                  // dispatchable handle: 4 bytes in, a token of 8 bytes out
	dhandles,                 // fixed array of them
	widen_value,              // size_t: zero-extended, and truncated again when read back
	widen_pointer,            // an address the bridge reads from guest memory as it is: zero-extended, never read back
	nested,                   // a structure inside the structure (or an array of them)
	raw_union,                // a union copied as far as both layouts reach
	descriptor_data,          // a descriptor's tagged pointer or device address
	pnext,                    // a chain of structures
	pointer_struct,           // to one or more structures
	pointer_struct_pointers,  // to an array of pointers to structures
	pointer_strings,          // to an array of strings
	pointer_dhandles,         // to an array of dispatchable handles
};

struct FieldInfo {
	Field kind;
	uint16_t off32, size32, off64, size64;
	uint16_t target;  // the structure a pointer or nested member leads to
	uint32_t len;     // first operation of the length program, or none
};

struct StructInfo {
	const char *name;
	uint16_t size32, size64;
	uint32_t first_field;
	uint16_t field_count;
	uint32_t stype;   // the sType of a chain element, zero otherwise
	bool supported;
};

enum class Op : uint8_t {
	end,
	constant,  // a
	field,     // the member with field index a of the structure the length belongs to
	param,     // the word of parameter a
	deref,     // the 32-bit value parameter a points at
	arrow,     // member b of the structure parameter a points at
	divide,
	add,
};

struct LenOp {
	Op op;
	uint32_t a, b;
};

inline constexpr uint32_t no_length = UINT32_MAX;
inline constexpr uint16_t no_target = UINT16_MAX;

enum class Param : uint8_t {
	word,             // one word of a plain value
	words,            // two words of a plain value: 64-bit integers, non-dispatchable handles and doubles
	dhandle,          // dispatchable handle
	in_struct,        // pointer to structures the call reads
	inout_struct,     // pointer to structures the call fills
	pass,             // pointer to data with the same layout in both ABIs, or an address passed as it is
	out_dhandles,     // pointer the call stores dispatchable handles through
	in_dhandles,      // pointer to dispatchable handles the call reads
	out_pointer,      // pointer the call stores an address through
};

struct ParamInfo {
	Param kind;
	bool floating;
	uint16_t target;
	uint32_t len;
};

enum class Ret : uint8_t { none, word, words, pointer };

struct CommandInfo {
	const char *name;
	Ret ret;
	uint32_t first_param;
	uint16_t param_count;
	uint16_t words;
};

extern const std::span<const FieldInfo> fields;
extern const std::span<const StructInfo> structs;
extern const std::span<const LenOp> lengths;
extern const std::span<const ParamInfo> params;
extern const std::span<const CommandInfo> commands;

const CommandInfo *find_command(std::string_view name);

}
