// Fuzz target: cycfi::q::midi_1_0::note_number(std::string_view), the
// note-name parser ("C#4" -> 61), and the note_name/note_frequency lookups
// that take its result.
//
// note.hpp documents the contract: "Returns -1 if parsing failed or the key
// is not a MIDI note, 0 (C-1) to 127 (G9)". A result outside that set (for
// instance an uninitialised value, as before upstream fix 650d04c575) is a
// bug, so the harness traps on it.
#include <q/midi/note.hpp>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string_view>

namespace midi = cycfi::q::midi_1_0;

extern "C" int LLVMFuzzerTestOneInput(std::uint8_t const* data, std::size_t size)
{
   std::string_view const s{reinterpret_cast<char const*>(data), size};
   int const n = midi::note_number(s);
   if (n == -1)
      return 0;
   if (n < 0 || n > 127)
      __builtin_trap();

   // Round trip: the name of a parsed key must parse back to the same key.
   char const* name = midi::note_name(std::uint8_t(n));
   if (name == nullptr)
      __builtin_trap();
   if (midi::note_number(std::string_view{name, std::strlen(name)}) != n)
      __builtin_trap();
   // note_frequency is 0 outside the keys it has a table for (9 to 119).
   volatile double f = cycfi::q::as_double(midi::note_frequency(std::uint8_t(n)));
   (void)f;
   return 0;
}
