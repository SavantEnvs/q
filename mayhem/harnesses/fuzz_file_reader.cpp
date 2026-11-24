// Fuzz target: cycfi::q::midi_1_0::file_reader, the Standard MIDI File
// parser (header and track chunks, delta times, running status, meta and
// tempo events), played through a processor as q_io's midi_file does.
#include <q/midi/file_reader.hpp>
#include <cstddef>
#include <cstdint>

namespace q = cycfi::q;
namespace midi = q::midi_1_0;

namespace
{
   struct recorder : midi::processor
   {
      using midi::processor::operator();

      void operator()(midi::note_on m, std::size_t t)
      { _sum += m.channel() + m.key() + m.velocity() + t; }
      void operator()(midi::note_off m, std::size_t t)
      { _sum += m.channel() + m.key() + m.velocity() + t; }
      void operator()(midi::control_change m, std::size_t t)
      { _sum += m.channel() + std::size_t(m.controller()) + m.value() + t; }
      void operator()(midi::pitch_bend m, std::size_t t)
      { _sum += m.channel() + m.value() + t; }

      std::size_t _sum = 0;
   };
}

extern "C" int LLVMFuzzerTestOneInput(std::uint8_t const* data, std::size_t size)
{
   midi::file_reader r{q::byte_span{data, size}};
   if (!r)
      return 0;
   volatile int format = r.format();
   volatile std::size_t tracks = r.tracks();
   volatile float tempo = r.tempo();
   volatile double duration = r.duration();
   (void)format; (void)tracks; (void)tempo; (void)duration;

   recorder rec;
   r(44100.0f, rec);
   volatile std::size_t sum = rec._sum;
   (void)sum;
   return 0;
}
