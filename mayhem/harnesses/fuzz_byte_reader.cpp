// Fuzz target: cycfi::q::midi_1_0::byte_reader, the MIDI 1.0 wire parser
// (running status, real-time bytes interleaved, sysex gathering and its
// capacity limit), feeding the MPE reader and the MIDI 1.0 -> 2.0
// translator (RPN/NRPN/bank state) as a MIDI input port would.
//
// The input is a raw MIDI 1.0 byte stream. It is delivered in chunks (the
// first byte picks the chunk size) because the reader keeps its state across
// calls, as it does across a port's buffers.
#include <q/midi/byte_reader.hpp>
#include <q/midi/mpe.hpp>
#include <q/midi/translate.hpp>
#include <cstddef>
#include <cstdint>

namespace q = cycfi::q;
namespace midi = q::midi_1_0;
namespace midi2 = q::midi_2_0;

namespace
{
   struct sink1 : midi::processor
   {
      using midi::processor::operator();

      void operator()(midi::note_on m, std::size_t t)
      { _sum += m.channel() + m.key() + m.velocity() + t; }
      void operator()(midi::control_change m, std::size_t t)
      { _sum += m.channel() + std::size_t(m.controller()) + m.value() + t; }
      void operator()(midi::sysex_view, std::size_t t)
      { _sum += t; }

      std::size_t _sum = 0;
   };

   struct sink2 : midi2::processor
   {
      using midi2::processor::operator();

      void operator()(midi2::note_on m, std::size_t)
      { _sum += m.word(0) + m.word(1); }
      void operator()(midi2::registered_controller m, std::size_t)
      { _sum += m.word(0) + m.word(1); }
      void operator()(midi2::assignable_controller m, std::size_t)
      { _sum += m.word(0) + m.word(1); }

      std::size_t _sum = 0;
   };
}

extern "C" int LLVMFuzzerTestOneInput(std::uint8_t const* data, std::size_t size)
{
   if (size < 1)
      return 0;
   std::size_t const chunk = (data[0] % 16) + 1;
   ++data;
   --size;

   sink1 plain;
   sink1 mpe_out;
   sink2 up_out;
   midi::mpe_reader<sink1&> mpe{mpe_out};
   midi2::to_midi2<sink2&> up{up_out};

   midi::byte_reader<> r1;
   midi::byte_reader<> r2;
   midi::byte_reader<8> small;     // a tiny sysex capacity, to reach the drop path

   std::size_t time = 0;
   for (std::size_t i = 0; i < size; i += chunk, ++time)
   {
      std::size_t const n = (size - i) < chunk ? (size - i) : chunk;
      q::byte_span const bytes{data + i, n};
      r1(bytes, time, mpe);
      r2(bytes, time, up);
      small(bytes, time, plain);
   }
   volatile std::size_t sum =
      plain._sum + mpe_out._sum + up_out._sum + small.drops() + r1.drops();
   (void)sum;
   return 0;
}
