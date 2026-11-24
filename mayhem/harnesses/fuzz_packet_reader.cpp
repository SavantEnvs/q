// Fuzz target: cycfi::q::midi_2_0::packet_reader, the Universal MIDI Packet
// parser (sysex7/sysex8 reassembly, mixed data sets, stream and flex-data
// text reassembly), dispatching into the per-note reader and the
// MIDI 2.0 -> 1.0 translator as a MIDI 2.0 input port would.
//
// The input is a stream of 32-bit words, big-endian as on the wire; each
// packet takes as many words as its message type says (packet::words()).
#include <q/midi/packet_reader.hpp>
#include <q/midi/per_note.hpp>
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
      void operator()(midi2::control_change m, std::size_t)
      { _sum += m.word(0) + m.word(1); }

      std::size_t _sum = 0;
   };

   std::uint32_t word(std::uint8_t const* p)
   {
      return (std::uint32_t(p[0]) << 24) | (std::uint32_t(p[1]) << 16)
         | (std::uint32_t(p[2]) << 8) | std::uint32_t(p[3]);
   }
}

extern "C" int LLVMFuzzerTestOneInput(std::uint8_t const* data, std::size_t size)
{
   sink1 down_out;
   sink2 per_note_out;
   sink2 plain;
   midi2::to_midi1<sink1&> down{down_out};
   midi2::per_note_reader<sink2&> per_note{per_note_out};

   midi2::packet_reader<> r1;
   midi2::packet_reader<> r2;
   midi2::packet_reader<8> small;    // a tiny capacity, to reach the drop path

   std::size_t const nwords = size / 4;
   std::size_t time = 0;
   for (std::size_t i = 0; i < nwords; ++time)
   {
      std::uint32_t w[4] = {word(data + 4 * i), 0, 0, 0};
      midi2::packet const first{w[0]};
      std::size_t const len = first.words();
      if (len < 1 || len > 4 || i + len > nwords)
         break;
      for (std::size_t k = 1; k < len; ++k)
         w[k] = word(data + 4 * (i + k));
      i += len;

      midi2::packet const p{w[0], w[1], w[2], w[3]};
      r1(p, time, down);
      r2(p, time, per_note);
      small(p, time, plain);
   }
   volatile std::size_t sum = down_out._sum + per_note_out._sum + plain._sum
      + r1.drops() + small.drops();
   (void)sum;
   return 0;
}
