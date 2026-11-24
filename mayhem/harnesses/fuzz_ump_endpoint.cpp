// Fuzz target: MIDI 2.0 UMP endpoint discovery, cycfi::q::midi_2_0 —
// endpoint_inquiry (the host side: endpoint info, device identity, name and
// product instance id text gathered into fixed buffers, function block
// table, stream configuration) and stream_responder (the device side: what
// it answers to discovery and function block requests), both fed through
// packet_reader, as in test/midi/midi2_inquiry.cpp.
//
// The input is a stream of 32-bit big-endian words; each packet takes as
// many words as its message type says. Every packet is read by both sides.
#include <q/midi/inquiry.hpp>
#include <q/midi/endpoint.hpp>
#include <q/midi/packet_reader.hpp>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <span>

namespace q = cycfi::q;
namespace midi2 = q::midi_2_0;

namespace
{
   struct synth : midi2::processor
   {
      using midi2::processor::operator();
      void operator()(midi2::note_on, std::size_t) { ++_notes; }
      std::size_t _notes = 0;
   };

   midi2::function_block const blocks[] =
   {
      {true, midi2::direction::bidirectional, 0, midi2::ui_hint::both
       , 0, 1, 0x02, 0, "Keys"}
    , {true, midi2::direction::output, 0, midi2::ui_hint::sender
       , 1, 2, 0x02, 0, "Strings"}
   };

   std::uint32_t word(std::uint8_t const* p)
   {
      return (std::uint32_t(p[0]) << 24) | (std::uint32_t(p[1]) << 16)
         | (std::uint32_t(p[2]) << 8) | std::uint32_t(p[3]);
   }
}

extern "C" int LLVMFuzzerTestOneInput(std::uint8_t const* data, std::size_t size)
{
   midi2::endpoint_description device{
      "Q Endpoint", "SN-001", {0x002109, 0x0102, 0x0304, 0x01020304}
    , true, true, false, false, midi2::protocol::midi2, true
    , std::span<midi2::function_block const>{blocks}};

   synth host_synth;
   synth device_synth;
   midi2::endpoint_inquiry<synth&> inquiry{host_synth};
   midi2::packet_reader<> host_reader;
   midi2::packet_reader<> device_reader;
   std::size_t sent = 0;

   // The host asks first, as it would on connecting.
   inquiry.poll([&](midi2::packet const&) { ++sent; }, 0);

   std::size_t const nwords = size / 4;
   std::size_t time = 1;
   for (std::size_t i = 0; i < nwords; ++time)
   {
      std::uint32_t w[4] = {word(data + 4 * i), 0, 0, 0};
      std::size_t const len = midi2::packet{w[0]}.words();
      if (len < 1 || len > 4 || i + len > nwords)
         break;
      for (std::size_t k = 1; k < len; ++k)
         w[k] = word(data + 4 * (i + k));
      i += len;
      midi2::packet const p{w[0], w[1], w[2], w[3]};

      host_reader(p, time, inquiry);

      midi2::stream_responder responder{
         device, [&](midi2::packet const&) { ++sent; }, std::ref(device_synth)};
      device_reader(p, time, responder);
   }
   inquiry.poll([&](midi2::packet const&) { ++sent; }, time + 1000000);

   auto const d = inquiry.description();
   std::size_t sum = d.name.size() + d.product_instance_id.size() + d.protocol;
   for (auto const& b : d.blocks)
      sum += b.name.size() + b.first_group + b.groups;
   volatile std::size_t v = sum + sent + inquiry.complete()
      + host_synth._notes + device_synth._notes;
   (void)v;
   return 0;
}
