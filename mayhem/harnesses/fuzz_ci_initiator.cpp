// Fuzz target: the MIDI-CI initiator side, cycfi::q::midi_ci —
// property_initiator (Property Exchange reply chunk reassembly, request and
// subscription tables) in front of profile_initiator (profile inquiry
// replies, profile reports) in front of initiator (discovery replies, the
// remote device table), with a responder behind them, as an application
// that talks to MIDI-CI devices builds it (test/midi/midi_ci_*initiator.cpp).
//
// Before the input is read, the initiator asks a known device for its
// capabilities, a resource and a subscription, and for its profiles, so that
// replies have requests to match. The input is a raw MIDI 1.0 byte stream:
// byte_reader frames the sysex messages and each is handed to the chain.
#include <q/midi/byte_reader.hpp>
#include <q/midi/ci.hpp>
#include <q/midi/profiles.hpp>
#include <q/midi/property_exchange.hpp>
#include <cstddef>
#include <cstdint>
#include <string_view>

namespace q = cycfi::q;
namespace midi = q::midi_1_0;
namespace ci = q::midi_ci;

namespace
{
   struct sink
   {
      void operator()(q::byte_span out) { _bytes += out.size(); }
      std::size_t _bytes = 0;
   };

   struct fixed_random
   {
      std::uint32_t operator()() const { return 0x1234567; }
   };

   ci::identity const me{0x002109, 0x0102, 0x0304, 0x01020304};
   ci::remote_device const synth{
      0x0AAAAAA, {0x7D0000, 1, 1, 0}, 0x0C, 512, 0, 0x7F};

   struct my_device
   {
      std::string_view property(std::string_view) const { return {}; }
   };

   // The application at the end of the chain: a responder for messages
   // that are not replies, and the hooks the initiators call.
   struct app
   {
      using responder_type = ci::responder<fixed_random>;
      using properties_type = ci::property_responder<my_device&, responder_type&>;

      template <typename Send>
      void operator()(midi::sysex_view msg, Send&& send) { _properties(msg, send); }
      std::uint32_t muid() const { return _properties.muid(); }
      template <typename Send>
      void announce(Send&& send) { _properties.announce(send); }

      void device_added(ci::remote_device const& d) { _sum += d.muid; }
      void device_removed(std::uint32_t muid) { _sum += muid; }
      void profile_state(
         std::uint32_t muid, std::uint8_t address
       , ci::profile_id const& id, bool enabled)
      { _sum += muid + address + id.byte1 + enabled; }
      void profiles_listed(std::uint32_t muid) { _sum += muid; }
      void property_reply(
         std::uint32_t muid, int request, int status
       , std::string_view header, q::byte_span data)
      { _sum += muid + request + status + header.size() + data.size(); }
      void property_update(
         std::uint32_t muid, std::string_view id
       , std::string_view command, q::byte_span data)
      { _sum += muid + id.size() + command.size() + data.size(); }
      void property_capabilities(std::uint32_t muid, int requests)
      { _sum += muid + requests; }

      my_device         _device;
      responder_type    _responder{me, fixed_random{}};
      properties_type   _properties{_device, _responder};
      std::size_t       _sum = 0;
   };

   using discovery_type = ci::initiator<app&>;
   using profiles_type = ci::profile_initiator<discovery_type&>;
   using properties_type = ci::property_initiator<profiles_type&, 4096, 4>;

   struct forward : midi::processor
   {
      using midi::processor::operator();

      forward(properties_type& chain, sink& out) : _chain(chain), _out(out) {}

      void operator()(midi::sysex_view msg, std::size_t)
      {
         _chain(msg, _out);
      }

      properties_type& _chain;
      sink& _out;
   };
}

extern "C" int LLVMFuzzerTestOneInput(std::uint8_t const* data, std::size_t size)
{
   app application;
   discovery_type discovery{application, 1000};
   profiles_type profiles{discovery};
   properties_type properties{profiles, 1000};
   sink out;

   properties.capabilities(synth, out);
   properties.get(synth, "DeviceInfo", out);
   properties.subscribe(synth, "State", out);
   profiles.ask(synth, out);

   forward fwd{properties, out};
   midi::byte_reader<> reader;
   reader(q::byte_span{data, size}, 0, fwd);
   properties.poll(500);

   volatile std::size_t n = out._bytes + application._sum;
   (void)n;
   return 0;
}
