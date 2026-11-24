// Fuzz target: the MIDI-CI responder side, cycfi::q::midi_ci —
// property_responder (Property Exchange: header JSON, chunk gathering, Set
// buffers, subscriptions) in front of profile_responder (profile inquiry,
// set on/off, details) in front of responder (discovery, NAK/ACK, endpoint
// and process inquiry). This is the chain a device builds to answer MIDI-CI
// (test/midi/midi_ci_profiles.cpp, "Responders nest").
//
// The input is a raw MIDI 1.0 byte stream: byte_reader frames the sysex
// messages (F0 ... F7) and each one is handed to the chain, which keeps its
// state across messages within the input. Replies go to a sink.
#include <q/midi/byte_reader.hpp>
#include <q/midi/ci.hpp>
#include <q/midi/profiles.hpp>
#include <q/midi/property_exchange.hpp>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

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

   std::uint32_t fixed_random() { return 0x1234567; }

   ci::identity const me{0x002109, 0x0102, 0x0304, 0x01020304};

   std::string_view const resources =
      R"([{"resource":"DeviceInfo"},{"resource":"ChannelList"},{"resource":"State"}])";
   std::string_view const device_info =
      R"({"manufacturerId":[0,33,9],"familyId":[2,2]})";

   struct device
   {
      std::string_view property(std::string_view name) const
      {
         if (name == ci::resource_list)
            return resources;
         if (name == "DeviceInfo")
            return device_info;
         if (name == "State")
            return {reinterpret_cast<char const*>(_state.data()), _state.size()};
         return {};
      }

      int set_property(std::string_view name, q::byte_span data)
      {
         if (name != "State")
            return ci::pe_reply::not_found;
         _state.assign(data.begin(), data.end());
         return ci::pe_reply::ok;
      }

      std::vector<std::uint8_t> _state;
   };

   template <typename Chain>
   struct forward : midi::processor
   {
      using midi::processor::operator();

      forward(Chain& chain, sink& out) : _chain(chain), _out(out) {}

      void operator()(midi::sysex_view msg, std::size_t)
      {
         _chain(msg, _out);
      }

      Chain& _chain;
      sink& _out;
   };
}

extern "C" int LLVMFuzzerTestOneInput(std::uint8_t const* data, std::size_t size)
{
   std::vector<ci::profile> profiles{
      {ci::profile_id{0x7E, 0x40, 0x01, 0x01, 0x01}, ci::to_function_block, true, false, 0, 0}
    , {ci::profile_id{0x00, 0x21, 0x09, 0x01, 0x01}, ci::to_function_block, false, false, 0, 0}
    , {ci::profile_id{0x7E, 0x41, 0x01, 0x01, 0x01}, 0x00, false, false, 0, 0}};

   using discovery_type = ci::responder<std::uint32_t(*)()>;
   using profiles_type = ci::profile_responder<discovery_type&>;
   using properties_type = ci::property_responder<device&, profiles_type&>;

   discovery_type discovery{me, fixed_random};
   profiles_type in_front{std::span<ci::profile>{profiles}, discovery};
   device dev;
   properties_type outermost{dev, in_front};
   sink out;

   forward<properties_type> fwd{outermost, out};
   midi::byte_reader<> reader;
   reader(q::byte_span{data, size}, 0, fwd);

   volatile std::size_t n = out._bytes + dev._state.size();
   (void)n;
   return 0;
}
