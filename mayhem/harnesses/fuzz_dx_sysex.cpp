// Fuzz target: cycfi::q::dx_cartridge / dx_voice, the DX7 system exclusive
// (.syx) patch readers (a 32-voice packed bulk dump, or one unpacked voice),
// and what a parsed patch drives next: dx_patcher compiles it for a sample
// rate, and an fm_voice plays a note of it for a few hundred samples.
//
// The input is a .syx file. The byte before the last (the dump's checksum)
// picks the key and velocity the voice is played at; the whole input is
// still what is parsed.
#include <q/synth/fm/dx_sysex.hpp>
#include <q/synth/fm/dx_patcher.hpp>
#include <q/synth/fm/fm_voice.hpp>
#include <q/support/phase.hpp>
#include <cmath>
#include <cstddef>
#include <cstdint>

namespace q = cycfi::q;

namespace
{
   constexpr float sps = 48000.0f;

   void play(q::dx_patch const& patch, std::uint8_t key, float velocity)
   {
      q::dx_patcher p{patch, sps};
      q::fm_voice v{p};
      v.attack(p, key, velocity);
      q::phase_iterator master{
         q::frequency{440.0 * std::exp2((int(key) - 69) / 12.0)}, sps};
      volatile float sum = 0.0f;
      for (int i = 0; i != 256; ++i)
         sum = sum + v(master++);
   }
}

extern "C" int LLVMFuzzerTestOneInput(std::uint8_t const* data, std::size_t size)
{
   q::dx_bytes const bytes{data, size};
   std::uint8_t const k = size >= 2 ? data[size - 2] : 0;
   std::uint8_t const key = k & 0x7F;
   float const velocity = (k >> 7) ? 1.0f : 0.5f;

   if (auto const v = q::dx_voice(bytes))
      play(*v, key, velocity);

   if (auto const bank = q::dx_cartridge(bytes))
   {
      // Every voice is compiled; the first is played.
      for (auto const& patch : *bank)
      {
         q::dx_patcher p{patch, sps};
         volatile float t = p.rate_time[0];
         (void)t;
      }
      play((*bank)[0], key, velocity);
   }
   return 0;
}
