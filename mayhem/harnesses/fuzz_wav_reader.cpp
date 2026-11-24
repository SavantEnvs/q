// Fuzz target: q_io's wav_reader (q_io/src/audio_file.cpp over its vendored
// dr_wav: RIFF/W64 chunk parsing, format and sample conversion to float),
// then q's pitch_detector on the decoded samples, as test/pitch does with
// recorded WAV files.
//
// wav_reader only opens files by name, so the input is written to a
// temporary file under $TMPDIR (default /tmp) and removed afterwards.
#include <q_io/audio_file.hpp>
#include <q/pitch/pitch_detector.hpp>
#include <q/support/literals.hpp>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <unistd.h>
#include <vector>

namespace q = cycfi::q;
using namespace q::literals;

namespace
{
   std::string write_temp(std::uint8_t const* data, std::size_t size)
   {
      char const* dir = std::getenv("TMPDIR");
      std::string path = std::string(dir && *dir ? dir : "/tmp") + "/q_wav_XXXXXX";
      int fd = mkstemp(path.data());
      if (fd < 0)
         return {};
      std::size_t done = 0;
      while (done < size)
      {
         auto n = ::write(fd, data + done, size - done);
         if (n <= 0)
            break;
         done += std::size_t(n);
      }
      ::close(fd);
      if (done != size)
      {
         ::unlink(path.c_str());
         return {};
      }
      return path;
   }
}

extern "C" int LLVMFuzzerTestOneInput(std::uint8_t const* data, std::size_t size)
{
   auto const path = write_temp(data, size);
   if (path.empty())
      return 0;
   {
      q::wav_reader r{path};
      if (r)
      {
         std::size_t const channels = r.num_channels();
         float const sps = r.sps();
         volatile std::uint64_t len = r.length();
         (void)len;

         // Read at most 8192 frames, a buffer at a time.
         std::vector<float> buf(1024 * (channels ? channels : 1));
         std::vector<float> mono;
         for (int i = 0; i != 8 && channels; ++i)
         {
            auto const n = r.read(buf.data(), std::uint32_t(buf.size()));
            for (std::size_t j = 0; j + channels <= n; j += channels)
               mono.push_back(buf[j]);
            if (n < buf.size())
               break;
         }
         r.seek(0);
         r.read(buf.data(), std::uint32_t(buf.size()));

         // The pitch detector needs a sample rate it can analyse at.
         if (std::isfinite(sps) && sps >= 8000.0f && sps <= 192000.0f)
         {
            q::pitch_detector pd{80_Hz, 1000_Hz, sps, -45_dB};
            for (auto s : mono)
            {
               if (!std::isfinite(s))
                  continue;
               if (pd(s))
               {
                  volatile float f = pd.get_frequency();
                  (void)f;
               }
            }
         }
      }
   }
   ::unlink(path.c_str());
   return 0;
}
