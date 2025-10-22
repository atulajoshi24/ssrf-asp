using System.Net;
using System.Numerics;
using System.Text;
using Microsoft.AspNetCore.Mvc;

namespace MyApp.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class FetchController : ControllerBase
    {
        // OPTIONAL: allow only certain hostnames / domains (comment out to disable)
        private static readonly string[] AllowedHostSuffixes = new[] { ".example.com", "api.trusted.com" };

        // Safety limits
        private const int MaxResponseBytes = 5 * 1024 * 1024; // 5 MB

        // Single shared HttpClient (no auto-redirects, short timeout)
        private static readonly HttpClient HttpClient;

        // RFC1918, link-local, loopback, multicast, ULA, etc.

        private sealed class IPAddressRange
        {
            private readonly BigInteger startNum;
            private readonly BigInteger endNum;

            public IPAddress Start { get; }
            public IPAddress End { get; }

            public IPAddressRange(IPAddress start, IPAddress end)
            {
                if (start == null || end == null)
                    throw new ArgumentNullException();

                Start = start;
                End = end;

                var startVal = ToBigInteger(start);
                var endVal = ToBigInteger(end);

                // Ensure start <= end
                if (startVal <= endVal)
                {
                    startNum = startVal;
                    endNum = endVal;
                }
                else
                {
                    startNum = endVal;
                    endNum = startVal;
                }
            }

            public bool Contains(IPAddress address)
            {
                if (address == null) return false;
                var value = ToBigInteger(address);
                return value >= startNum && value <= endNum;
            }

            private static BigInteger ToBigInteger(IPAddress ip)
            {
                var bytes = ip.GetAddressBytes();
                Array.Reverse(bytes); // BigInteger expects little-endian
                return new BigInteger(bytes.Concat(new byte[] { 0 }).ToArray());
            } 

        } 

        private static bool IsInternalIp(IPAddress ip)
        {
            // Define your private IP address ranges
            var privateRanges = new IPAddressRange[]
            {
                new IPAddressRange(IPAddress.Parse("10.0.0.0"), IPAddress.Parse("10.255.255.255")),
                new IPAddressRange(IPAddress.Parse("172.16.0.0"), IPAddress.Parse("172.31.255.255")),
                new IPAddressRange(IPAddress.Parse("192.168.0.0"), IPAddress.Parse("192.168.255.255")),
            };
            // Check if the IP falls within any of these ranges
            // You would need a custom implementation for IPAddressRange
            return privateRanges.Any(r => r.Contains(ip));
        }

        static FetchController()
        {
            var handler = new HttpClientHandler
            {
                AllowAutoRedirect = false
            };

            HttpClient = new HttpClient(handler)
            {
                Timeout = TimeSpan.FromSeconds(10) // simple per-request timeout
            };
        }

        public class FetchRequest { public string Url { get; set; } }

        [HttpPost("fetch")]
        public async Task<IActionResult> Fetch([FromBody] FetchRequest req)
        {
            if (req == null || string.IsNullOrWhiteSpace(req.Url))
                return BadRequest("url is required");

            if (!Uri.TryCreate(req.Url.Trim(), UriKind.Absolute, out var uri))
                return BadRequest("invalid url");

            // only http/https
            if (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps)
                return BadRequest("only http/https allowed");

            // optional domain allowlist
            if (AllowedHostSuffixes.Length > 0 && !IsAllowedByDomainAllowlist(uri.Host))
                return BadRequest("host not allowed");

            // resolve host → validate all IPs
            IPAddress[] addrs;
            try
            {
                addrs = await Dns.GetHostAddressesAsync(uri.Host);
                if (addrs.Length == 0) return BadRequest("no addresses resolved");
            }
            catch (Exception ex)
            {
                return BadRequest($"dns resolution failed: {ex.Message}");
            }

            foreach (var ip in addrs)
            {
                if (IsForbidden(ip)) return BadRequest("resolved address is disallowed");
            }

            // make request (no auto-redirects)
            using var msg = new HttpRequestMessage(HttpMethod.Get, uri);
            using var resp = await HttpClient.SendAsync(msg, HttpCompletionOption.ResponseHeadersRead);

            // refuse manual redirect chains (since auto-redirects are off)
            if ((int)resp.StatusCode is >= 300 and < 400)
                return BadRequest("redirects not allowed");

            // simple size enforcement: if Content-Length present and too big, reject
            if (resp.Content.Headers.ContentLength is long len && len > MaxResponseBytes)
                return BadRequest("content too large");

            await using var stream = await resp.Content.ReadAsStreamAsync();
            using var ms = new MemoryStream();
            var buffer = new byte[8192];
            int read;
            long total = 0;

            while ((read = await stream.ReadAsync(buffer, 0, buffer.Length)) > 0)
            {
                total += read;
                if (total > MaxResponseBytes) return BadRequest("response too large");
                ms.Write(buffer, 0, read);
            }

            var data = ms.ToArray();
            var snippet = TryUtf8(data, Math.Min(256, data.Length));

            return Ok(new
            {
                status = (int)resp.StatusCode,
                contentType = resp.Content.Headers.ContentType?.ToString(),
                size = data.Length,
                snippet
            });
        }

        // ---------- helpers ----------

        private static bool IsAllowedByDomainAllowlist(string host)
        {
            var h = host.ToLowerInvariant();
            return AllowedHostSuffixes.Any(s =>
            {
                var x = s.ToLowerInvariant();
                return h == x || h.EndsWith("." + x) || h.EndsWith(x);
            });
        }

        private static bool IsForbidden(IPAddress ip)
        {
            if (ip == null) return true;

            // normalize IPv4-mapped IPv6 → IPv4
            if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();

            // quick built-ins
            if (IPAddress.IsLoopback(ip)) return true;
            if (ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Any)) return true;

            // ranges
            return IsInternalIp(ip);
        }

        private static string TryUtf8(byte[] data, int count)
        {
            try { return Encoding.UTF8.GetString(data, 0, count); }
            catch { return Convert.ToBase64String(data, 0, count); }
        }
    }
}