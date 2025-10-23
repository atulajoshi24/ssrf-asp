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

                    // Define your private IP address ranges
        private static readonly IPAddressRange[] PrivateRanges= new []
        {
            new IPAddressRange(IPAddress.Parse("10.0.0.0"), IPAddress.Parse("10.255.255.255")),
            new IPAddressRange(IPAddress.Parse("172.16.0.0"), IPAddress.Parse("172.31.255.255")),
            new IPAddressRange(IPAddress.Parse("192.168.0.0"), IPAddress.Parse("192.168.255.255")),
        };
        // OPTIONAL: allow only certain hostnames / domains (comment out to disable)
        private static readonly string[] AllowedHostSuffixes = new[] { "mvyywdgkktnvefmgecobk310oeo4vtoh1.oast.fun", "api.trusted.com" };

        // Safety limits
        private const int MaxResponseBytes = 5 * 1024 * 1024; // 5 MB

        // Single shared HttpClient (no auto-redirects, short timeout)
        private static readonly HttpClient HttpClient;

        // RFC1918, link-local, loopback, multicast, ULA, etc.

        private sealed class IPAddressRange
        {
            private readonly IPAddress Start;
            private readonly IPAddress End;

            public IPAddressRange(IPAddress start, IPAddress end)
            {
                if (start == null || end == null)
                    throw new ArgumentNullException();

                // Normalize address family (IPv4 vs IPv6)
                if (start.AddressFamily != end.AddressFamily)
                    throw new ArgumentException("Start and end must be same address family");

                // Ensure Start <= End (lexicographically)
                if (CompareBytes(start, end) <= 0)
                {
                    Start = start;
                    End = end;
                }
                else
                {
                    Start = end;
                    End = start;
                }
            }

            public bool Contains(IPAddress address)
            {
                Console.WriteLine("IPAddress Contains : {0} ",address);
                if (address == null) return false;
                if (address.AddressFamily != Start.AddressFamily) return false;

                return CompareBytes(Start, address) <= 0 &&
                    CompareBytes(address, End) <= 0;
            }

            private static int CompareBytes(IPAddress a, IPAddress b)
            {
                var aBytes = a.GetAddressBytes();
                var bBytes = b.GetAddressBytes();

                // Pad IPv4 addresses to 16 bytes to match IPv6 if needed
                if (aBytes.Length < bBytes.Length)
                    aBytes = PadLeft(aBytes, bBytes.Length);
                else if (bBytes.Length < aBytes.Length)
                    bBytes = PadLeft(bBytes, aBytes.Length);

                for (int i = 0; i < aBytes.Length; i++)
                {
                    int diff = aBytes[i].CompareTo(bBytes[i]);
                    if (diff != 0)
                    {   
                        Console.WriteLine("diff : {0} ",diff);
                        return diff;
                    }
                }
                return 0;
            }

            private static byte[] PadLeft(byte[] bytes, int totalLength)
            {
                var result = new byte[totalLength];
                Buffer.BlockCopy(bytes, 0, result, totalLength - bytes.Length, bytes.Length);
                return result;
            }
        } 

        private static bool IsInternalIp(IPAddress ip)
        {
            Console.WriteLine("IsInternalIp check: {0}",ip);
            // Check if the IP falls within any of these ranges
            // You would need a custom implementation for IPAddressRange
            return PrivateRanges.Any(r => r.Contains(ip));
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

        public class FetchRequest { public required string Url { get; set; } }

        [HttpPost("securefetch")]
        public async Task<IActionResult> SecureFetch([FromBody] FetchRequest req)
        {
            Console.WriteLine("Inside securefetch..");
            if (req == null || string.IsNullOrWhiteSpace(req.Url))
                return BadRequest("url is required");

            if (!Uri.TryCreate(req.Url.Trim(), UriKind.Absolute, out var uri))
                return BadRequest("invalid url");

            Console.WriteLine("scheme: {0} ",uri.Scheme);
            // only http/https
            if (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps)
                return BadRequest("only http/https allowed");

            Console.WriteLine("uri.host: {0} ",uri.Host);
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
                Console.WriteLine("resolved ip : {0} ",ip);
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

        [HttpPost("fetch")]
        public async Task<IActionResult> Fetch([FromBody] FetchRequest req)
        {
            if (req == null || string.IsNullOrWhiteSpace(req.Url))
                return BadRequest("url is required");

            if (!Uri.TryCreate(req.Url.Trim(), UriKind.Absolute, out var uri))
                return BadRequest("invalid url");
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
            Console.WriteLine("host name : {0}",h);
            return AllowedHostSuffixes.Any(s =>
            {
                var x = s.ToLowerInvariant();
                Console.WriteLine("allowed host : {0}",x);
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