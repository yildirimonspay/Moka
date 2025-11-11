using System.Security.Cryptography;
using System.Text;

namespace Moka.Contracts.Helper;

public static class SignatureUtil
{
 // Builds canonical string: keys ordered alphabetically by key
 public static string BuildCanonical(IDictionary<string,string?> values)
 {
 var ordered = values.OrderBy(k => k.Key, StringComparer.Ordinal);
 var sb = new StringBuilder();
 bool first = true;
 foreach (var kv in ordered)
 {
 if (!first) sb.Append('&');
 first = false;
 sb.Append(kv.Key).Append('=').Append(kv.Value);
 }
 return sb.ToString();
 }

 public static string ComputeHmacHex(string data, string? secret)
 {
 if (string.IsNullOrEmpty(secret)) return string.Empty;
 using var h = new HMACSHA256(Encoding.UTF8.GetBytes(secret));
 return Convert.ToHexString(h.ComputeHash(Encoding.UTF8.GetBytes(data))).ToLowerInvariant();
 }

 public static bool FixedEqualsHex(string? a, string? b)
 {
 if (string.IsNullOrEmpty(a) || string.IsNullOrEmpty(b) || a.Length != b.Length) return false;
 try
 {
 var ba = Convert.FromHexString(a);
 var bb = Convert.FromHexString(b);
 return CryptographicOperations.FixedTimeEquals(ba, bb);
 }
 catch { return false; }
 }
}
