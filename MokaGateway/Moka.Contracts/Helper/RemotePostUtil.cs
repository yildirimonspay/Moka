namespace Moka.Contracts.Helper
{
    using Microsoft.AspNetCore.Mvc;
    using System.Text;
    using System.Text.Encodings.Web;

    public static class RemotePostUtil
    {
        // Uygulama ayarlarından ya da DI'dan gelebilir
        private static readonly HashSet<string> AllowedHosts = new(StringComparer.OrdinalIgnoreCase)
    {
        "bank.example.com",
        "secure.payprovider.com"
        // ...ekle
    };

        public static ContentResult ToUrlAutoPost(string url, IDictionary<string, string> fields)
        {
            // 1) URL doğrulama + HTTPS zorunluluğu
            if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps)
                throw new ArgumentException("Invalid url (absolute HTTPS required).");

            // 2) Host allowlist
            if (!AllowedHosts.Contains(uri.Host))
                throw new ArgumentException("Target host is not allowed.");

            // 3) Nonce üret (CSP için)
            var nonce = Convert.ToBase64String(Guid.NewGuid().ToByteArray());

            var enc = HtmlEncoder.Default;
            var sb = new StringBuilder(1024);
            sb.AppendLine("<!doctype html>");
            sb.AppendLine("<html lang=\"tr\"><head>");
            sb.AppendLine("<meta charset=\"utf-8\"/>");

            // 4) Sıkı CSP (sadece bu dokümandaki nonce'lı script'e izin ver)
            sb.AppendLine($"<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self' https:; script-src 'nonce-{nonce}'; style-src 'unsafe-inline'; img-src data:; connect-src 'none'\">");

            // 5) Referrer Policy: hiçbir şey sızdırma
            sb.AppendLine("<meta name=\"referrer\" content=\"no-referrer\"/>");
            sb.AppendLine("</head><body>");

            // 6) Form (urlencoded, utf-8)
            sb.AppendLine($"<form id=\"f\" method=\"post\" accept-charset=\"UTF-8\" enctype=\"application/x-www-form-urlencoded\" action=\"{enc.Encode(url)}\">");

            foreach (var kv in fields)
            {
                var name = enc.Encode(kv.Key);
                var value = enc.Encode(kv.Value ?? string.Empty);
                sb.AppendLine($"<input type=\"hidden\" name=\"{name}\" value=\"{value}\" />");
            }

            // JS kapalıysa görünür buton
            sb.AppendLine("<noscript><p>Devam etmek için gönder tuşuna basın.</p><button type=\"submit\">Gönder</button></noscript>");
            sb.AppendLine("</form>");

            // 7) Otomatik submit (nonce'lı inline script)
            sb.AppendLine($"<script nonce=\"{nonce}\">(function(){{var f=document.getElementById('f'); if(f){{ try{{ f.submit(); }}catch(_ ){{}} }} }})();</script>");

            sb.AppendLine("</body></html>");

            return new ContentResult
            {
                Content = sb.ToString(),
                ContentType = "text/html; charset=utf-8",
                StatusCode = 200
            };
        }
    }

}
