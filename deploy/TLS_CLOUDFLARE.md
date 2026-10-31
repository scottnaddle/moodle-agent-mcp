# TLS / Cloudflare 메모

- **도메인은 변수**: 아래에서 `MCP_DOMAIN`(예: `mcp.example.com`)만 자기 도메인으로 바꾸면 됩니다.
- **Let's Encrypt만 쓸 때**: DNS A/AAAA → 서버, `certbot --nginx -d $MCP_DOMAIN`. 갱신은 certbot 타이머가 처리.
- **Cloudflare 프록시(주황 구름) 뒤에 둘 때**
  - SSL/TLS 모드는 **Full (strict)**. 원본에는 Let's Encrypt 또는 Cloudflare Origin Certificate.
  - HTTP-01 발급이 막히면 DNS-01(`certbot-dns-cloudflare`) 사용. API 토큰은 Zone:DNS:Edit 최소 권한.
  - Streamable HTTP는 긴 응답/스트리밍을 쓰므로 Cloudflare 캐시는 `/mcp` 경로에 대해 **Bypass** 규칙.
  - 원본 nginx에서 Cloudflare IP 대역만 allow 하면 원본 직접 접근을 막을 수 있습니다(https://www.cloudflare.com/ips/).
  - Cloudflare Access/WAF를 추가로 걸 수 있지만, MCP 클라이언트는 Bearer 헤더만 보내므로 브라우저 로그인형 Access 정책은 쓰지 마세요(서비스 토큰 방식은 가능).
- `/health`는 인증 없이 열려 있고, `/mcp`는 `Authorization: Bearer <MCP_BEARER_TOKEN>` 필수입니다.
