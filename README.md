# Real IP from Cloudflare Proxy/Tunnel

[![Code Coverage](https://codecov.io/gh/poesterlin/cloudflarewarp/branch/master/graph/badge.svg?token=QFGZS5QJSG)](https://codecov.io/gh/poesterlin/cloudflarewarp)
[![Code Analysis](https://github.com/poesterlin/cloudflarewarp/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/poesterlin/cloudflarewarp/actions/workflows/codeql-analysis.yml)
[![Codacy Security Scan](https://github.com/poesterlin/cloudflarewarp/actions/workflows/codacy-analysis.yml/badge.svg)](https://github.com/poesterlin/cloudflarewarp/actions/workflows/codacy-analysis.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/poesterlin/cloudflarewarp)](https://goreportcard.com/report/github.com/poesterlin/cloudflarewarp)
[![Build and Test Source](https://github.com/poesterlin/cloudflarewarp/actions/workflows/buildAndTest.yml/badge.svg)](https://github.com/poesterlin/cloudflarewarp/actions/workflows/buildAndTest.yml)
[![Integration Test](https://github.com/poesterlin/cloudflarewarp/actions/workflows/prodTest.yml/badge.svg)](https://github.com/poesterlin/cloudflarewarp/actions/workflows/prodTest.yml)

If Traefik is behind a Cloudflare Proxy/Tunnel, it won't be able to get the real IP from the external client as well as other information.

This plugin solves this issue by overwriting the X-Real-IP and X-Forwarded-For with an IP from the CF-Connecting-IP header.  
The real IP will be the Cf-Connecting-IP if the request comes from Cloudflare or another trusted IP in the configuration file.  
The plugin also writes the CF-Visitor scheme to the X-Forwarded-Proto. (This fixes an infinite redirect issue for wordpress when using CF[443]->PROXY/TUNNEL->Traefik[80]->WP[80])

When a trusted request does not include any Cloudflare-specific headers, the plugin treats it as direct/local traffic. In that case it sets X-Real-IP from the direct remote address but does not overwrite X-Forwarded-For. This avoids producing malformed forwarded chains such as `, 172.18.0.1` for local split-DNS, Docker network, Tailscale, or other non-Cloudflare paths.

## Configuration

### Configuration documentation

Supported configurations per body

| Setting        | Allowed values | Required | Description                                         |
| :------------- | :------------- | :------- | :-------------------------------------------------- |
| trustip        | []string       | No       | IP or IP range to trust                             |
| disableDefault | bool           | Yes      | Disable the built in list of CloudFlare IPs/Servers |

### Notes re CloudFlare

One thing included in this plugin is we bundle the CloudFlare server IPs with it, so you do not have to define them manually.  
However on the flip-side, if you want to, you can just disable them by setting `disableDefault` to `true`.

If you do not define `trustip` and `disableDefault`, it doesn't seem to load the plugin, so just set `disableDefault` to `false` and you are able to use the default IP list.

### Notes re local or split-DNS traffic

If the same Traefik entrypoint handles both Cloudflare traffic and direct local traffic, add your local proxy or container network to `trustip`. The plugin now distinguishes trusted Cloudflare traffic from trusted local traffic by checking whether Cloudflare-specific headers are present.

- Trusted request with `Cf-Connecting-Ip` or `Cf-Visitor`: Cloudflare mode. `X-Forwarded-For` and `X-Real-Ip` are set from `Cf-Connecting-Ip`.
- Trusted request without Cloudflare headers: direct/local mode. `X-Real-Ip` is set from the direct remote address, and `X-Forwarded-For` is preserved.
- Untrusted request: Cloudflare headers are removed and `X-Real-Ip` is set from the direct remote address.

This makes the middleware safe to attach globally to an entrypoint that serves Cloudflare Tunnel, local LAN, Docker, or Tailscale clients.

### Enable the plugin

```yaml
experimental:
  plugins:
    cloudflarewarp:
      moduleName: github.com/poesterlin/cloudflarewarp
      version: v1.4.0
```

### Plugin configuration

```yaml
http:
  middlewares:
    cloudflarewarp:
      plugin:
        cloudflarewarp:
          disableDefault: false
          trustip: # Trust IPS not required if disableDefault is false - we will allocate Cloud Flare IPs automatically
            - "2400:cb00::/32"

  routers:
    my-router:
      rule: Path(`/whoami`)
      service: service-whoami
      entryPoints:
        - http
      middlewares:
        - cloudflarewarp

  services:
    service-whoami:
      loadBalancer:
        servers:
          - url: http://127.0.0.1:5000
```

# Testing

[https://github.com/poesterlin/cloudflarewarp/tree/master/test](https://github.com/poesterlin/cloudflarewarp/tree/master/test)

We have written the following tests in this repo:

- golang linting
- yaegi tests (validate configuration matches what Traefik expects)
- General GO code coverage
- Virtual implementation tests (spin up traefik with yml/toml tests to make sure the plugin actually works)
- Live implementation tests (spin up traefik with the plugin definition as it would be for you, and run the same tests again)

These tests allow us to make sure the plugin is always functional with Traefik and Traefik version updates.

# Standing up the crowdsec bouncer plugin in traefik

See the following blog post for a walkthrough on how to stand up the crowdsec bouncer plugin in traefik: [https://bpto.li/H0JY11Zb](https://bpto.li/H0JY11Zb)
