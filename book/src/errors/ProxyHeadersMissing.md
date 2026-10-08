# ProxyHeadersMissing

## Summary
This is **not a client error** — it is a PEP misconfiguration.

The matched `proxy_pass` location did not `include proxy_headers.conf;`, so the
`proxy_set_header` directives that strip client-supplied credentials
(`Authorization`, `DPoP`, `popp`) before forwarding upstream are not in effect.
Rather than authorize a request whose credentials would then leak to the
upstream, the PEP refuses it.

## Fix
Add the include to the offending location:

```nginx
location /your/proxied/path/ {
    include proxy_headers.conf;
    proxy_pass http://upstream;
}
```

Note that nginx's `proxy_set_header` inheritance is **non-additive**: a location
that declares *any* `proxy_set_header` of its own does not inherit the parent's
set. So if you add your own `proxy_set_header` in a (nested) location, you must
re-`include proxy_headers.conf;` in that same location.
