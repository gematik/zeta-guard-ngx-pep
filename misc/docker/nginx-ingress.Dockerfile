FROM nginx-ingress-base

# debian: OPENSSLDIR: "/usr/lib/ssl"
COPY misc/docker/openssl.cnf /usr/lib/ssl/openssl.cnf
# debian: MODULESDIR: "/usr/lib/x86_64-linux-gnu/ossl-modules"
COPY --from=pep-build /libossl_hsm.so /usr/lib/x86_64-linux-gnu/ossl-modules/

COPY --from=headers-more /ngx_http_headers_more_filter_module.so /etc/nginx/modules/
