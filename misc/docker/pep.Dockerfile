# package pep, ossl_hsm, headers-more into nginx runtime image
FROM pep-base

COPY misc/docker/nginx.conf /etc/nginx/nginx.conf
COPY misc/config/main_modules.conf /etc/nginx/
COPY misc/config/main_common.conf /etc/nginx/
COPY misc/config/http_common.conf /etc/nginx/
COPY misc/config/server_common.conf /etc/nginx/
COPY misc/config/asl.conf /etc/nginx/
COPY misc/config/proxy_headers.conf /etc/nginx/
RUN  rm /etc/nginx/conf.d/default.conf
COPY prefix/conf/tls.p256.pem /etc/nginx/
COPY --from=pep-build /libngx_pep.so /etc/nginx/modules/
COPY --from=pep-build /book/. /usr/share/nginx/html/doc
# debian: OPENSSLDIR: "/usr/lib/ssl"
COPY misc/docker/openssl.cnf /usr/lib/ssl/openssl.cnf
# debian: MODULESDIR: "/usr/lib/x86_64-linux-gnu/ossl-modules"
COPY --from=pep-build /libossl_hsm.so /usr/lib/x86_64-linux-gnu/ossl-modules/
COPY --from=headers-more /ngx_http_headers_more_filter_module.so /etc/nginx/modules/
