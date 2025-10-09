# vim: ft=nginx
# NOTE: generated from misc/nginx.conf.tpl during `cargo build`
# make sure to escape \{'s not meant for template expansion
daemon off;

# master_process off;
master_process on;
worker_processes auto;

# load_module modules/debug/libngx_pep.{libsuff};
load_module modules/release/libngx_pep.{libsuff};

# error_log /dev/stdout debug;

events \{
    worker_connections  1024;
}

http \{
    include       mime.types;
    default_type  application/octet-stream;

    # log_format  main  '$remote_addr - $remote_user [$time_local] "$request" '
    #                  '$status $body_bytes_sent "$http_referer" '
    #                  # '"$http_user_agent" "$http_x_forwarded_for"';
    #                  '"$http_x_forwarded_for"';
    #
    # access_log  /dev/stdout  main;

    sendfile        on;

    keepalive_timeout  65;

    pep_issuer https://zeta-dev.spree.de/auth/realms/ngx_pdp_dev;
    # pep_http_client_idle_timeout 30; # s
    # pep_http_client_max_idle_per_host 64;
    # pep_http_client_tcp_keepalive 30; # s
    # pep_http_client_connect_timeout 2; # s
    # pep_http_client_timeout 10; # s
    # pep_http_client_accept_invalid_certs off;

    server \{
        listen       8000;
        server_name  localhost;


        location / \{
            root   html;
            index  index.html;
        }

        location /secret \{
            pep                  on;
            # pep_require_aud_any  "account|other"; # optional, multiple values with |, any one match suffices
            # pep_require_scope    "openid profile email"; # optional, exact string match
            # pep_leeway           60; # s
            # proxy_pass           http://localhost:8001;
            # etag off;
            add_header Cache-Control 'no-cache';
        }

    }
}
