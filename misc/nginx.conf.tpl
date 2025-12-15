# vim: ft=nginx
# NOTE: generated from misc/nginx.conf.tpl during `cargo build`
# make sure to escape \{'s not meant for template expansion
daemon off;

# master_process off;
master_process on;
worker_processes auto;

load_module modules/debug/libngx_pep.{libsuff};
# load_module modules/release/libngx_pep.{libsuff};

error_log /dev/stdout debug;
# error_log /dev/stdout;

events \{
    worker_connections  1024;
}

http \{
    include       mime.types;
    default_type  application/octet-stream;

    log_format  main '$remote_addr - $remote_user [$time_local] "$request" '
                     '$status $body_bytes_sent $\{request_time}s "$http_referer" '
                     '"$http_user_agent" "$http_x_forwarded_for"';

    access_log  /dev/stdout  main;

    sendfile    on;
    aio         threads;
    aio_write   on;
    tcp_nopush  on;

    keepalive_timeout  65;

    pep_pdp_issuer https://zeta-cd.westeurope.cloudapp.azure.com/auth/realms/zeta-guard;
    pep_popp_issuer http://localhost:8000;
    # pep_http_client_idle_timeout 30; # s
    # pep_http_client_max_idle_per_host 64;
    # pep_http_client_tcp_keepalive 30; # s
    # pep_http_client_connect_timeout 2; # s
    # pep_http_client_timeout 10; # s
    pep_http_client_accept_invalid_certs on;


    # These options are location configs, but can be declared in http and server levels
    # also to be inherited in lower levels.
    #
    # # enable access phase handler to check access tokens, DPoP and, optionally, PoPP?
    pep                  on;
    # # space separated list of required audiences
    pep_require_aud      "https://zeta-cd.westeurope.cloudapp.azure.com";
    # # space separated list of required scopes
    # pep_require_scope    "openid profile email";
    # # clock leeway when checking exp,nbf,iat claims in seconds, default: 60
    # pep_leeway           60;
    # # implied dpop validity in s: iat + pep_dpop_validity + pep_leeway
    # pep_dpop_validity    300;
    # # validate PoPP header and pass along decoded claims as ZETA-PoPP-Token-Content?
    # pep_require_popp    on;
    # # implied ppop validity in s (TODO: update default, token-gen. sets static iat)
    # pep_ppop_validity    31536000;

    server \{
        listen       8000;
        server_name  localhost;

        location / \{
        }

        location /pep/achelos_testfachdienst/hellozeta \{
            proxy_pass "http://localhost:8001";
            # return 200;
        }

        location /ASL \{
            asl on;
            client_body_buffer_size 1m;
            client_max_body_size 1m;
        }

        # helpful for local dev.
        location /jwks.json \{
          pep           off;
          asl           off;
          default_type  application/json;
          alias         html/jwks.json;
          autoindex     off;
        }
    }
}
