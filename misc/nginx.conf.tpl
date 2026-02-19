# vim: ft=nginx
# NOTE: generated from misc/nginx.conf.tpl during `cargo build`
# make sure to escape \{'s not meant for template expansion
daemon off;

{{if multi_process}}
master_process on;
worker_processes 2;
{{else}}
master_process off;
{{endif}}

{{if as_root}}
# CI — to be able to write out coverage data
user root;
{{endif}}

load_module modules/{target}/libngx_pep.{libsuff};

error_log {error_log};
pid {temp_prefix}/logs/nginx.pid;

events \{
    worker_connections  1024;
}

http \{

    map $http_upgrade $connection_upgrade \{
      default upgrade;
      ''      '';
    }
    proxy_read_timeout 300s;

    include       mime.types;
    default_type  application/octet-stream;

    log_format  main '$remote_addr - $remote_user [$time_local] "$request" '
                     '$status $body_bytes_sent $\{request_time}s "$http_referer" '
                     '"$http_user_agent" "$http_x_forwarded_for"';

    client_body_temp_path {temp_prefix}client_body_temp;
    proxy_temp_path {temp_prefix}proxy_temp;
    scgi_temp_path {temp_prefix}scgi_temp;
    uwsgi_temp_path {temp_prefix}uwsgi_temp;

    access_log  {access_log};

    sendfile    on;
    aio         threads;
    aio_write   on;
    tcp_nopush  on;

    keepalive_timeout  65;

    pep_pdp_issuer https://zeta-cd.westeurope.cloudapp.azure.com/auth/realms/zeta-guard;
    # pep_pdp_issuer https://zeta-staging.spree.de/auth/realms/zeta-guard;
    pep_popp_issuer http://localhost:{port};
    # pep_http_client_idle_timeout 30; # s
    # pep_http_client_max_idle_per_host 64;
    # pep_http_client_tcp_keepalive 30; # s
    # pep_http_client_connect_timeout 2; # s
    # pep_http_client_timeout 10; # s
    pep_http_client_accept_invalid_certs on;
    pep_asl_testing on;

    # These options are location configs, but can be declared in http and server levels
    # also to be inherited in lower levels.
    #
    # # enable access phase handler to check access tokens, DPoP and, optionally, PoPP?
    pep                  on;
    # # space separated list of required audiences
    pep_require_aud      "https://zeta-cd.westeurope.cloudapp.azure.com";
    # pep_require_aud      "https://zeta-staging.spree.de";
    # # space separated list of required scopes
    # pep_require_scope    "openid profile email";
    # # clock leeway when checking exp,nbf,iat claims in seconds, default: 60
    # pep_leeway           60;
    # # implied dpop validity in s: iat + pep_dpop_validity + pep_leeway
    # pep_dpop_validity    300;
    # # validate PoPP header and pass along decoded claims as ZETA-PoPP-Token-Content?
    pep_require_popp    off;
    # # implied ppop validity in s
    # pep_ppop_validity    31536000;

    server \{
        listen       {port};
        server_name  localhost;

        location /proxy \{
            proxy_http_version 1.1;
            proxy_pass "http://localhost:8001";
        }

        location /ASL \{
            asl on;
            client_body_buffer_size 1m;
            client_max_body_size 1m;
        }

        # helpful for local dev.
        location /jwks.json \{
          pep              off;
          asl              off;
          default_type     application/json;
          alias            html/jwks.json;
          autoindex        off;
        }

        # for integration tests
        location /ready \{
          pep              off;
          asl              off;
          return 200;
        }
        location /empty.json \{
          default_type     application/json;
          alias            html/empty.json;
          autoindex        off;
        }
        location /with_popp.json \{
          default_type     application/json;
          alias            html/empty.json;
          autoindex        off;
          pep_require_popp on;
        }

        # see tests/common/echo.rs
        location /echo/ \{
          proxy_http_version 1.1;
          proxy_pass "http://127.1.33.7:{echo_port}/";

          location /echo/ready/ \{
            pep off;
            proxy_pass "http://127.1.33.7:{echo_port}/ready/";
          }

          location /echo/ws/ \{
            proxy_pass "http://127.1.33.7:{echo_port}/ws/";

            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection $connection_upgrade;
          }
        }
        location /echo-with-popp/ \{
          proxy_pass "http://127.1.33.7:{echo_port}/";
          pep_require_popp on;
        }
    }
}
