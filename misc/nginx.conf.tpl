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
pid {temp_prefix}logs/nginx.pid;

events \{
    worker_connections 1024;
}

http \{
    include common.conf;

    client_body_temp_path {temp_prefix}client_body_temp;
    proxy_temp_path {temp_prefix}proxy_temp;
    scgi_temp_path {temp_prefix}scgi_temp;
    uwsgi_temp_path {temp_prefix}uwsgi_temp;

    access_log {access_log};

    ### Global Config

    # pep_pdp_issuer http://localhost:18080/realms/zeta-guard;
    pep_pdp_issuer https://zeta-cd.westeurope.cloudapp.azure.com/auth/realms/zeta-guard;
    # pep_pdp_issuer https://zeta-dev.westeurope.cloudapp.azure.com/auth/realms/zeta-guard;
    # pep_pdp_issuer https://zeta-staging.spree.de/auth/realms/zeta-guard;
    ## server hosting PoPP entity statement at /.well-known/openid-federation
    ## optional if no locations use pep_require_popp
    pep_popp_issuer http://localhost:{port};
    # pep_http_client_idle_timeout 30; # s
    # pep_http_client_max_idle_per_host 64;
    # pep_http_client_tcp_keepalive 30; # s
    # pep_http_client_connect_timeout 2; # s
    # pep_http_client_timeout 10; # s
    pep_http_client_accept_invalid_certs on;
    pep_asl_testing on;
    pep_asl_signer_cert signer_cert.pem;
    pep_asl_signer_key signer_key.pem;
    pep_asl_ca_cert issuer_cert.pem;
    pep_asl_roots_json roots.json;
    pep_asl_root_ca FAKE.RCA1;
    ## cert: use AuthorityInformationAccess (AIA) from cert (default)
    ## off: disable OCSP checks
    ## https://ocsp.example.org: override responder, ignore cert AIA
    pep_asl_ocsp {ocsp_url};
    pep_asl_ocsp_ttl 1m;
    ## enable or disable no-travel enforcement (ip address consistency)
    # pep_no_travel off;

    ### Location Config

    ## These can be set per-location, but it is recommended to set them once globally, and
    ## only override in specific locations as needed.
    ## enable access phase handler to check access tokens, DPoP and, optionally, PoPP
    pep on;
    ## space separated list of required audiences
    # pep_require_aud "http://localhost:18080";
    pep_require_aud "https://zeta-cd.westeurope.cloudapp.azure.com";
    # pep_require_aud "https://zeta-dev.westeurope.cloudapp.azure.com";
    # pep_require_aud "https://zeta-staging.spree.de";

    ## space separated list of required scopes
    # pep_require_scope "openid profile email";
    ## clock leeway when checking exp,nbf,iat claims in s, default: 60
    # pep_leeway 60;
    ## implied dpop validity in s: iat + pep_dpop_validity + pep_leeway
    # pep_dpop_validity 300;
    ## validate PoPP header and pass along decoded claims as ZETA-PoPP-Token-Content
    # pep_require_popp off;
    # implied ppop validity in s
    # pep_ppop_validity 31536000;

    server \{
        listen {port};
        {{if tls}}
        listen 2{port} ssl;
        ## ssl_certificate doesn't support loading from openssl stores, so tls.p256.pem
        ## must be an actual file prefix/conf/tls.p256.pem, which is committed.
        ## See README.md
        ssl_certificate "tls.p256.pem";
        ssl_certificate_key "store:hsm:tls.p256";
        {{endif}}

        include server_common.conf;

        server_name localhost;

        location /proxy/ \{
            proxy_http_version 1.1;
            proxy_pass "http://localhost:8001/";
        }

        include asl.conf;

        location = /.well-known/signed-jwks \{
          pep off;
          default_type application/jwt;
          alias html/signed-jwks.txt;
        }
        location = /.well-known/openid-federation \{
          pep off;
          default_type application/jwt;
          alias html/openid-federation.txt;
        }

        ## mock /pep/achelos_testfachdienst/hellozeta, e.g. for local asl testing
        location = /pep/achelos_testfachdienst/hellozeta \{
          default_type application/json;
          alias html/empty.json;
        }

        ## for integration tests
        location = /ready/ \{
          pep off;
          return 200;
        }
        location = /empty.json \{
          default_type application/json;
          alias html/empty.json;
        }
        location = /with_popp.json \{
          default_type application/json;
          alias html/empty.json;
          pep_require_popp on;
        }

        ## see tests/common/echo.rs
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
