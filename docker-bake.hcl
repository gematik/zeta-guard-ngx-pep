# *_VERSION are defined in build.env
variable "NGINX_VERSION" {}
variable "NGINX_INGRESS_VERSION" {}
variable "RUST_VERSION" {}
variable "HEADERS_MORE_VERSION" {}
variable "AZDO_CRATES_MIRROR_URL" {
  default = ""
}
variable "EXT_IMAGE_PREFIX" {
  default = ""
}
variable "CI_REGISTRY_IMAGE" {
  default = "ngx_pep"
}
variable "CI_COMMIT_REF_SLUG" {
  default = "main"
}
variable "CI_DEFAULT_BRANCH" {
  default = "main"
}
variable "BASE_IMAGE_RUST" {
  default = "${EXT_IMAGE_PREFIX}rust:${RUST_VERSION}-slim-trixie"
}
variable "BASE_IMAGE_NGINX" {
  default = "${EXT_IMAGE_PREFIX}nginxinc/nginx-unprivileged:${NGINX_VERSION}-trixie-otel"
}
variable "BASE_IMAGE_NGINX_INGRESS" {
  default = "${EXT_IMAGE_PREFIX}nginx/nginx-ingress:${NGINX_INGRESS_VERSION}"
}
variable "BASE_IMAGE_DEBIAN" {
  default = "${EXT_IMAGE_PREFIX}debian:trixie"
}
# multiple tags: comma-separated, no space
variable "TAGS" {
  default = "latest"
}
variable "CACHE" {
  default = false
}
variable "SCCACHE" {
  default = false
}
variable "ARTIFACTS" {
  default = false
}
variable "IT_HOST" {
  default = ""
}
variable "IT_P12" {
  default = ""
}
variable "IT_P12_PASS" {
  default = ""
}
variable "SKIP_TESTS" {
  default = ""
}

variable "REF_BUILD_ENV" {
  default = "target:build-env"
}
variable "REF_PEP_BASE" {
  default = "target:pep-base"
}
variable "REF_NGINX_INGRESS_BASE" {
  default = "target:nginx-ingress-base"
}
variable "REF_HEADERS_MORE" {
  default = "target:headers-more"
}
variable "REF_PEP_BUILD" {
  default = "target:pep-build"
}

group "default" {
  targets = ["package"]
}

group "base" {
  targets = ["build-env", "pep-base", "nginx-ingress-base"]
}

group "aux-build" {
  targets = ["headers-more"]
}

group "package" {
  // load-dispenser excluded, as it needs ./keystores setup. Plain `docker bake` locally
  // would fail otherwise.
  targets = ["pep", "hsm-sim", "nginx-ingress"]
}

function "image_name" {
  params = [name]
  result = name == "" ? "" : "/${name}"
}

function "image_tags" {
  params = [name]
  result = formatlist("${CI_REGISTRY_IMAGE}${image_name(name)}:%s", split(",", TAGS))
}

# restore from <branch>-cache, fallback to main-cache
function "cache_froms" {
  params = [name]
  result = CACHE ? [
    "type=registry,ref=${CI_REGISTRY_IMAGE}${image_name(name)}:${CI_COMMIT_REF_SLUG}-cache0",
    "type=registry,ref=${CI_REGISTRY_IMAGE}${image_name(name)}:${CI_DEFAULT_BRANCH}-cache0",
  ] : [""]
}

function "cache_tos" {
  params = [name]
  result = CACHE ? ["type=registry,ref=${CI_REGISTRY_IMAGE}${image_name(name)}:${CI_COMMIT_REF_SLUG}-cache0,mode=max,compression=zstd,compression-level=7"] : [""]
}

target "_common" {
  args = { BUILDKIT_SYNTAX = "${EXT_IMAGE_PREFIX}docker/dockerfile:1" }
}

target "_crates_mirror" {
  secret = ["id=azdo_pat,type=file,env=AZDO_CRATES_PAT"]
  args = {
    AZDO_CRATES_MIRROR_URL = AZDO_CRATES_MIRROR_URL
  }
}

target "_sccache" {
  args = {
    RUSTC_WRAPPER = SCCACHE ? "sccache" : ""
    SCCACHE_REDIS = SCCACHE ? "redis://sccache-redis:6379" : "" # terraform/gematik-azure/ci/sccache_redis.tf
    CC            = SCCACHE ? "sccache clang" : ""
  }
}

target "pep-base" {
  inherits   = ["_common"]
  dockerfile = "misc/docker/pep-base.Dockerfile"
  contexts = {
    nginx = "docker-image://${BASE_IMAGE_NGINX}"
  }
  cache-from = cache_froms("pep-base")
  cache-to   = cache_tos("pep-base")
  tags       = image_tags("pep-base")
}

target "nginx-ingress-base" {
  inherits   = ["_common"]
  dockerfile = "misc/docker/nginx-ingress-base.Dockerfile"
  contexts = {
    nginx-ingress = "docker-image://${BASE_IMAGE_NGINX_INGRESS}"
  }
  cache-from = cache_froms("nginx-ingress-base")
  cache-to   = cache_tos("nginx-ingress-base")
  tags       = image_tags("nginx-ingress-base")
}

target "build-env" {
  inherits   = ["_common", "_crates_mirror", "_sccache"]
  dockerfile = "misc/docker/build-env.Dockerfile"
  contexts = {
    rust = "docker-image://${BASE_IMAGE_RUST}"
  }
  cache-from = cache_froms("build-env")
  cache-to   = cache_tos("build-env")
  tags       = image_tags("build-env")
}

target "headers-more" {
  inherits   = ["_common", "_crates_mirror", "_sccache"]
  dockerfile = "misc/docker/headers-more.Dockerfile"
  contexts = {
    build-env = REF_BUILD_ENV
  }
  args = {
    NGINX_VERSION        = NGINX_VERSION
    HEADERS_MORE_VERSION = HEADERS_MORE_VERSION
  }
  cache-from = cache_froms("headers-more")
  cache-to   = cache_tos("headers-more")
  tags       = formatlist("${CI_REGISTRY_IMAGE}/headers-more:%s", split(",", TAGS))
}

target "pep-build" {
  inherits   = ["_common", "_crates_mirror", "_sccache"]
  dockerfile = "misc/docker/pep-build.Dockerfile"
  contexts = {
    build-env = REF_BUILD_ENV
  }
  args = {
    NGINX_VERSION = NGINX_VERSION
    SKIP_TESTS = SKIP_TESTS
  }
  secret = IT_HOST == "" ? [] : [
    "id=it_host,type=env,env=IT_HOST",
    "id=it_p12,type=file,src=${IT_P12}",
    "id=it_p12_pass,type=env,env=IT_P12_PASS",
  ]
  cache-from = cache_froms("pep-build")
  cache-to   = cache_tos("pep-build")
  tags       = image_tags("pep-build")

  output = ARTIFACTS ? [
    "type=image",
    "type=local,dest=./artifacts,mode=delete"
  ] : ["type=image"]
}

target "pep" {
  inherits   = ["_common"]
  dockerfile = "misc/docker/pep.Dockerfile"
  contexts = {
    pep-base     = REF_PEP_BASE
    pep-build    = REF_PEP_BUILD
    headers-more = REF_HEADERS_MORE
  }
  cache-from = cache_froms("")
  cache-to   = cache_tos("")
  tags       = image_tags("")
}

target "load-dispenser" {
  inherits   = ["_common"]
  dockerfile = "misc/docker/load-dispenser.Dockerfile"
  contexts = {
    pep-build = REF_PEP_BUILD
    keystores = "./keystores"
  }
  cache-from = cache_froms("load-dispenser")
  cache-to   = cache_tos("load-dispenser")
  tags       = image_tags("load-dispenser")
}

target "hsm-sim" {
  inherits   = ["_common"]
  dockerfile = "misc/docker/hsm-sim.Dockerfile"
  contexts = {
    debian    = "docker-image://${BASE_IMAGE_DEBIAN}"
    pep-build = REF_PEP_BUILD
  }
  cache-from = cache_froms("hsm_sim")
  cache-to   = cache_tos("hsm_sim")
  tags       = image_tags("hsm_sim")
}

target "nginx-ingress" {
  inherits   = ["_common"]
  dockerfile = "misc/docker/nginx-ingress.Dockerfile"
  contexts = {
    nginx-ingress-base = REF_NGINX_INGRESS_BASE
    pep-build          = REF_PEP_BUILD
    headers-more       = REF_HEADERS_MORE
  }
  cache-from = cache_froms("nginx-ingress")
  cache-to   = cache_tos("nginx-ingress")
  tags       = image_tags("nginx-ingress")
}
