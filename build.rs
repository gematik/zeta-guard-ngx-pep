/*-
 * #%L
 * ngx_pep
 * %%
 * (C) tech@Spree GmbH, 2026, licensed for gematik GmbH
 * %%
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * *******
 *
 * For additional notes and disclaimer from gematik and in case of changes by gematik find details in the "Readme" file.
 * #L%
 */

use std::{
    env,
    fs::{self, create_dir_all},
    io::{self, ErrorKind},
    path::{Path, PathBuf},
    process::Command,
    process::Stdio,
};

use anyhow::{Context, Result, bail};
use schemars::schema::RootSchema;
use schemars::visit::{Visitor, visit_schema_object};
use serde::Serialize;
use tinytemplate::TinyTemplate;
use typify::{TypeSpace, TypeSpaceSettings};

fn get_nginx_source_dir(build_dir: &Path) -> PathBuf {
    // nginx-sys sets build_dir = source_dir.join("objs"), so the parent is the source dir
    build_dir
        .parent()
        .expect("nginx build_dir has a parent")
        .to_path_buf()
}

#[derive(Serialize)]
struct ConfigFile {
    name: String,
    pdp_host: String,
    libsuff: String,
    target: String,
    // which module .so to load: "dev" (default features, target/module,
    // built via `cargo module`) or "test" (`its` feature for the tarpc control
    // socket, target/module-test, built by the nextest setup script). The
    // symlinks live in prefix/modules/libngx_pep.{variant}.{target}.{libsuff}.
    variant: String,
    multi_process: bool,
    error_log: String,
    access_log: String,
    port: u16,
    // IT: embedded echo server port for upstream tests
    echo_port: u16,
    no_travel: String,
    // IT: set to mock server representing PDP's sid revocation service (no-travel blocks) —
    // defaults to an URL derived from pdp_issuer otherwise
    revocation_url: Option<String>,
    // pep_asl_ocsp value: "off" or "http://127.0.0.1:{port}"
    ocsp_url: String,
    temp_prefix: String,
    // adds 'user root;' for CI (coverage), no effect when master is not root (e.g. locally)
    as_root: bool,
    // enable tls via ossl_hsm
    tls: bool,
    // pep_require_popp
    require_popp: String,
}

impl ConfigFile {
    fn new() -> Self {
        println!("cargo:rerun-if-env-changed=IT_HOST");
        ConfigFile {
            name: "nginx".to_string(),
            pdp_host: env::var("IT_HOST")
                .unwrap_or("zeta-cd.westeurope.cloudapp.azure.com".to_string()),
            #[cfg(target_os = "macos")]
            libsuff: "dylib".to_string(),
            #[cfg(not(target_os = "macos"))]
            libsuff: "so".to_string(),
            target: "debug".to_string(),
            variant: "dev".to_string(),
            multi_process: false, // set to false for easier debugging — test should use true
            error_log: "/dev/stdout".to_string(),
            access_log: "/dev/stdout main".to_string(),
            port: 8000,
            echo_port: 8100, // should be port + 100
            no_travel: "on".to_string(),
            revocation_url: None,
            ocsp_url: "off".to_string(),
            temp_prefix: "".to_string(),
            as_root: false,
            tls: false,
            require_popp: "off".to_string(),
        }
    }

    fn write(&self) -> anyhow::Result<()> {
        let mut tt = TinyTemplate::new();
        let sauce = "misc/nginx.conf.tpl";
        let text = fs::read_to_string(sauce)?;
        let filename = format!("{}.conf", self.name);
        let path = format!("prefix/conf/{filename}");
        eprintln!("{sauce} → {path}");
        tt.add_template(&filename, &text).map_err(|e| {
            io::Error::new(
                ErrorKind::InvalidData,
                format!("Unable to parse {sauce}: {e}"),
            )
        })?;

        fs::write(
            &path,
            tt.render(&filename, &self).map_err(|e| {
                io::Error::new(
                    ErrorKind::InvalidData,
                    format!("Unable to render {path}: {e}"),
                )
            })?,
        )?;
        Ok(())
    }
}

pub fn install_config() -> Result<()> {
    println!("cargo:rerun-if-changed=misc/nginx.conf.tpl");

    let main_config = ConfigFile::new();
    main_config.write()?;
    // prepare ephemeral prefixes for integration tests by symlinking prefix and rendering
    // configuration for a range of ports. This allows starting multiple tests in parallel.
    //
    // see also: tests/common/mod.rs
    for port in 8003..=8006 {
        let mut test_config = ConfigFile::new();
        test_config.name = format!("test-{port}");
        test_config.variant = "test".to_string();
        test_config.multi_process = true;
        // All test instances share a single log file for easier debugging
        test_config.error_log = "test.log".to_string();
        test_config.access_log = "test.log main".to_string();
        test_config.port = port;
        test_config.echo_port = port + 100; // e.g. 8003 → 8103
        test_config.no_travel = "on".to_string();
        test_config.revocation_url = Some(format!("http://127.0.0.1:{}", port + 400));
        test_config.ocsp_url = format!("http://127.0.0.1:{}", port + 300);
        test_config.temp_prefix = format!("{}/", test_config.name);
        test_config.as_root = true; // needed in CI to write out coverage data
        test_config.tls = true; // IT start an in-process hsm-sim and tests tls with it
        test_config.require_popp = "off".to_string();
        test_config.write()?;
        let test_dir = Path::new("prefix").join(format!("test-{port}"));
        create_dir_all(&test_dir)?;

        for dir in [
            "logs",
            "client_body_temp",
            "proxy_temp",
            "scgi_temp",
            "uwsgi_temp",
        ] {
            create_dir_all(test_dir.join(dir))?;
        }
    }
    Ok(())
}

pub fn make_install() -> Result<()> {
    println!("cargo:rerun-if-env-changed=NGX_CONFIGURE_ARGS");
    println!("cargo:rerun-if-env-changed=MAKE");

    let make = env::var("MAKE").unwrap_or_else(|_| "make".to_string());
    let jobs = env::var("NUM_JOBS").unwrap_or_else(|_| {
        std::thread::available_parallelism()
            .map(|n| n.to_string())
            .unwrap_or("1".to_string())
    });

    let build_dir = std::env::var("DEP_NGINX_BUILD_DIR").unwrap();
    let build_dir = Path::new(&build_dir);
    let source_dir = get_nginx_source_dir(build_dir);

    eprintln!(
        "running `{make} -f {}/Makefile -j{jobs} install` in {}",
        build_dir.display(),
        source_dir.display()
    );

    Command::new(&make)
        .arg("-f")
        .arg(build_dir.join("Makefile"))
        .arg(format!("-j{jobs}"))
        .arg("install")
        .current_dir(&source_dir)
        .status()?;
    install_config()?;
    Ok(())
}

fn load_schema(path: &Path) -> Result<RootSchema> {
    println!("cargo:rerun-if-changed={}", path.display());
    let content = fs::read_to_string(path)
        .with_context(|| format!("reading schema file {}", path.display()))?;
    let schema: RootSchema = serde_yaml_ng::from_str(&content).with_context(|| "parsing schema")?;
    Ok(schema)
}

struct Resolver {
    path: PathBuf,
}

impl Resolver {
    fn new(path: PathBuf) -> Self {
        Resolver { path }
    }
}

impl Visitor for Resolver {
    fn visit_schema_object(&mut self, schema: &mut schemars::schema::SchemaObject) {
        if let Some(reference) = schema.reference.clone()
            && !reference.starts_with('#')
        {
            let sub = resolve_schema(self.path.join(reference)).expect("schema");
            *schema = sub.schema;
        }
        visit_schema_object(self, schema);
    }
}

fn resolve_schema(path: PathBuf) -> Result<RootSchema> {
    let mut root = load_schema(&path)?;
    let mut resolver = Resolver::new(path.parent().expect("parent").to_path_buf());

    resolver.visit_schema_object(&mut root.schema);
    Ok(root)
}

fn generate_schema() -> Result<()> {
    let schemas = vec![
        resolve_schema(Path::new("./src/schema/access-token.yaml").to_path_buf())?,
        resolve_schema(Path::new("./src/schema/client-data.yaml").to_path_buf())?,
        resolve_schema(Path::new("./src/schema/zeta-user-info.yaml").to_path_buf())?,
        resolve_schema(Path::new("./src/schema/dpop-token.yaml").to_path_buf())?,
        resolve_schema(Path::new("./src/schema/zeta-error.yaml").to_path_buf())?,
    ];

    let mut type_space =
        TypeSpace::new(TypeSpaceSettings::default().with_derive("PartialEq".to_string()));
    for schema in schemas {
        type_space.add_root_schema(schema)?;
    }

    let contents =
        prettyplease::unparse(&syn::parse2::<syn::File>(type_space.to_stream()).unwrap());
    let out_file = Path::new(&env::var("OUT_DIR").unwrap()).join("typify.rs");
    fs::write(out_file, contents)?;
    Ok(())
}

fn generate_book() -> Result<()> {
    println!("cargo:rerun-if-changed=book/src");
    println!("cargo:rerun-if-changed=book/book.toml");

    let status = Command::new("/usr/bin/env")
        .arg("sh")
        .arg("-c")
        .arg("command -v mdbook 1>/dev/null 2>&1")
        .status()?;

    if status.success() {
        let mut mdbook = Command::new("/usr/bin/env");
        mdbook
            .arg("mdbook")
            .arg("build")
            .arg("book")
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
        let mdbook_status = mdbook.status()?;

        if !mdbook_status.success() {
            panic!("`{:?}` failed, rc={mdbook_status}", mdbook,);
        }
    } else {
        println!("cargo::warning=unable to find mdbook command, skipping generation");
    }

    Ok(())
}

fn copy(source: &str, target: &str) -> Result<u64> {
    let source = Path::new(source);
    println!("cargo:rerun-if-changed={}", source.display());
    let target = Path::new(target);
    fs::copy(source, target).context(format!("copy {} {}", source.display(), target.display()))
}

fn copy_aslkeys() -> Result<()> {
    copy(
        "libasl/fixtures/signer_cert.pem",
        "prefix/conf/signer_cert.pem",
    )?;
    copy(
        "libasl/fixtures/signer_key.pem",
        "prefix/conf/signer_key.pem",
    )?;
    copy(
        "libasl/fixtures/issuer_cert.pem",
        "prefix/conf/issuer_cert.pem",
    )?;
    // NOTE: required for the ocsp responder impl. in integration tests, not the nginx module
    copy(
        "libasl/fixtures/issuer_key.pem",
        "prefix/conf/issuer_key.pem",
    )?;
    copy("libasl/fixtures/roots.json", "prefix/conf/roots.json")?;

    copy(
        "misc/config/main_common.conf",
        "prefix/conf/main_common.conf",
    )?;
    copy(
        "misc/config/http_common.conf",
        "prefix/conf/http_common.conf",
    )?;
    copy(
        "misc/config/server_common.conf",
        "prefix/conf/server_common.conf",
    )?;
    copy("misc/config/asl.conf", "prefix/conf/asl.conf")?;
    copy(
        "misc/config/proxy_headers.conf",
        "prefix/conf/proxy_headers.conf",
    )?;

    Ok(())
}

/// Generate Rust bindings for the (built-in) proxy module's per-location config struct.
///
/// We only emit `ngx_http_proxy_loc_conf_t` (+ its two proxy-local helper structs and the
/// `ngx_http_proxy_module` symbol); every other field type is reused from `nginx_sys` via
/// `allowlist_recursively(false)` + `use nginx_sys::*`. That keeps `ngx_hash_t` etc. identical
/// to what `ngx_hash_find` expects, and — crucially — outsources the feature-macro-dependent
/// layout of the embedded `ngx_http_upstream_conf_t` (which fixes the offset of `headers`) to
/// nginx-sys, which derived it from this same configured source tree. We feed bindgen the exact
/// include paths nginx-sys used (`DEP_NGINX_INCLUDE`), so `objs/ngx_auto_config.h` supplies the
/// same `NGX_HTTP_*` defines. A layout/field change on an nginx bump surfaces as a compile error
/// in `src/proxy_conf.rs`, not silent UB.
fn generate_proxy_binding() -> Result<()> {
    let out_dir = PathBuf::from(env::var("OUT_DIR")?);
    let include =
        env::var("DEP_NGINX_INCLUDE").context("DEP_NGINX_INCLUDE not exported by nginx-sys")?;

    let mut clang_args: Vec<String> = env::split_paths(&include)
        .map(|p| format!("-I{}", p.display()))
        .collect();
    // The header lives in src/http/modules; ALL_INCS already lists it, but be explicit.
    let build_dir = PathBuf::from(env::var("DEP_NGINX_BUILD_DIR")?);
    let modules = get_nginx_source_dir(&build_dir).join("src/http/modules");
    clang_args.push(format!("-I{}", modules.display()));

    let bindings = bindgen::Builder::default()
        .header_contents("proxy_wrapper.h", "#include <ngx_http_proxy_module.h>\n")
        .clang_args(&clang_args)
        .allowlist_type("ngx_http_proxy_loc_conf_t")
        .allowlist_type("ngx_http_proxy_headers_t")
        .allowlist_type("ngx_http_proxy_vars_t")
        .allowlist_var("ngx_http_proxy_module")
        // do not regenerate the core ngx_* types — reuse nginx-sys' (identical, and correctly
        // laid out for this build's feature macros). The including module (src/proxy_conf.rs)
        // supplies `use nginx_sys::*;` so the unqualified field types resolve.
        .allowlist_recursively(false)
        .layout_tests(false)
        .use_core()
        .generate()
        .map_err(|e| anyhow::anyhow!("bindgen ngx_http_proxy_module.h: {e}"))?;

    bindings.write_to_file(out_dir.join("proxy_bindings.rs"))?;
    println!(
        "cargo:rerun-if-changed={}",
        modules.join("ngx_http_proxy_module.h").display()
    );
    Ok(())
}

fn generate_openssl_cnf() -> Result<()> {
    let target_dir = PathBuf::from(env::var("OUT_DIR")?)
        .join("..")
        .join("..")
        .join("..")
        .canonicalize()?;
    #[cfg(target_os = "macos")]
    let libsuff = "dylib";
    #[cfg(not(target_os = "macos"))]
    let libsuff = "so";
    let text = format!(
        "\
        openssl_conf = openssl_init \n\
        \n\
        [openssl_init]\n\
        providers = provider_sect\n\
        \n\
        [provider_sect]\n\
        ossl_hsm = ossl_hsm_sect\n\
        default = default_sect\n\
        \n\
        [ossl_hsm_sect]\n\
        module = {}/libossl_hsm.{libsuff}\n\
        activate = 1\n\
        \n\
        [default_sect]\n\
        activate = 1\n\
        ",
        target_dir.display()
    );
    let target = target_dir.join("openssl.cnf");
    fs::write(&target, &text)?;
    Ok(())
}

fn run_xtask_check() -> Result<()> {
    println!("cargo:rerun-if-env-changed=NGINX_VERSION");
    println!("cargo:rerun-if-env-changed=NGX_CONFIGURE_ARGS");

    // can't do cargo xtask configure automatically — when this is run, nginx-sys is already built
    // instead, bail and instruct the user to run it
    let status = Command::new("/usr/bin/env")
        .arg("sh")
        .arg("-c")
        .arg("cargo xtask check")
        // A CARGO_TARGET_DIR in our environment (e.g. the nextest setup script
        // building into target/module, or a user-global setting) would be
        // inherited by the nested cargo, which then blocks on the build-dir
        // lock the outer cargo holds while running this build script —
        // deadlock. xtask is its own workspace; let it use its own target dir.
        .env_remove("CARGO_TARGET_DIR")
        .status()?;
    if !status.success() {
        bail!("cargo xtask check failed. Run `cargo xtask configure` and try again")
    }
    Ok(())
}

/// Warn on the bare `cargo build`/`cargo check` signature: default features,
/// debug profile, default target dir. That artifact is not loaded by any nginx
/// config (the prefix/modules symlinks resolve into target/module-{dev,test}),
/// and the invocation evicts the test build's fingerprints in target/ — the
/// next `cargo nextest run` pays a full rebuild. Module builds (`cargo module`,
/// `cargo module-test`), test/check with --workspace --all-targets, RA
/// (all-features), and release builds all fall outside this signature.
fn warn_bare_build() {
    let bare_features =
        env::var_os("CARGO_FEATURE_CLIENT").is_none() && env::var_os("CARGO_FEATURE_ITS").is_none();
    let debug_profile = env::var("PROFILE").as_deref() == Ok("debug");
    let default_target_dir = env::var("OUT_DIR")
        .map(|d| d.contains("/target/debug/"))
        .unwrap_or(false);
    if bare_features && debug_profile && default_target_dir {
        println!(
            "cargo:warning=plain `cargo build`/`cargo check`: nginx does not load this artifact \
             — use `cargo module` (dev .so) or `cargo nextest run` (tests)"
        );
    }
}

fn main() -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        // allow unresolved symbols (resolved by nginx at runtime)
        // NOTE: only required on macos, Linux allows this by default
        println!("cargo:rustc-cdylib-link-arg=-Wl,-undefined,dynamic_lookup");
    }

    warn_bare_build();
    run_xtask_check()?;
    make_install()?;
    generate_proxy_binding()?;
    generate_schema()?;
    generate_book()?;
    copy_aslkeys()?;
    generate_openssl_cnf()?;

    println!("cargo::rustc-check-cfg=cfg(coverage)");
    Ok(())
}
