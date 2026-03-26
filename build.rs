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

use anyhow::{Context, Result};
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
    libsuff: String,
    target: String,
    multi_process: bool,
    error_log: String,
    access_log: String,
    port: u16,
    // IT: embedded echo server port for upstream tests
    echo_port: u16,
    temp_prefix: String,
    // adds 'user root;' for CI (coverage), no effect when master is not root (e.g. locally)
    as_root: bool,
}

impl ConfigFile {
    fn new() -> Self {
        ConfigFile {
            name: "nginx".to_string(),
            #[cfg(target_os = "macos")]
            libsuff: "dylib".to_string(),
            #[cfg(not(target_os = "macos"))]
            libsuff: "so".to_string(),
            target: "debug".to_string(),
            multi_process: true, // set to false for easier debugging
            error_log: "/dev/stdout debug".to_string(),
            access_log: "/dev/stdout main".to_string(),
            port: 8000,
            echo_port: 8100, // should be port + 100
            temp_prefix: "".to_string(),
            as_root: false,
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
    for port in 8003..=8010 {
        let mut test_config = ConfigFile::new();
        test_config.name = format!("test-{port}");
        test_config.error_log = format!("{}/logs/error.log", test_config.name);
        test_config.access_log = format!("{}/logs/access.log", test_config.name);
        test_config.port = port;
        test_config.echo_port = port + 100; // e.g. 8003 → 8103
        test_config.temp_prefix = format!("{}/", test_config.name);
        test_config.as_root = true; // needed in CI to write out coverage data
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
        resolve_schema(Path::new("./src/schema/popp-token.yaml").to_path_buf())?,
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

fn copy_aslkeys() -> Result<()> {
    let source = Path::new("libasl/fixtures/signer_cert.pem");
    println!("cargo:rerun-if-changed={}", source.display());
    let target = Path::new("prefix/conf/signer_cert.pem");
    println!("cargo:rerun-if-changed={}", target.display());
    fs::copy(source, target)?;

    let source = Path::new("libasl/fixtures/signer_key.pem");
    println!("cargo:rerun-if-changed={}", source.display());
    let target = Path::new("prefix/conf/signer_key.pem");
    println!("cargo:rerun-if-changed={}", target.display());
    fs::copy(source, target)?;

    let source = Path::new("libasl/fixtures/issuer_cert.pem");
    println!("cargo:rerun-if-changed={}", source.display());
    let target = Path::new("prefix/conf/issuer_cert.pem");
    println!("cargo:rerun-if-changed={}", target.display());
    fs::copy(source, target)?;

    let source = Path::new("libasl/fixtures/roots.json");
    println!("cargo:rerun-if-changed={}", source.display());
    let target = Path::new("prefix/conf/roots.json");
    println!("cargo:rerun-if-changed={}", target.display());
    fs::copy(source, target)?;

    Ok(())
}

fn main() -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        // allow unresolved symbols (resolved by nginx at runtime)
        // NOTE: only required on macos, Linux allows this by default
        println!("cargo:rustc-cdylib-link-arg=-Wl,-undefined,dynamic_lookup");
    }

    make_install()?;
    generate_schema()?;
    generate_book()?;
    copy_aslkeys()?;

    println!("cargo::rustc-check-cfg=cfg(coverage)");
    Ok(())
}
