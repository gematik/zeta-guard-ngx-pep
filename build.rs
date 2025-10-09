/*-
 * #%L
 * ngx_pep
 * %%
 * (C) akquinet tech@Spree GmbH, 2025, licensed for gematik GmbH
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
    env, fs,
    io::{self, ErrorKind},
    path::{Path, PathBuf},
    process::Command,
};

use cargo_metadata::MetadataCommand;
use serde::Serialize;
use tinytemplate::TinyTemplate;

// Use cargo_metadata to find nginx-src's embedded nginx source tree, as it doesn't cleanly export
// that, but we want to call `make install` in it to populate the prefix.
fn get_nginx_src_path() -> io::Result<PathBuf> {
    let metadata = MetadataCommand::new().exec().unwrap();
    let nginx_src = metadata
        .packages
        .iter()
        .find(|package| package.name.as_str() == "nginx-src");
    nginx_src
        .map(|p| p.manifest_path.parent().unwrap().join("nginx").into())
        .ok_or(io::Error::new(
            ErrorKind::NotFound,
            "Unable to find nginx source folder",
        ))
}

fn install_site() -> io::Result<()> {
    let node_modules = Path::new("./site/node_modules");
    if !node_modules.exists() {
        eprintln!("running `npm install` in ./site");
        Command::new("npm")
            .arg("install")
            .current_dir("./site")
            .status()?;
    }
    let main_js = Path::new("./site/public/js/main.js");
    if !main_js.exists() {
        eprintln!("running `npm build` in ./site");
        Command::new("npm")
            .arg("run")
            .arg("build")
            .current_dir("./site")
            .status()?;
    }

    eprintln!("running `npm run prefix_install` in ./site to populate ./prefix/html");
    Command::new("npm")
        .arg("run")
        .arg("prefix_install")
        .current_dir("./site")
        .status()?;
    Ok(())
}

fn nproc() -> usize {
    Command::new("nproc")
        .output()
        .map(|o| {
            String::from_utf8(o.stdout)
                .expect("nproc output")
                .parse()
                .expect("nproc parse")
        })
        .unwrap_or(1)
}

fn make_install() -> io::Result<()> {
    println!("cargo:rerun-if-env-changed=NGX_CONFIGURE_ARGS");
    println!("cargo:rerun-if-env-changed=MAKE");

    let make = env::var("MAKE").unwrap_or_else(|_| "make".to_string());
    let jobs = env::var("NUM_JOBS").unwrap_or_else(|_| format!("{}", nproc()));

    let build_dir = std::env::var("DEP_NGINX_BUILD_DIR").unwrap();
    let build_dir = Path::new(&build_dir);
    let source_dir = get_nginx_src_path()?;

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
    // install site again after each `make install`
    install_site()?;
    Ok(())
}

#[derive(Serialize)]
struct Ctx {
    libsuff: String,
}

fn install_config() -> io::Result<()> {
    println!("cargo:rerun-if-changed=misc/nginx.conf.tpl");

    #[cfg(target_os = "macos")]
    let ctx = Ctx {
        libsuff: "dylib".to_string(),
    };

    #[cfg(not(target_os = "macos"))]
    let ctx = Ctx {
        libsuff: "so".to_string(),
    };

    let mut tt = TinyTemplate::new();
    let text = fs::read_to_string("misc/nginx.conf.tpl")?;
    tt.add_template("nginx.conf", &text).map_err(|e| {
        io::Error::new(
            ErrorKind::InvalidData,
            format!("Unable to parse misc/nginx.conf.tlp: {e}"),
        )
    })?;
    fs::write(
        "prefix/conf/nginx.conf",
        tt.render("nginx.conf", &ctx).map_err(|e| {
            io::Error::new(
                ErrorKind::InvalidData,
                format!("Unable to render prefix/conf/nginx.conf: {e}"),
            )
        })?,
    )?;
    Ok(())
}

fn main() -> io::Result<()> {
    #[cfg(target_os = "macos")]
    {
        // allow unresolved symbols (resolved by nginx at runtime)
        // NOTE: only required on macos, Linux allows this by default
        println!("cargo:rustc-cdylib-link-arg=-Wl,-undefined,dynamic_lookup");
    }

    make_install()?;
    install_config()?;

    Ok(())
}
