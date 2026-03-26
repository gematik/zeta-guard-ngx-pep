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

use std::env;
use std::fs::{self, File, Permissions};
use std::io;
use std::os::unix::prelude::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};

use flate2::read::GzDecoder;
use tar::Archive;

const NGINX_DOWNLOAD_URL: &str = "https://nginx.org/download";
const KEYSERVER: &str = "hkps://keyserver.ubuntu.com";

// see ngx-rust/nginx-src/src/download.rs
const NGINX_SIGNING_KEYS: &[&str] = &[
    // Key 1: Konstantin Pavlov's public key. For Nginx 1.25.3 and earlier
    "13C82A63B603576156E30A4EA0EA981B66B0D967",
    // Key 2: Sergey Kandaurov's public key. For Nginx 1.25.4
    "D6786CE303D9A9022998DC6CC8464D549AF75C0A",
    // Key 3: Maxim Dounin's public key. At least used for Nginx 1.18.0
    "B0F4253373F8F6F510D42178520A9993A1C052F8",
    // Key 4: Roman Arutyunyan's public key. For Nginx 1.25.5
    "43387825DDB1BB97EC36BA5D007C8D7C15D87369",
];

fn project_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

fn main() -> ExitCode {
    match env::args().nth(1).as_deref() {
        Some("configure") => configure(),
        _ => {
            eprintln!("Usage: cargo xtask <command>");
            eprintln!();
            eprintln!("Commands:");
            eprintln!("  configure    Download (if needed) and configure nginx");
            ExitCode::FAILURE
        }
    }
}

fn download(url: &str, dest: &Path) -> io::Result<()> {
    if dest.exists() && dest.metadata().is_ok_and(|m| m.len() > 0) {
        eprintln!("  cached: {}", dest.display());
        return Ok(());
    }
    eprintln!("  downloading: {url}");
    let response = ureq::get(url).call().map_err(io::Error::other)?;
    let mut file = File::create(dest)?;
    let mut reader = response.into_body().into_reader();
    io::copy(&mut reader, &mut file)?;
    Ok(())
}

fn verify_gpg(tarball: &Path, signature: &Path) -> bool {
    let gpg_home = tarball.parent().unwrap().join(".gnupg");
    fs::create_dir_all(&gpg_home).ok();
    fs::set_permissions(&gpg_home, Permissions::from_mode(0o700)).expect("chmod 0700");

    if Command::new("gpg").arg("--version").output().is_err() {
        panic!("gpg not found, can't verify signature");
    }

    let import = Command::new("gpg")
        .args(["--homedir"])
        .arg(&gpg_home)
        .args(["--keyserver", KEYSERVER, "--recv-keys"])
        .args(NGINX_SIGNING_KEYS)
        .stderr(Stdio::inherit())
        .stdout(Stdio::inherit())
        .status();

    if !import.as_ref().is_ok_and(|s| s.success()) {
        panic!("failed to import GPG keys");
    }

    let verify = Command::new("gpg")
        .args(["--homedir"])
        .arg(&gpg_home)
        .args(["--verify"])
        .arg(signature)
        .arg(tarball)
        .stderr(Stdio::inherit())
        .stdout(Stdio::inherit())
        .status();

    if verify.is_ok_and(|s| s.success()) {
        eprintln!("  GPG signature verified");
        true
    } else {
        eprintln!("  error: GPG signature verification failed!");
        false
    }
}

fn extract_tarball(tarball: &Path, target_dir: &Path) -> io::Result<()> {
    eprintln!("  extracting to {}", target_dir.display());
    fs::create_dir_all(target_dir)?;
    let file = File::open(tarball)?;
    let decoder = GzDecoder::new(file);
    let mut archive = Archive::new(decoder);
    for entry in archive.entries()? {
        let mut entry = entry?;
        // Strip the top-level nginx-{version}/ directory
        let path: PathBuf = entry.path()?.components().skip(1).collect();
        if path.as_os_str().is_empty() {
            continue;
        }
        entry.unpack(target_dir.join(path))?;
    }
    Ok(())
}

fn download_nginx(version: &str, source_dir: &Path) -> Result<(), String> {
    let cache_dir = source_dir.parent().unwrap().join(".nginx-cache");
    fs::create_dir_all(&cache_dir).map_err(|e| format!("create cache dir: {e}"))?;

    let tarball_name = format!("nginx-{version}.tar.gz");
    let tarball_url = format!("{NGINX_DOWNLOAD_URL}/{tarball_name}");
    let sig_url = format!("{tarball_url}.asc");

    let tarball_path = cache_dir.join(&tarball_name);
    let sig_path = cache_dir.join(format!("{tarball_name}.asc"));

    eprintln!("Downloading nginx {version}...");
    download(&tarball_url, &tarball_path).map_err(|e| format!("download tarball: {e}"))?;
    download(&sig_url, &sig_path).map_err(|e| format!("download signature: {e}"))?;

    if !verify_gpg(&tarball_path, &sig_path) {
        // Remove corrupted/tampered tarball
        let _ = fs::remove_file(&tarball_path);
        let _ = fs::remove_file(&sig_path);
        return Err("signature verification failed".into());
    }

    extract_tarball(&tarball_path, source_dir).map_err(|e| format!("extract: {e}"))?;
    Ok(())
}

fn pkg_config(flag: &str, libs: &[&str]) -> Result<String, io::Error> {
    let mut flags = vec![];
    for lib in libs {
        let out = Command::new("pkg-config")
            .arg(flag)
            .arg(lib)
            .stderr(Stdio::inherit())
            .output()?;

        if !out.status.success() {
            return Err(io::Error::other(format!(
                "pkg-config flag={flag} lib={lib} failed, rc: {:?}",
                out.status.code()
            )));
        }
        let output = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if !output.is_empty() {
            flags.push(output);
        }
    }
    Ok(flags.join(" "))
}

/// Find the configure script: `configure` (nginx 1.29+) or `auto/configure` (older).
fn find_configure(source_dir: &Path) -> Option<PathBuf> {
    ["configure", "auto/configure"]
        .into_iter()
        .map(|p| source_dir.join(p))
        .find(|p| p.is_file())
}

fn configure() -> ExitCode {
    let root = project_root();
    let source_dir = env::var("NGINX_SOURCE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| root.join(".nginx"));

    let version = env::var("NGINX_VERSION").expect("NGINX_VERSION");
    let source_version = source_dir.join(".version");
    if source_dir.exists() && source_version.exists() {
        let source_version = fs::read_to_string(&source_version).expect(".version");
        if source_version != version {
            eprintln!(
                "Version change {} → {}, remove {}",
                source_version,
                version,
                source_dir.display()
            );
            let _ = fs::remove_dir_all(&source_dir);
        }
    };

    // Download if source tree is not present
    if find_configure(&source_dir).is_none() {
        let version = match env::var("NGINX_VERSION") {
            Ok(v) => v,
            Err(_) => {
                eprintln!(
                    "error: {} has no nginx source and NGINX_VERSION is not set",
                    source_dir.display()
                );
                return ExitCode::FAILURE;
            }
        };
        if let Err(e) = download_nginx(&version, &source_dir) {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    } else {
        eprintln!("nginx source found at {}", source_dir.display());
    }

    let configure_script =
        find_configure(&source_dir).expect("configure script not found after download");

    let prefix = root.join("prefix");
    fs::create_dir_all(&prefix).expect("create prefix directory");
    let prefix = prefix.canonicalize().expect("canonicalize prefix");

    let mut args = vec![
        "--with-compat".to_string(),
        "--with-http_realip_module".to_string(),
        "--with-http_ssl_module".to_string(),
        "--with-http_v2_module".to_string(),
        "--with-stream".to_string(),
        "--with-stream_realip_module".to_string(),
        "--with-stream_ssl_module".to_string(),
        "--with-threads".to_string(),
        "--with-debug".to_string(),
        format!("--prefix={}", prefix.display()),
    ];

    let cflags = pkg_config("--cflags", &["openssl", "zlib", "libpcre2-32"]).expect("cflags");

    let arg = format!("--with-cc-opt={cflags}");
    args.push(arg);

    let libs = pkg_config("--libs", &["openssl", "zlib", "libpcre2-32"]).expect("libs");
    let arg = format!("--with-ld-opt={libs}");
    args.push(arg);

    if let Ok(extra) = env::var("NGX_CONFIGURE_ARGS") {
        args.extend(extra.split_whitespace().map(String::from));
    }

    // Check if configure already ran with the same args
    let stamp_file = source_dir.join("objs/.configure-stamp");
    let stamp = args.join("\n");
    if stamp_file.is_file() && fs::read_to_string(&stamp_file).is_ok_and(|s| s == stamp) {
        eprintln!(
            "configure args unchanged, skipping (delete {} to force)",
            stamp_file.display()
        );
        return ExitCode::SUCCESS;
    }

    let script_name = configure_script
        .strip_prefix(&source_dir)
        .unwrap()
        .display();
    eprintln!("Running: {script_name} \\");
    for (i, arg) in args.iter().enumerate() {
        if i + 1 < args.len() {
            eprintln!("  {arg} \\");
        } else {
            eprintln!("  {arg}");
        }
    }

    let status = Command::new(&configure_script)
        .args(&args)
        .current_dir(&source_dir)
        .status()
        .expect("failed to execute configure");

    if status.success() {
        // Write stamp after successful configure
        let _ = fs::write(&stamp_file, &stamp);
        let _ = fs::write(&source_version, version);
        eprintln!("nginx configured successfully");
        ExitCode::SUCCESS
    } else {
        eprintln!("configure failed: {status}");
        ExitCode::FAILURE
    }
}
