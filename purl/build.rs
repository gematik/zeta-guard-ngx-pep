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
    fs::{self},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use schemars::schema::RootSchema;
use schemars::visit::{Visitor, visit_schema_object};
use typify::TypeSpace;

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
        resolve_schema(Path::new("../src/schema/access-token.yaml").to_path_buf())?,
        resolve_schema(Path::new("../src/schema/popp-token.yaml").to_path_buf())?,
        resolve_schema(Path::new("../src/schema/client-instance.yaml").to_path_buf())?,
        resolve_schema(Path::new("../src/schema/user-info.yaml").to_path_buf())?,
        resolve_schema(Path::new("../src/schema/dpop-token.yaml").to_path_buf())?,
        resolve_schema(Path::new("../src/schema/client-assertion-jwt.yaml").to_path_buf())?,
    ];

    let mut type_space = TypeSpace::default();
    for schema in schemas {
        type_space.add_root_schema(schema)?;
    }

    let contents =
        prettyplease::unparse(&syn::parse2::<syn::File>(type_space.to_stream()).unwrap());
    let out_file = Path::new(&env::var("OUT_DIR").unwrap()).join("typify.rs");
    fs::write(out_file, contents)?;
    Ok(())
}

fn main() -> Result<()> {
    generate_schema()?;

    Ok(())
}
