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
import { build, context } from "esbuild";

const isWatch = process.argv.includes("--watch");
const isServe = process.argv.includes("--serve");

let envPlugin = {
  name: "env",
  setup(build) {
    build.onResolve({ filter: /^env$/ }, (args) => ({
      path: args.path,
      namespace: "env-ns",
    }));

    build.onLoad({ filter: /.*/, namespace: "env-ns" }, () => ({
      contents: JSON.stringify({
        KC_URL: process.env.KC_URL || "",
        KC_REALM: process.env.KC_REALM || "",
        KC_CLIENT_ID: process.env.KC_CLIENT_ID || "",
        KC_REDIRECT_URI: process.env.KC_REDIRECT_URI || "",
      }),
      loader: "json",
    }));
  },
};

const common = {
  entryPoints: ["src/main.ts"],
  bundle: true,
  format: "esm",
  sourcemap: true,
  outdir: "public/js",
  target: ["es2022"],
  plugins: [envPlugin],
};

if (isWatch || isServe) {
  const ctx = await context(common);
  if (isServe) {
    await ctx.serve({ servedir: "public", port: 8000, host: "localhost" });
    console.log("Dev server on http://localhost:8000");
  } else {
    await ctx.watch();
    console.log("Watching…");
  }
} else {
  await build(common);
  console.log("esbuild: → public/js/*");
}
