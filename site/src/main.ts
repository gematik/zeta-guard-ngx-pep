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
import Keycloak from "keycloak-js";
import env from "env";

const statusEl = document.getElementById("status") as HTMLPreElement;
function setStatus(msg: string) {
  statusEl.textContent = `${msg}\n`;
}

function logError(msg: string) {
  console.error(msg);
  setStatus(msg);
}

const keycloak = new Keycloak({
  url: env.KC_URL,
  realm: env.KC_REALM,
  clientId: env.KC_CLIENT_ID,
});
await keycloak.init({
  redirectUri: env.KC_REDIRECT_URI,
  onLoad: "check-sso",
});

setStatus("ready.");

const loginBtn = document.getElementById("loginBtn") as HTMLButtonElement;
async function login() {
  try {
    await keycloak.login();
  } catch (error) {
    logError(`Failed to log in: ${error}`);
  }
  setStatus("authenticated");
  await checkLogin();
  return false;
}

loginBtn.addEventListener("click", login);

const logoutBtn = document.getElementById("logoutBtn") as HTMLButtonElement;
async function logout() {
  try {
    await keycloak.logout();
  } catch (error) {
    logError(`Failed to log out: ${error}`);
  }
  setStatus("logged out");
  await checkLogin();
  return false;
}
logoutBtn.addEventListener("click", logout);

async function refresh(minSeconds = 30) {
  try {
    // Only refresh if we have a session
    if (keycloak.authenticated) {
      await keycloak.updateToken(minSeconds);
    }
  } catch (e) {
    logError(`refresh failed: ${e}`);
    // If the refresh fails, force a re-login
    await keycloak.login();
  }
}

const callBtn = document.getElementById("callBtn") as HTMLButtonElement;
async function call() {
  if (!keycloak.authenticated || !keycloak.token) {
    logError("no auth");
    return await checkLogin();
  }
  await refresh();
  setStatus("Fetching protected resource…");
  try {
    const r = await fetch("secret/data.json", {
      method: "GET",
      headers: { Authorization: `Bearer ${keycloak.token}` },
    });
    const txt = await r.text();
    if (r.status != 200) {
      logError(`Received error:\nHTTP ${r.status}\n${txt}`);
    } else {
      const secret = JSON.parse(txt);
      setStatus(`Received secret value:\n„${secret.value}”`);
    }
  } catch (e) {
    logError(`${e}`);
  }
  return false;
}
callBtn.addEventListener("click", call);

async function checkLogin() {
  if (keycloak.authenticated) {
    loginBtn.hidden = true;
    loginBtn.disabled = true;
    logoutBtn.hidden = false;
    logoutBtn.disabled = false;
    callBtn.hidden = false;
    callBtn.disabled = false;
  } else {
    loginBtn.hidden = false;
    loginBtn.disabled = false;
    logoutBtn.hidden = true;
    logoutBtn.disabled = true;
    callBtn.hidden = true;
    callBtn.disabled = true;
  }
}

await checkLogin();
