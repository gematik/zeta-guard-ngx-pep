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

mod common;

use hsm_sim::proto::HealthCheckRequest;
use hsm_sim::proto::health_check_response::ServingStatus;
use hsm_sim::proto::hsm_proxy_service_client::HsmProxyServiceClient;
use tonic_health::pb::HealthCheckRequest as GrpcHealthCheckRequest;
use tonic_health::pb::health_client::HealthClient;

#[tokio::test]
async fn health_check() {
    let mut client = common::hsm_client().await;

    let resp = client
        .health_check(HealthCheckRequest {})
        .await
        .unwrap()
        .into_inner();

    assert!(resp.status == ServingStatus::Serving.into());
    assert!(resp.hsm_info == "HSM Simulator");
}

#[tokio::test]
async fn grpc_standard_health_check() {
    let channel = common::start_server("127.1.33.7:0").await;
    let mut health = HealthClient::new(channel.clone());

    // Check overall server health (empty service name)
    let resp = health
        .check(GrpcHealthCheckRequest {
            service: String::new(),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        resp.status(),
        tonic_health::pb::health_check_response::ServingStatus::Serving
    );

    // Check named service health
    let resp = health
        .check(GrpcHealthCheckRequest {
            service: "gematik.zetaguard.hsmproxy.v1.HsmProxyService".to_string(),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        resp.status(),
        tonic_health::pb::health_check_response::ServingStatus::Serving
    );

    // Also verify the hsm_sim client still works on the same channel
    let mut client = HsmProxyServiceClient::new(channel);
    let resp = client
        .health_check(HealthCheckRequest {})
        .await
        .unwrap()
        .into_inner();
    assert_eq!(resp.status, ServingStatus::Serving.into());
}
