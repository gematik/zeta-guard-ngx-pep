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

//! In-process OTLP/gRPC receiver. The test nginx exports its logs, metrics and traces here
//! (`OTEL_EXPORTER_OTLP_ENDPOINT`), so tests can assert on the telemetry the PEP actually sends.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{LazyLock, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use opentelemetry_proto::tonic::collector::logs::v1::logs_service_server::{
    LogsService, LogsServiceServer,
};
use opentelemetry_proto::tonic::collector::logs::v1::{
    ExportLogsServiceRequest, ExportLogsServiceResponse,
};
use opentelemetry_proto::tonic::collector::metrics::v1::metrics_service_server::{
    MetricsService, MetricsServiceServer,
};
use opentelemetry_proto::tonic::collector::metrics::v1::{
    ExportMetricsServiceRequest, ExportMetricsServiceResponse,
};
use opentelemetry_proto::tonic::collector::trace::v1::trace_service_server::{
    TraceService, TraceServiceServer,
};
use opentelemetry_proto::tonic::collector::trace::v1::{
    ExportTraceServiceRequest, ExportTraceServiceResponse,
};
use opentelemetry_proto::tonic::common::v1::{KeyValue, any_value};
use opentelemetry_proto::tonic::logs::v1::LogRecord;
use opentelemetry_proto::tonic::metrics::v1::{Metric, metric, number_data_point};
use tokio::time::{sleep, timeout};
use tonic::transport::Server;
use tonic::{Request, Response, Status};

static LOGS: LazyLock<Mutex<Vec<LogRecord>>> = LazyLock::new(Default::default);
/// Latest export per (metric name, `service.instance.id`): counters are cumulative, so the newest
/// export of an instance wins, but every nginx worker exports its own stream, which must not
/// overwrite another worker's.
static METRICS: LazyLock<Mutex<HashMap<(String, String), Metric>>> =
    LazyLock::new(Default::default);

#[derive(Default)]
struct Receiver;

#[tonic::async_trait]
impl LogsService for Receiver {
    async fn export(
        &self,
        request: Request<ExportLogsServiceRequest>,
    ) -> Result<Response<ExportLogsServiceResponse>, Status> {
        let records = request
            .into_inner()
            .resource_logs
            .into_iter()
            .flat_map(|r| r.scope_logs)
            .flat_map(|s| s.log_records);
        LOGS.lock().unwrap().extend(records);
        Ok(Response::new(Default::default()))
    }
}

#[tonic::async_trait]
impl MetricsService for Receiver {
    async fn export(
        &self,
        request: Request<ExportMetricsServiceRequest>,
    ) -> Result<Response<ExportMetricsServiceResponse>, Status> {
        let mut stored = METRICS.lock().unwrap();
        for resource_metrics in request.into_inner().resource_metrics {
            let instance = resource_metrics
                .resource
                .as_ref()
                .and_then(|r| attr(&r.attributes, "service.instance.id"))
                .unwrap_or_default()
                .to_string();
            for metric in resource_metrics
                .scope_metrics
                .into_iter()
                .flat_map(|s| s.metrics)
            {
                stored.insert((metric.name.clone(), instance.clone()), metric);
            }
        }
        Ok(Response::new(Default::default()))
    }
}

#[tonic::async_trait]
impl TraceService for Receiver {
    async fn export(
        &self,
        _request: Request<ExportTraceServiceRequest>,
    ) -> Result<Response<ExportTraceServiceResponse>, Status> {
        Ok(Response::new(Default::default()))
    }
}

pub async fn otlp_server(port: u16) -> Result<()> {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    eprintln!("[otlp_server] listening on {addr}");
    Server::builder()
        .add_service(LogsServiceServer::new(Receiver))
        .add_service(MetricsServiceServer::new(Receiver))
        .add_service(TraceServiceServer::new(Receiver))
        .serve(addr)
        .await?;
    Ok(())
}

/// String value of the attribute `key`, if present.
pub fn attr<'a>(attributes: &'a [KeyValue], key: &str) -> Option<&'a str> {
    attributes
        .iter()
        .find(|kv| kv.key == key)
        .and_then(|kv| kv.value.as_ref())
        .and_then(|v| match v.value.as_ref()? {
            any_value::Value::StringValue(s) => Some(s.as_str()),
            _ => None,
        })
}

fn body_text(record: &LogRecord) -> Option<&str> {
    match record.body.as_ref()?.value.as_ref()? {
        any_value::Value::StringValue(s) => Some(s.as_str()),
        _ => None,
    }
}

/// Waits for a log record received so far that satisfies `pred` and returns it.
pub async fn wait_for_log(what: &str, pred: impl Fn(&LogRecord) -> bool) -> Result<LogRecord> {
    timeout(Duration::from_secs(15), async {
        loop {
            if let Some(record) = LOGS.lock().unwrap().iter().find(|r| pred(r)) {
                return record.clone();
            }
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .with_context(|| format!("no OTLP log record received: {what}"))
}

/// Waits for a data point of the counter `name` whose attributes contain `key=value` and
/// returns its (cumulative) value, summed over all exporting workers.
pub async fn wait_for_counter(name: &str, key: &str, value: &str) -> Result<i64> {
    timeout(Duration::from_secs(15), async {
        loop {
            let values: Vec<i64> = METRICS
                .lock()
                .unwrap()
                .iter()
                .filter(|((metric_name, _), _)| metric_name == name)
                .filter_map(|(_, m)| match m.data.as_ref()? {
                    metric::Data::Sum(sum) => Some(sum.data_points.clone()),
                    _ => None,
                })
                .flatten()
                .filter(|dp| attr(&dp.attributes, key) == Some(value))
                .filter_map(|dp| match dp.value? {
                    number_data_point::Value::AsInt(i) => Some(i),
                    number_data_point::Value::AsDouble(d) => Some(d as i64),
                })
                .collect();
            if !values.is_empty() {
                return values.iter().sum();
            }
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .with_context(|| format!("no OTLP data point for {name} with {key}={value}"))
}

/// Attack-detection log record for a request from `client_ip`.
pub async fn wait_for_attack_log(client_ip: &str) -> Result<LogRecord> {
    wait_for_log(&format!("attackDetection.clientIP={client_ip}"), |r| {
        body_text(r).is_some_and(|b| b.starts_with("possible attack detected"))
            && attr(&r.attributes, "attackDetection.clientIP") == Some(client_ip)
    })
    .await
}
