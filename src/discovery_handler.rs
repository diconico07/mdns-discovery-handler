use std::collections::HashMap;

use akri_discovery_utils::discovery::{
    discovery_handler::{ deserialize_discovery_details, DISCOVERED_DEVICES_CHANNEL_CAPACITY},
    v0::{discovery_handler_server::DiscoveryHandler, Device, DiscoverRequest, DiscoverResponse},
    DiscoverStream,
};
use async_trait::async_trait;
use log::{error, trace};
use mdns_sd::{ServiceDaemon, ServiceEvent};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tonic::{Response, Status};

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct MdnsDiscoveryDetails {
    pub service_name: String,
}

pub struct DiscoveryHandlerImpl {
    register_sender: tokio::sync::mpsc::Sender<()>,
    daemon: ServiceDaemon,
}

impl DiscoveryHandlerImpl {
    pub fn new(register_sender: tokio::sync::mpsc::Sender<()>) -> Self {
        let daemon = ServiceDaemon::new().expect("Failed to create daemon");
        DiscoveryHandlerImpl {
            register_sender,
            daemon,
        }
    }
}

#[async_trait]
impl DiscoveryHandler for DiscoveryHandlerImpl {
    type DiscoverStream = DiscoverStream;
    async fn discover(
        &self,
        request: tonic::Request<DiscoverRequest>,
    ) -> Result<Response<Self::DiscoverStream>, Status> {
        let register_sender = self.register_sender.clone();
        let discover_request = request.get_ref();
        let (discovered_devices_sender, discovered_devices_receiver) =
            mpsc::channel(DISCOVERED_DEVICES_CHANNEL_CAPACITY);
        let discovery_handler_config: MdnsDiscoveryDetails =
            deserialize_discovery_details(&discover_request.discovery_details)
                .map_err(|e| tonic::Status::new(tonic::Code::InvalidArgument, format!("{}", e)))?;

        // If the service name doesn't end with a point '.' add it
        let service_name = match discovery_handler_config.service_name.ends_with('.') {
            true => discovery_handler_config.service_name,
            false => format!("{}.", discovery_handler_config.service_name),
        };
        let receiver = self
            .daemon
            .browse(&service_name)
            .map_err(|_| Status::invalid_argument("Invalid service name"))?;

        let mut devices_cache = HashMap::new();

        tokio::spawn(async move {
            while let Ok(event) = receiver.recv_async().await {
                // Before each iteration, check if receiver has dropped
                if discovered_devices_sender.is_closed() {
                    error!("discover - channel closed ... attempting to re-register with Agent");
                    register_sender.send(()).await.unwrap();
                    break;
                }
                trace!("got event: {:?}", event);
                match event {
                    ServiceEvent::ServiceResolved(service) => {
                        devices_cache.insert(service.get_fullname().to_string(), service);
                    }
                    ServiceEvent::ServiceRemoved(_, name) => {
                        devices_cache.remove(&name);
                    }
                    ServiceEvent::SearchStopped(_) => break,
                    _ => continue,
                }

                discovered_devices_sender
                    .send(Ok(DiscoverResponse {
                        devices: devices_cache
                            .iter()
                            .map(|(name, service)| {
                                let mut properties = HashMap::from([(
                                    "MDNS_HOSTNAME".to_string(),
                                    service.get_hostname().to_string(),
                                ), ("MDNS_PORT".to_string(), service.get_port().to_string())]);
                                
                                properties.extend(service.get_addresses().iter().enumerate().map(
                                    |(index, ip)| {
                                        (format!("MDNS_IP_ADDRESS_{}", index), ip.to_string())
                                    },
                                ));
                                properties.extend(service.get_properties().iter().filter_map(
                                    |txt| {
                                        if txt.key().is_ascii() {
                                            Some((
                                                format!(
                                                    "MDNS_TXT_{}",
                                                    txt.key().to_uppercase().replace(' ', "_")
                                                ),
                                                txt.val_str().to_string(),
                                            ))
                                        } else {
                                            None
                                        }
                                    },
                                ));
                                Device {
                                    id: name.to_string(),
                                    properties,
                                    ..Default::default()
                                }
                            })
                            .collect(),
                    }))
                    .await
                    .unwrap();
            }
        });
        Ok(Response::new(tokio_stream::wrappers::ReceiverStream::new(
            discovered_devices_receiver,
        )))
    }
}
