//! A backend as the configuration spells it.
//!
//! A node is a server, the ticket or the node ID it is reached by, and the
//! domains it serves; a domain mapping is one domain and the server that
//! serves it.

use crate::ClientError;

use iroh::EndpointAddr;

#[derive(Debug, Clone)]
pub struct DomainMapping {
    pub domain: String,
    pub server_node_id: Option<String>,
    pub server_ticket: Option<String>,
}

impl DomainMapping {
    pub fn to_endpoint_addr(&self) -> Result<EndpointAddr, ClientError> {
        crate::connection_pool::parse_endpoint_addr(
            self.server_node_id.as_deref(),
            self.server_ticket.as_deref(),
        )
    }

    pub fn key(&self) -> String {
        if let Some(id) = &self.server_node_id {
            format!("node_id:{}", id)
        } else if let Some(ticket) = &self.server_ticket {
            format!("ticket:{}", ticket)
        } else {
            "unknown".to_string()
        }
    }
}

#[derive(Debug, Clone)]
pub struct NodeConfig {
    pub server_node_id: Option<String>,
    pub server_ticket: Option<String>,
    pub domains: Vec<String>,
}

impl NodeConfig {
    pub fn to_endpoint_addr(&self) -> Result<EndpointAddr, ClientError> {
        crate::connection_pool::parse_endpoint_addr(
            self.server_node_id.as_deref(),
            self.server_ticket.as_deref(),
        )
    }

    pub fn key(&self) -> String {
        if let Some(id) = &self.server_node_id {
            format!("node_id:{}", id)
        } else if let Some(ticket) = &self.server_ticket {
            format!("ticket:{}", ticket)
        } else {
            "unknown".to_string()
        }
    }

    pub fn to_domain_mappings(&self) -> Vec<DomainMapping> {
        self.domains
            .iter()
            .map(|domain| DomainMapping {
                domain: domain.clone(),
                server_node_id: self.server_node_id.clone(),
                server_ticket: self.server_ticket.clone(),
            })
            .collect()
    }
}
