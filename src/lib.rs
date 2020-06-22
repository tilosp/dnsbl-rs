use std::fmt;
use std::net::IpAddr;

use trust_dns_resolver::{
    config::{ResolverConfig, ResolverOpts},
    error::ResolveError,
    Name, TokioAsyncResolver,
};

use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub type Error = ResolveError;

pub type BlockList = Domain;

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct Domain(Name);

impl Domain {
    pub fn new<S: AsRef<str>>(name: S) -> Result<Self, Error> {
        let name = Name::from_utf8(name)?;
        Ok(Self(name))
    }
}

impl fmt::Display for Domain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl Serialize for Domain {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.to_string().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Domain {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let string: String = String::deserialize(deserializer)?;
        Ok(Self::new(string).map_err(serde::de::Error::custom)?)
    }
}

pub struct DNSBL {
    resolver: TokioAsyncResolver,
}

impl DNSBL {
    pub async fn new() -> Result<Self, Error> {
        let resolver =
            TokioAsyncResolver::tokio(ResolverConfig::cloudflare_tls(), ResolverOpts::default())
                .await?;
        Ok(Self { resolver })
    }

    pub async fn check_domain(&self, list: &BlockList, domain: &Domain) -> BlockStatus {
        let dns_name =
            Name::from_labels(domain.0.into_iter().chain(&list.0)).expect("always valid");

        self.check(dns_name).await
    }

    pub async fn check_ip<A: Into<IpAddr>>(&self, list: &BlockList, ip_addr: A) -> BlockStatus {
        let ip: Name = ip_addr.into().into();

        let dns_name = Name::from_labels(
            ip.into_iter()
                .take(usize::from(ip.num_labels() - 2))
                .chain(&list.0),
        )
        .expect("always valid");

        self.check(dns_name).await
    }

    async fn check(&self, dns_name: Name) -> BlockStatus {
        if self.resolver.ipv4_lookup(dns_name.clone()).await.is_err() {
            BlockStatus::NotBlocked
        } else if let Ok(txt) = self.resolver.txt_lookup(dns_name).await {
            let message = txt
                .iter()
                .map(|i| {
                    i.iter()
                        .map(|i| String::from_utf8(i.to_vec()).unwrap_or_else(|_| "".to_owned()))
                        .collect::<Vec<_>>()
                        .join(" ")
                })
                .collect::<Vec<_>>()
                .join(" ");
            BlockStatus::Blocked {
                message: Some(message).filter(|s| !s.is_empty()),
            }
        } else {
            BlockStatus::Blocked { message: None }
        }
    }
}
#[derive(PartialEq)]
pub enum BlockStatus {
    Blocked { message: Option<String> },
    NotBlocked,
}
