//! Traefik dynamic configuration manager.
//!
//! Manages the dynamic.yml file that Traefik watches for routing updates.
//! Thread-safe for concurrent access from multiple services.

use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use color_eyre::eyre::{Result, eyre};
use serde::{Deserialize, Serialize};

use crate::config::ExtraTraefikRoute;

/// Traefik dynamic configuration manager.
///
/// This struct manages the dynamic.yml file that Traefik watches.
/// Routes map hostnames to ToxiProxy ports for unified addressing.
#[derive(Clone, Debug)]
pub struct TraefikConfig {
    /// Path to the dynamic configuration file
    config_path: PathBuf,
    /// File-based TLS mode — all routes get HTTPS entrypoint
    use_tls: bool,
    /// Hostname -> ToxiProxy port mapping (thread-safe)
    routes: Arc<Mutex<HashMap<String, u16>>>,
    /// User-defined extra routes (from TOML config, stored in memory only)
    extra_routes: Arc<Mutex<Vec<ExtraTraefikRoute>>>,
}

/// Traefik dynamic configuration structure (for YAML serialization)
#[derive(Debug, Serialize, Deserialize)]
struct TraefikDynamicConfig {
    http: HttpConfig,
}

#[derive(Debug, Serialize, Deserialize)]
struct ServersTransport {
    #[serde(rename = "insecureSkipVerify", skip_serializing_if = "Option::is_none")]
    insecure_skip_verify: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
struct HttpConfig {
    routers: HashMap<String, Router>,
    services: HashMap<String, TraefikService>,
    #[serde(rename = "serversTransports", skip_serializing_if = "Option::is_none")]
    servers_transports: Option<HashMap<String, ServersTransport>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    middlewares: Option<HashMap<String, Middleware>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Router {
    rule: String,
    service: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    priority: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tls: Option<TlsConfig>,
    #[serde(rename = "entryPoints", skip_serializing_if = "Option::is_none")]
    entry_points: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    middlewares: Option<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct TraefikService {
    #[serde(rename = "loadBalancer")]
    load_balancer: LoadBalancer,
}

#[derive(Debug, Serialize, Deserialize)]
struct LoadBalancer {
    servers: Vec<Server>,
    #[serde(rename = "serversTransport", skip_serializing_if = "Option::is_none")]
    servers_transport: Option<String>,
    #[serde(rename = "passHostHeader", skip_serializing_if = "Option::is_none")]
    pass_host_header: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Server {
    url: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct TlsConfig {
    #[serde(rename = "certResolver", skip_serializing_if = "Option::is_none")]
    cert_resolver: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Middleware {
    #[serde(rename = "redirectScheme", skip_serializing_if = "Option::is_none")]
    redirect_scheme: Option<RedirectScheme>,
}

#[derive(Debug, Serialize, Deserialize)]
struct RedirectScheme {
    scheme: String,
    permanent: bool,
}

impl TraefikConfig {
    /// Load existing routes from the dynamic.yml file.
    ///
    /// Parses the YAML file and extracts hostname -> port mappings.
    fn load_from_file(config_path: &Path) -> HashMap<String, u16> {
        // Return empty if file doesn't exist
        if !config_path.exists() {
            return HashMap::new();
        }

        // Read file contents
        let contents = match fs::read_to_string(config_path) {
            Ok(c) => c,
            Err(_) => return HashMap::new(),
        };

        // Parse YAML
        let config: TraefikDynamicConfig = match serde_yaml::from_str(&contents) {
            Ok(c) => c,
            Err(_) => return HashMap::new(),
        };

        let mut routes = HashMap::new();

        // Extract routes from routers and services
        for (name, router) in config.http.routers {
            // Extract hostname from "Host(`node0.xmtpd.local`)"
            if let Some(hostname) = router
                .rule
                .strip_prefix("Host(`")
                .and_then(|s| s.strip_suffix("`)"))
            {
                // Get port from corresponding service (only auto-generated routes
                // use the h2c://xnet-toxiproxy:{port} URL pattern)
                if let Some(service) = config.http.services.get(&router.service)
                    && let Some(server) = service.load_balancer.servers.first()
                    && let Some(port_str) = server.url.strip_prefix("h2c://xnet-toxiproxy:")
                    && let Ok(port) = port_str.parse()
                {
                    routes.insert(hostname.to_string(), port);
                }
            }
        }

        routes
    }

    /// Create a new Traefik config manager.
    ///
    /// The config file will be written to the specified path.
    /// Creates parent directories if they don't exist.
    /// Loads existing routes from the file if it exists.
    pub fn new(config_path: impl Into<PathBuf>, use_tls: bool) -> Result<Self> {
        let config_path = config_path.into();

        // Create parent directory if it doesn't exist
        if let Some(parent) = config_path.parent() {
            fs::create_dir_all(parent)?;
        }

        // Load existing routes from file
        let routes = Self::load_from_file(&config_path);
        info!(
            "Loaded {} existing routes from {}",
            routes.len(),
            config_path.display()
        );

        Ok(Self {
            config_path,
            use_tls,
            routes: Arc::new(Mutex::new(routes)),
            extra_routes: Arc::new(Mutex::new(Vec::new())),
        })
    }

    /// Add a route mapping hostname to ToxiProxy port.
    ///
    /// This will update the dynamic.yml file, which Traefik will automatically reload.
    pub fn add_route(&self, hostname: impl Into<String>, toxi_port: u16) -> Result<()> {
        let hostname = hostname.into();

        {
            let mut routes = self.routes.lock().unwrap();
            routes.insert(hostname.clone(), toxi_port);
        }

        self.write()?;
        info!(
            "Added Traefik route: {} -> toxiproxy:{}",
            hostname, toxi_port
        );
        Ok(())
    }

    /// Remove a route for the given hostname.
    ///
    /// This will update the dynamic.yml file, which Traefik will automatically reload.
    pub fn remove_route(&self, hostname: &str) -> Result<()> {
        {
            let mut routes = self.routes.lock().unwrap();
            routes.remove(hostname);
        }

        self.write()?;
        info!("Removed Traefik route: {}", hostname);
        Ok(())
    }

    /// Get all current routes.
    pub fn routes(&self) -> HashMap<String, u16> {
        self.routes.lock().unwrap().clone()
    }

    /// Set user-defined extra routes from TOML config.
    ///
    /// Extra routes are stored in memory only (not round-tripped through YAML)
    /// and merged into dynamic.yml on every write() call.
    pub fn set_extra_routes(&self, routes: Vec<ExtraTraefikRoute>) -> Result<()> {
        {
            let mut extra = self.extra_routes.lock().unwrap();
            *extra = routes;
        }
        self.write()?;
        info!(
            "Set {} extra Traefik route(s)",
            self.extra_routes.lock().unwrap().len()
        );
        Ok(())
    }

    /// Write the current configuration to the dynamic.yml file.
    ///
    /// Traefik will automatically detect and reload the changes.
    fn write(&self) -> Result<()> {
        let routes = self.routes.lock().unwrap();
        let extra = self.extra_routes.lock().unwrap();

        let mut routers = HashMap::new();
        let mut services = HashMap::new();
        let mut middlewares = HashMap::new();
        let mut any_tls = false;

        for (hostname, toxi_port) in routes.iter() {
            let name = hostname.replace(['.', '-'], "_");

            if self.use_tls {
                // HTTPS router (primary)
                routers.insert(
                    name.clone(),
                    Router {
                        rule: format!("Host(`{}`)", hostname),
                        service: name.clone(),
                        priority: None,
                        tls: Some(TlsConfig {
                            cert_resolver: None,
                        }),
                        entry_points: Some(vec!["https".to_string()]),
                        middlewares: None,
                    },
                );
                // HTTP → HTTPS redirect router
                routers.insert(
                    format!("{}_redirect", name),
                    Router {
                        rule: format!("Host(`{}`)", hostname),
                        service: name.clone(),
                        priority: None,
                        tls: None,
                        entry_points: Some(vec!["http".to_string()]),
                        middlewares: Some(vec!["redirect-https".to_string()]),
                    },
                );
                any_tls = true;
            } else {
                routers.insert(
                    name.clone(),
                    Router {
                        rule: format!("Host(`{}`)", hostname),
                        service: name.clone(),
                        priority: None,
                        tls: None,
                        entry_points: None,
                        middlewares: None,
                    },
                );
            }

            services.insert(
                name,
                TraefikService {
                    load_balancer: LoadBalancer {
                        servers: vec![Server {
                            url: format!("h2c://xnet-toxiproxy:{}", toxi_port),
                        }],
                        servers_transport: None,
                        pass_host_header: Some(true),
                    },
                },
            );
        }

        // Extra routes (user-defined, may use any URL/rule)

        for route in extra.iter() {
            if route.tls {
                any_tls = true;

                let tls_config = if self.use_tls {
                    TlsConfig {
                        cert_resolver: None,
                    }
                } else {
                    TlsConfig {
                        cert_resolver: Some("letsencrypt".to_string()),
                    }
                };

                // HTTPS router with cert resolver
                routers.insert(
                    route.name.clone(),
                    Router {
                        rule: route.rule.clone(),
                        service: route.name.clone(),
                        priority: route.priority,
                        tls: Some(tls_config),
                        entry_points: Some(vec!["https".to_string()]),
                        middlewares: None,
                    },
                );

                // HTTP → HTTPS redirect router
                routers.insert(
                    format!("{}-redirect", route.name),
                    Router {
                        rule: route.rule.clone(),
                        service: route.name.clone(),
                        priority: route.priority,
                        entry_points: Some(vec!["http".to_string()]),
                        middlewares: Some(vec!["redirect-https".to_string()]),
                        tls: None,
                    },
                );
            } else {
                routers.insert(
                    route.name.clone(),
                    Router {
                        rule: route.rule.clone(),
                        service: route.name.clone(),
                        priority: route.priority,
                        tls: None,
                        entry_points: None,
                        middlewares: None,
                    },
                );
            }

            services.insert(
                route.name.clone(),
                TraefikService {
                    load_balancer: LoadBalancer {
                        servers: vec![Server {
                            url: route.url.clone(),
                        }],
                        servers_transport: None,
                        pass_host_header: Some(true),
                    },
                },
            );
        }

        // Insert redirect middleware once if any route uses TLS
        if any_tls {
            middlewares.insert(
                "redirect-https".to_string(),
                Middleware {
                    redirect_scheme: Some(RedirectScheme {
                        scheme: "https".to_string(),
                        permanent: true,
                    }),
                },
            );
        }

        let config = TraefikDynamicConfig {
            http: HttpConfig {
                routers,
                services,
                servers_transports: None,
                middlewares: if middlewares.is_empty() {
                    None
                } else {
                    Some(middlewares)
                },
            },
        };

        let yaml = serde_yaml::to_string(&config)?;
        fs::write(&self.config_path, yaml)?;

        debug!(
            "Wrote Traefik config with {} routes ({} auto + {} extra) to {}",
            routes.len() + extra.len(),
            routes.len(),
            extra.len(),
            self.config_path.display()
        );

        Ok(())
    }

    /// Get the config file path.
    pub fn path(&self) -> &Path {
        &self.config_path
    }

    /// Print /etc/hosts entries for all registered routes.
    ///
    /// Returns a formatted string that can be appended to /etc/hosts.
    /// All hostnames resolve to 127.0.0.1 for local access through Traefik.
    /// In remote mode, returns empty (sslip.io handles DNS resolution).
    pub fn hosts_entries(&self) -> String {
        // In remote mode, no /etc/hosts entries needed
        if crate::Config::load()
            .map(|c| c.address_mode.is_remote())
            .unwrap_or(false)
        {
            return String::new();
        }

        let routes = self.routes.lock().unwrap();

        if routes.is_empty() {
            return String::new();
        }

        let mut entries = vec!["# xnet hostname entries (generated by xnet)".to_string()];

        for hostname in routes.keys() {
            entries.push(format!("127.0.0.1 {}", hostname));
        }

        entries.join("\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ExtraTraefikRoute;
    use tempfile::NamedTempFile;

    fn temp_config() -> (TraefikConfig, NamedTempFile) {
        let file = NamedTempFile::new().unwrap();
        let config = TraefikConfig::new(file.path(), false).unwrap();
        (config, file)
    }

    fn temp_config_tls() -> (TraefikConfig, NamedTempFile) {
        let file = NamedTempFile::new().unwrap();
        let config = TraefikConfig::new(file.path(), true).unwrap();
        (config, file)
    }

    #[test]
    fn write_with_no_routes_produces_empty_config() {
        let (config, file) = temp_config();
        config.write().unwrap();
        let contents = fs::read_to_string(file.path()).unwrap();
        let parsed: TraefikDynamicConfig = serde_yaml::from_str(&contents).unwrap();
        assert!(parsed.http.routers.is_empty());
        assert!(parsed.http.services.is_empty());
    }

    #[test]
    fn extra_routes_appear_in_dynamic_yaml() {
        let (config, file) = temp_config();
        config
            .set_extra_routes(vec![ExtraTraefikRoute {
                name: "status-page".to_string(),
                rule: "Host(`migrate.xmtp.run`)".to_string(),
                url: "http://127.0.0.1:8899".to_string(),
                priority: Some(100),
                ..Default::default()
            }])
            .unwrap();

        let contents = fs::read_to_string(file.path()).unwrap();
        let parsed: TraefikDynamicConfig = serde_yaml::from_str(&contents).unwrap();

        let router = parsed
            .http
            .routers
            .get("status-page")
            .expect("router missing");
        assert_eq!(router.rule, "Host(`migrate.xmtp.run`)");
        assert_eq!(router.service, "status-page");
        assert_eq!(router.priority, Some(100));

        let service = parsed
            .http
            .services
            .get("status-page")
            .expect("service missing");
        assert_eq!(
            service.load_balancer.servers[0].url,
            "http://127.0.0.1:8899"
        );
        assert_eq!(service.load_balancer.pass_host_header, Some(true));
    }

    #[test]
    fn extra_routes_without_priority_omit_priority_field() {
        let (config, file) = temp_config();
        config
            .set_extra_routes(vec![ExtraTraefikRoute {
                name: "no-priority".to_string(),
                rule: "Host(`example.com`)".to_string(),
                url: "http://127.0.0.1:9999".to_string(),
                priority: None,
                ..Default::default()
            }])
            .unwrap();

        let contents = fs::read_to_string(file.path()).unwrap();
        let parsed: TraefikDynamicConfig = serde_yaml::from_str(&contents).unwrap();
        let router = parsed.http.routers.get("no-priority").unwrap();
        assert_eq!(router.priority, None);
    }

    #[test]
    fn extra_routes_merge_with_auto_routes() {
        let (config, file) = temp_config();
        config.add_route("node100.xmtpd.local", 8150).unwrap();
        config
            .set_extra_routes(vec![ExtraTraefikRoute {
                name: "status-page".to_string(),
                rule: "Host(`migrate.xmtp.run`)".to_string(),
                url: "http://127.0.0.1:8899".to_string(),
                priority: Some(100),
                ..Default::default()
            }])
            .unwrap();

        let contents = fs::read_to_string(file.path()).unwrap();
        let parsed: TraefikDynamicConfig = serde_yaml::from_str(&contents).unwrap();

        // Auto-generated route present
        assert!(parsed.http.routers.contains_key("node100_xmtpd_local"));
        assert!(parsed.http.services.contains_key("node100_xmtpd_local"));

        // Extra route present
        assert!(parsed.http.routers.contains_key("status-page"));
        assert!(parsed.http.services.contains_key("status-page"));

        // Total: 2 routes
        assert_eq!(parsed.http.routers.len(), 2);
        assert_eq!(parsed.http.services.len(), 2);
    }

    #[test]
    fn extra_routes_not_lost_after_add_route() {
        let (config, file) = temp_config();
        config
            .set_extra_routes(vec![ExtraTraefikRoute {
                name: "status-page".to_string(),
                rule: "Host(`migrate.xmtp.run`)".to_string(),
                url: "http://127.0.0.1:8899".to_string(),
                priority: None,
                ..Default::default()
            }])
            .unwrap();

        // Adding a regular route should not lose extra routes
        config.add_route("node200.xmtpd.local", 8151).unwrap();

        let contents = fs::read_to_string(file.path()).unwrap();
        let parsed: TraefikDynamicConfig = serde_yaml::from_str(&contents).unwrap();
        assert!(parsed.http.routers.contains_key("status-page"));
        assert!(parsed.http.routers.contains_key("node200_xmtpd_local"));
    }

    #[test]
    fn load_from_file_ignores_extra_routes_in_yaml() {
        let (config, file) = temp_config();
        // Write an extra route
        config
            .set_extra_routes(vec![ExtraTraefikRoute {
                name: "status-page".to_string(),
                rule: "Host(`migrate.xmtp.run`)".to_string(),
                url: "http://127.0.0.1:8899".to_string(),
                priority: Some(100),
                ..Default::default()
            }])
            .unwrap();

        // Re-load from file — extra routes should NOT be recovered
        // (they are memory-only, sourced from TOML config)
        let config2 = TraefikConfig::new(file.path(), false).unwrap();
        assert!(config2.routes().is_empty());

        // Extra routes Vec should be empty on fresh load
        let extra = config2.extra_routes.lock().unwrap();
        assert!(extra.is_empty());
    }

    #[test]
    fn tls_route_generates_router_with_cert_resolver_and_redirect() {
        let (config, file) = temp_config();
        config
            .set_extra_routes(vec![ExtraTraefikRoute {
                name: "status-page".to_string(),
                rule: "Host(`migrate.xmtp.run`)".to_string(),
                url: "http://xnet-status:8899".to_string(),
                priority: Some(100),
                tls: true,
            }])
            .unwrap();

        let contents = fs::read_to_string(file.path()).unwrap();
        let parsed: TraefikDynamicConfig = serde_yaml::from_str(&contents).unwrap();

        // HTTPS router with certResolver
        let router = parsed
            .http
            .routers
            .get("status-page")
            .expect("HTTPS router missing");
        assert_eq!(router.entry_points, Some(vec!["https".to_string()]));
        let tls = router.tls.as_ref().expect("tls config missing");
        assert_eq!(tls.cert_resolver, Some("letsencrypt".to_string()));

        // HTTP→HTTPS redirect router
        let redirect = parsed
            .http
            .routers
            .get("status-page-redirect")
            .expect("redirect router missing");
        assert_eq!(redirect.entry_points, Some(vec!["http".to_string()]));
        assert_eq!(
            redirect.middlewares,
            Some(vec!["redirect-https".to_string()])
        );
        assert!(redirect.tls.is_none());

        // Redirect middleware
        let mw = parsed
            .http
            .middlewares
            .as_ref()
            .expect("middlewares missing");
        let rs = mw
            .get("redirect-https")
            .expect("redirect-https middleware missing");
        let scheme = rs.redirect_scheme.as_ref().expect("redirectScheme missing");
        assert_eq!(scheme.scheme, "https");
        assert!(scheme.permanent);

        // Service exists
        let svc = parsed
            .http
            .services
            .get("status-page")
            .expect("service missing");
        assert_eq!(svc.load_balancer.servers[0].url, "http://xnet-status:8899");
    }

    #[test]
    fn non_tls_route_has_no_tls_fields() {
        let (config, file) = temp_config();
        config
            .set_extra_routes(vec![ExtraTraefikRoute {
                name: "grafana".to_string(),
                rule: "Host(`grafana.xmtp.run`)".to_string(),
                url: "http://xnet-grafana:3000".to_string(),
                priority: None,
                tls: false,
            }])
            .unwrap();

        let contents = fs::read_to_string(file.path()).unwrap();
        let parsed: TraefikDynamicConfig = serde_yaml::from_str(&contents).unwrap();

        let router = parsed.http.routers.get("grafana").expect("router missing");
        assert!(router.tls.is_none());
        assert!(router.entry_points.is_none());
        assert!(router.middlewares.is_none());

        // No redirect router
        assert!(parsed.http.routers.get("grafana-redirect").is_none());
    }

    #[test]
    fn mixed_tls_and_non_tls_routes() {
        let (config, file) = temp_config();
        config
            .set_extra_routes(vec![
                ExtraTraefikRoute {
                    name: "status-page".to_string(),
                    rule: "Host(`migrate.xmtp.run`)".to_string(),
                    url: "http://xnet-status:8899".to_string(),
                    priority: Some(100),
                    tls: true,
                },
                ExtraTraefikRoute {
                    name: "grafana".to_string(),
                    rule: "Host(`grafana.xmtp.run`)".to_string(),
                    url: "http://xnet-grafana:3000".to_string(),
                    priority: None,
                    tls: false,
                },
            ])
            .unwrap();

        let contents = fs::read_to_string(file.path()).unwrap();
        let parsed: TraefikDynamicConfig = serde_yaml::from_str(&contents).unwrap();

        // TLS route: main + redirect = 2 routers, non-TLS: 1 router => total 3
        assert_eq!(parsed.http.routers.len(), 3);
        assert!(parsed.http.routers.contains_key("status-page"));
        assert!(parsed.http.routers.contains_key("status-page-redirect"));
        assert!(parsed.http.routers.contains_key("grafana"));

        // Only 2 services (redirect router shares the service)
        assert_eq!(parsed.http.services.len(), 2);
    }

    #[test]
    fn auto_routes_get_tls_when_use_tls_enabled() {
        let (config, file) = temp_config_tls();
        config.add_route("node100.xmtp.run", 8150).unwrap();

        let contents = fs::read_to_string(file.path()).unwrap();
        let parsed: TraefikDynamicConfig = serde_yaml::from_str(&contents).unwrap();

        let name = "node100_xmtp_run";
        let router = parsed.http.routers.get(name).expect("HTTPS router missing");
        assert_eq!(router.entry_points, Some(vec!["https".to_string()]));
        let tls = router.tls.as_ref().expect("tls config missing");
        assert!(
            tls.cert_resolver.is_none(),
            "file-based TLS should have no certResolver"
        );

        let redirect_name = format!("{}_redirect", name);
        let redirect = parsed
            .http
            .routers
            .get(&redirect_name)
            .expect("redirect router missing");
        assert_eq!(redirect.entry_points, Some(vec!["http".to_string()]));
        assert_eq!(
            redirect.middlewares,
            Some(vec!["redirect-https".to_string()])
        );
        assert!(redirect.tls.is_none());

        let mw = parsed
            .http
            .middlewares
            .as_ref()
            .expect("middlewares missing");
        assert!(mw.contains_key("redirect-https"));
    }

    #[test]
    fn auto_routes_no_tls_when_use_tls_disabled() {
        let (config, file) = temp_config();
        config.add_route("node100.xmtpd.local", 8150).unwrap();

        let contents = fs::read_to_string(file.path()).unwrap();
        let parsed: TraefikDynamicConfig = serde_yaml::from_str(&contents).unwrap();

        let router = parsed
            .http
            .routers
            .get("node100_xmtpd_local")
            .expect("router missing");
        assert!(router.tls.is_none());
        assert!(router.entry_points.is_none());
        assert!(router.middlewares.is_none());
        assert!(
            !parsed
                .http
                .routers
                .contains_key("node100_xmtpd_local_redirect")
        );
    }

    #[test]
    fn extra_route_tls_uses_file_cert_when_use_tls_enabled() {
        let (config, file) = temp_config_tls();
        config
            .set_extra_routes(vec![ExtraTraefikRoute {
                name: "status-page".to_string(),
                rule: "Host(`migrate.xmtp.run`)".to_string(),
                url: "http://xnet-status:8899".to_string(),
                priority: Some(100),
                tls: true,
            }])
            .unwrap();

        let contents = fs::read_to_string(file.path()).unwrap();
        let parsed: TraefikDynamicConfig = serde_yaml::from_str(&contents).unwrap();

        let router = parsed
            .http
            .routers
            .get("status-page")
            .expect("HTTPS router missing");
        let tls = router.tls.as_ref().expect("tls config missing");
        assert!(tls.cert_resolver.is_none());
        assert_eq!(router.entry_points, Some(vec!["https".to_string()]));
    }
}
