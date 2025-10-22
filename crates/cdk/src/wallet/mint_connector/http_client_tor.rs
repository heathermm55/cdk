//! HTTP client with Tor support using SOCKS proxy

#[cfg(feature = "tor")]
use std::sync::{Arc, RwLock};

#[cfg(feature = "tor")]
use arti_client::{TorClient, TorClientConfig};
#[cfg(feature = "tor")]
use tor_rtcompat::PreferredRuntime;
#[cfg(feature = "tor")]
use tor_config::Listen;
#[cfg(feature = "tor")]
use async_trait::async_trait;
#[cfg(feature = "tor")]
use tokio::task::JoinHandle;

use super::Error;
use crate::mint_url::MintUrl;
use crate::nuts::{
    CheckStateRequest, CheckStateResponse, Id, KeySet, KeysResponse, KeysetResponse, MeltQuoteBolt11Request,
    MeltQuoteBolt11Response, MeltRequest, MintInfo, MintQuoteBolt11Request,
    MintQuoteBolt11Response, MintRequest, MintResponse, RestoreRequest, RestoreResponse,
    SwapRequest, SwapResponse,
};
#[cfg(feature = "auth")]
use crate::wallet::AuthWallet;

use super::{HttpClient, MintConnector};

/// Tor usage policy
#[cfg(feature = "tor")]
#[derive(Debug, Clone)]
pub enum TorPolicy {
    /// Never use Tor
    Never,
    /// Only use Tor for .onion addresses
    OnionOnly,
    /// Always use Tor for all requests
    Always,
}

/// Tor configuration
#[cfg(feature = "tor")]
#[derive(Debug, Clone)]
pub struct TorConfig {
    /// Tor usage policy
    pub policy: TorPolicy,
    /// Tor client configuration
    pub client_config: Option<TorClientConfig>,
    /// Whether to accept invalid certificates
    pub accept_invalid_certs: bool,
    /// Cache directory for Tor (optional, defaults to in-memory if not provided)
    pub cache_dir: Option<String>,
    /// State directory for Tor (optional, defaults to in-memory if not provided)
    pub state_dir: Option<String>,
    /// Tor bridges (optional, for censored networks)
    /// Format: "obfs4 IP:PORT FINGERPRINT cert=CERT iat-mode=0"
    pub bridges: Option<Vec<String>>,
}

/// Tor manager - singleton instance  
#[cfg(feature = "tor")]
pub struct TorManager {
    config: Arc<RwLock<Option<TorConfig>>>,
    tor_client: Arc<RwLock<Option<TorClient<PreferredRuntime>>>>,
    socks_proxy: Arc<RwLock<Option<JoinHandle<anyhow::Result<()>>>>>,
    socks_port: Arc<RwLock<Option<u16>>>,
    tor_http_client: Arc<RwLock<Option<Arc<reqwest::Client>>>>,
}

#[cfg(feature = "tor")]
impl TorManager {
    /// Create new Tor manager
    pub fn new() -> Self {
        Self {
            config: Arc::new(RwLock::new(None)),
            tor_client: Arc::new(RwLock::new(None)),
            socks_proxy: Arc::new(RwLock::new(None)),
            socks_port: Arc::new(RwLock::new(None)),
            tor_http_client: Arc::new(RwLock::new(None)),
        }
    }

    /// Set Tor configuration
    pub async fn set_config(&self, config: TorConfig) -> Result<(), Error> {
        // Store config
        {
            let mut config_guard = self.config.write().unwrap();
            *config_guard = Some(config.clone());
        }

        // Initialize Tor client if needed
        if !matches!(config.policy, TorPolicy::Never) {
            self.initialize_tor_client(&config).await?;
        }

        Ok(())
    }

    /// Get current Tor configuration
    pub fn get_config(&self) -> Option<TorConfig> {
        self.config.read().unwrap().clone()
    }

    /// Check if Tor should be used for a given URL
    pub fn should_use_tor(&self, url: &MintUrl) -> bool {
        let url_str = url.to_string();
        let is_onion = url_str.contains(".onion");
        
        let config_guard = self.config.read().unwrap();
        let result = match config_guard.as_ref() {
            Some(config) => {
                tracing::info!(
                    "TorManager::should_use_tor: url={}, is_onion={}, policy={:?}",
                    url_str, is_onion, config.policy
                );
                match config.policy {
                    TorPolicy::Never => false,
                    TorPolicy::OnionOnly => is_onion,
                    TorPolicy::Always => true,
                }
            },
            // Default behavior: use Tor for .onion addresses even without explicit config
            None => {
                tracing::warn!(
                    "TorManager::should_use_tor: url={}, is_onion={}, NO CONFIG SET (defaulting to onion-only)",
                    url_str, is_onion
                );
                is_onion
            }
        };
        
        tracing::info!("TorManager::should_use_tor: result={}", result);
        result
    }

    /// Get Tor HTTP client for making requests
    /// Creates client lazily with SOCKS proxy configuration
    pub async fn get_tor_http_client(&self) -> Result<Option<Arc<reqwest::Client>>, Error> {
        // Check if client already exists
        {
            let client_guard = self.tor_http_client.read().unwrap();
            if client_guard.is_some() {
                tracing::info!("Reusing existing Tor HTTP client with SOCKS proxy");
                return Ok(client_guard.clone());
            }
        }
        
        // Get SOCKS port
        let socks_port = {
            let port_guard = self.socks_port.read().unwrap();
            *port_guard
        };
        
        if let Some(port) = socks_port {
            tracing::info!("Creating Tor HTTP client with SOCKS proxy on port {}", port);
            
            // Build reqwest client with SOCKS proxy
            // Timeouts must be longer than Arti's internal timeouts to allow full descriptor fetch
            let proxy_url = format!("socks5h://127.0.0.1:{}", port);  // socks5h = DNS through proxy
            let http_client = reqwest::Client::builder()
                .proxy(reqwest::Proxy::all(&proxy_url)
                    .map_err(|e| Error::TorError(format!("Failed to create SOCKS proxy: {}", e)))?)
                .timeout(std::time::Duration::from_secs(300))  // 6 minutes total (longer than Arti's 5 min)
                .connect_timeout(std::time::Duration::from_secs(120))  // 2 minutes to connect via bridge
                .build()
                .map_err(|e| Error::TorError(format!("Failed to build reqwest client: {}", e)))?;
            
            let http_client = Arc::new(http_client);
            tracing::info!("Tor HTTP client with SOCKS proxy created successfully");
            
            // Cache it
            {
                let mut client_guard = self.tor_http_client.write().unwrap();
                *client_guard = Some(http_client.clone());
            }
            
            Ok(Some(http_client))
        } else {
            Ok(None)
        }
    }

    /// Initialize Tor client
    async fn initialize_tor_client(&self, config: &TorConfig) -> Result<(), Error> {
        use arti_client::config::CfgPath;
        
        let tor_config = if let Some(cfg) = &config.client_config {
            cfg.clone()
        } else {
            // Build config with custom storage paths if provided
            let mut builder = TorClientConfig::builder();
            
            // Configure storage paths if provided
            if let Some(cache_dir) = &config.cache_dir {
                tracing::info!("Using Tor cache directory: {}", cache_dir);
                builder.storage()
                    .cache_dir(CfgPath::new(cache_dir.clone()));
            }
            
            if let Some(state_dir) = &config.state_dir {
                tracing::info!("Using Tor state directory: {}", state_dir);
                builder.storage()
                    .state_dir(CfgPath::new(state_dir.clone()));
            }
            
            // Configure bridges if provided (for censored networks)
            if let Some(bridges) = &config.bridges {
                if !bridges.is_empty() {
                    use std::str::FromStr;
                    use arti_client::config::pt::TransportConfigBuilder;
                    
                    tracing::info!("Configuring {} Tor bridges for censored network", bridges.len());
                    
                    let mut bridge_builders = Vec::new();
                    let mut needs_obfs4 = false;
                    
                    for (idx, bridge_line) in bridges.iter().enumerate() {
                        tracing::info!("Bridge {}: {}", idx + 1, bridge_line);
                        
                        // Check if this is an obfs4 bridge
                        if bridge_line.starts_with("obfs4 ") {
                            needs_obfs4 = true;
                        }
                        
                        // Parse bridge line using FromStr (requires bridge-client feature in arti-client)
                        match arti_client::config::BridgeConfigBuilder::from_str(bridge_line) {
                            Ok(bridge_builder) => {
                                tracing::info!("Successfully parsed bridge {}", idx + 1);
                                bridge_builders.push(bridge_builder);
                            }
                            Err(e) => {
                                tracing::warn!("Failed to parse bridge {} '{}': {}", idx + 1, bridge_line, e);
                            }
                        }
                    }
                    
                    // Add parsed bridges to config
                    if !bridge_builders.is_empty() {
                        tracing::info!("Adding {} valid bridges to Tor configuration", bridge_builders.len());
                        *builder.bridges().bridges() = bridge_builders;
                        
                        // Configure obfs4 transport if needed
                        if needs_obfs4 {
                            tracing::info!("Configuring obfs4 pluggable transport");
                            let mut transport = TransportConfigBuilder::default();
                            
                            // Parse protocol name
                            match "obfs4".parse() {
                                Ok(protocol) => {
                                    transport.protocols(vec![protocol]);
                                    
                                    // Set path to obfs4proxy binary
                                    // Note: On Android, this might need to be bundled with the app
                                    // For now, we'll try common paths
                                    transport.path(CfgPath::new("obfs4proxy".into()));
                                    transport.run_on_startup(true);
                                    
                                    builder.bridges().transports().push(transport);
                                    tracing::info!("obfs4 transport configured successfully");
                                }
                                Err(e) => {
                                    tracing::error!("Failed to parse obfs4 protocol: {}", e);
                                }
                            }
                        }
                    } else {
                        tracing::warn!("No valid bridges could be parsed");
                    }
                }
            }
            
            // Configure aggressive timeouts for hidden service connections
            // These are especially important when using bridges with high latency
            tracing::info!("Configuring extended timeouts for hidden service connections via bridges");
            use std::time::Duration;
            
            builder.circuit_timing()
                .request_timeout(Duration::from_secs(250))  // 5 minutes for circuit requests (bridges are slow)
                .hs_desc_fetch_attempts(20)  // Many more attempts for descriptor fetch
                .hs_intro_rend_attempts(20)  // Many more attempts for intro/rendezvous
                .max_dirtiness(Duration::from_secs(3600));  // Keep circuits alive longer (1 hour)
            
            // Aggressive stream timeouts for high-latency bridge connections
            builder.stream_timeouts()
                .connect_timeout(Duration::from_secs(60))  // 1 minute for stream connect
                .resolve_timeout(Duration::from_secs(60))  // 1 minute for DNS resolve
                .resolve_ptr_timeout(Duration::from_secs(60));  // 1 minute for PTR resolve
            
            // Configure download schedule for better reliability with bridges
            builder.download_schedule()
                .retry_bootstrap()
                .attempts(100)  // More bootstrap retry attempts
                .initial_delay(Duration::from_secs(5))
                .parallelism(4);  // More parallel requests
            
            // Build the config
            builder.build()
                .map_err(|e| Error::TorError(format!("Failed to build Tor config: {}", e)))?
        };
        
        tracing::info!("Attempting to bootstrap Tor client...");
        
        // Create Tor client (uses current Tokio runtime from Flutter Rust Bridge)
        let tor_client = TorClient::create_bootstrapped(tor_config)
            .await
            .map_err(|e| Error::TorError(format!("Failed to create Tor client: {}", e)))?;

        tracing::info!("Tor client bootstrapped successfully");

        // Start SOCKS proxy on a random available port
        use std::net::{TcpListener, SocketAddr};
        let temp_listener = TcpListener::bind("127.0.0.1:0")
            .map_err(|e| Error::TorError(format!("Failed to find available port: {}", e)))?;
        let socks_addr: SocketAddr = temp_listener.local_addr()
            .map_err(|e| Error::TorError(format!("Failed to get local address: {}", e)))?;
        let socks_port = socks_addr.port();
        drop(temp_listener); // Release the port
        
        tracing::info!("Starting SOCKS proxy on port {}", socks_port);
        
        // Start SOCKS proxy server (using arti's experimental API)
        let client_clone = tor_client.clone();
        let runtime_clone = tor_client.runtime().clone();
        let proxy_handle = tokio::spawn(arti::socks::run_socks_proxy(
            runtime_clone,
            client_clone,
            Listen::new_localhost(socks_port),
            None,
        ));
        
        tracing::info!("SOCKS proxy started successfully on port {}", socks_port);

        // Store TorClient, proxy handle, and SOCKS port
        {
            let mut client_guard = self.tor_client.write().unwrap();
            *client_guard = Some(tor_client);
        }
        {
            let mut proxy_guard = self.socks_proxy.write().unwrap();
            *proxy_guard = Some(proxy_handle);
        }
        {
            let mut port_guard = self.socks_port.write().unwrap();
            *port_guard = Some(socks_port);
        }

        tracing::info!("Tor client and SOCKS proxy initialized successfully");

        Ok(())
    }
}

#[cfg(feature = "tor")]
impl Default for TorManager {
    fn default() -> Self {
        Self::new()
    }
}

// Global singleton instance
#[cfg(feature = "tor")]
lazy_static::lazy_static! {
    pub static ref TOR_MANAGER: TorManager = TorManager::new();
}

/// Set Tor configuration
#[cfg(feature = "tor")]
pub async fn set_tor_config(config: TorConfig) -> Result<(), Error> {
    TOR_MANAGER.set_config(config).await
}

/// Get Tor configuration
#[cfg(feature = "tor")]
pub fn get_tor_config() -> Option<TorConfig> {
    TOR_MANAGER.get_config()
}

/// Check if Tor should be used for a given URL
#[cfg(feature = "tor")]
pub fn should_use_tor_for_url(url: &MintUrl) -> bool {
    TOR_MANAGER.should_use_tor(url)
}

/// Get Tor HTTP client for making requests
#[cfg(feature = "tor")]
pub async fn get_tor_http_client() -> Result<Option<Arc<reqwest::Client>>, Error> {
    TOR_MANAGER.get_tor_http_client().await
}

/// Check if Tor is ready (HTTP client initialized)
#[cfg(feature = "tor")]
pub async fn is_tor_ready() -> Result<bool, Error> {
    let client = TOR_MANAGER.get_tor_http_client().await?;
    Ok(client.is_some())
}

// Non-Tor implementations (when feature is disabled)
#[cfg(not(feature = "tor"))]
pub async fn set_tor_config(_config: ()) -> Result<(), Error> {
    Err(Error::TorError("Tor feature not enabled".to_string()))
}

#[cfg(not(feature = "tor"))]
pub fn get_tor_config() -> Option<()> {
    None
}

#[cfg(not(feature = "tor"))]
pub fn should_use_tor_for_url(_url: &MintUrl) -> bool {
    false
}

#[cfg(not(feature = "tor"))]
pub async fn get_tor_http_client() -> Result<Option<()>, Error> {
    Ok(None)
}

/// HTTP client with Tor support that automatically routes requests based on global configuration
#[cfg(feature = "tor")]
#[derive(Debug, Clone)]
pub struct HttpClientTor {
    /// Regular HTTP client for non-Tor requests
    http_client: HttpClient,
    /// Mint URL
    mint_url: MintUrl,
    #[cfg(feature = "auth")]
    auth_wallet: Arc<RwLock<Option<AuthWallet>>>,
}

#[cfg(feature = "tor")]
impl HttpClientTor {
    /// Create new HttpClientTor
    pub fn new(
        mint_url: MintUrl,
        #[cfg(feature = "auth")]
        auth_wallet: Option<AuthWallet>,
    ) -> Result<Self, Error> {
        #[cfg(feature = "auth")]
        let http_client = HttpClient::new(mint_url.clone(), auth_wallet.clone())?;
        
        #[cfg(not(feature = "auth"))]
        let http_client = HttpClient::new(mint_url.clone())?;
        
        Ok(Self {
            http_client,
            mint_url,
            #[cfg(feature = "auth")]
            auth_wallet: Arc::new(RwLock::new(auth_wallet)),
        })
    }

    /// Check if Tor should be used for this mint URL
    fn should_use_tor(&self) -> bool {
        should_use_tor_for_url(&self.mint_url)
    }

    /// Get the appropriate client for making requests
    async fn get_client(&self) -> Result<ClientType, Error> {
        if self.should_use_tor() {
            let url_str = self.mint_url.to_string();
            let is_onion = url_str.contains(".onion");
            
            let tor_http_client = get_tor_http_client().await?;
            match tor_http_client {
                Some(client) => {
                    tracing::info!("Using Tor client for {}", url_str);
                    Ok(ClientType::Tor(client))
                },
                None => {
                    // Tor is not initialized
                    // Check if TorPolicy::Always is set
                    let config = TOR_MANAGER.get_config();
                    let is_always_tor = config
                        .as_ref()
                        .map(|c| matches!(c.policy, TorPolicy::Always))
                        .unwrap_or(false);
                    
                    if is_onion || is_always_tor {
                        // For .onion addresses or TorPolicy::Always, Tor is required
                        return Err(Error::TorError(
                            format!(
                                "Tor is not initialized. {} Please call set_tor_config_with_paths() \
                                with proper storage directories before accessing the mint.",
                                if is_onion { "For .onion addresses," } else { "TorPolicy::Always is set." }
                            )
                        ));
                    }
                    // For non-onion addresses with OnionOnly policy, fallback to HTTP
                    tracing::warn!("Tor not initialized for non-onion address, falling back to HTTP client");
                    Ok(ClientType::Http(self.http_client.clone()))
                }
            }
        } else {
            tracing::info!("Using direct HTTP client for {}", self.mint_url);
            Ok(ClientType::Http(self.http_client.clone()))
        }
    }
    
    /// Get URL with correct protocol for Tor requests
    /// For .onion addresses, use http instead of https
    fn get_tor_url(&self) -> String {
        let url_str = self.mint_url.to_string();
        if url_str.starts_with("https://") && url_str.contains(".onion") {
            // Replace https with http for .onion addresses
            url_str.replace("https://", "http://")
        } else {
            url_str
        }
    }
}

#[cfg(feature = "tor")]
#[derive(Debug)]
enum ClientType {
    Http(HttpClient),
    Tor(Arc<reqwest::Client>),
}

#[cfg(feature = "tor")]
#[async_trait]
impl MintConnector for HttpClientTor {
    async fn get_mint_keys(&self) -> Result<Vec<KeySet>, Error> {
        let client = self.get_client().await?;
        match client {
            ClientType::Http(http_client) => http_client.get_mint_keys().await,
            ClientType::Tor(tor_client) => {
                let base_url = self.get_tor_url();
                let url = format!("{}/v1/keys", base_url);
                
                let response = tor_client.get(&url)
                    .send()
                    .await
                    .map_err(|e| Error::TorError(format!("Tor request failed: {}", e)))?;
                
                let keys_response: KeysResponse = response.json()
                    .await
                    .map_err(|e| Error::TorError(format!("Failed to parse response: {}", e)))?;
                
                Ok(keys_response.keysets)
            }
        }
    }

    async fn get_mint_keyset(&self, keyset_id: Id) -> Result<KeySet, Error> {
        let client = self.get_client().await?;
        match client {
            ClientType::Http(http_client) => http_client.get_mint_keyset(keyset_id).await,
            ClientType::Tor(tor_client) => {
                let base_url = self.get_tor_url();
                let url = format!("{}/v1/keys/{}", base_url, keyset_id);
                
                let response = tor_client.get(&url)
                    .send()
                    .await
                    .map_err(|e| Error::TorError(format!("Tor request failed: {}", e)))?;
                
                let keys_response: KeysResponse = response.json()
                    .await
                    .map_err(|e| Error::TorError(format!("Failed to parse response: {}", e)))?;
                
                Ok(keys_response.keysets.first().unwrap().clone())
            }
        }
    }

    async fn get_mint_keysets(&self) -> Result<KeysetResponse, Error> {
        let client = self.get_client().await?;
        match client {
            ClientType::Http(http_client) => http_client.get_mint_keysets().await,
            ClientType::Tor(tor_client) => {
                let base_url = self.get_tor_url();
                let url = format!("{}/v1/keysets", base_url);
                
                let response = tor_client.get(&url)
                    .send()
                    .await
                    .map_err(|e| Error::TorError(format!("Tor request failed: {}", e)))?;
                
                let keysets: KeysetResponse = response.json()
                    .await
                    .map_err(|e| Error::TorError(format!("Failed to parse response: {}", e)))?;
                
                Ok(keysets)
            }
        }
    }

    async fn post_mint_quote(&self, request: MintQuoteBolt11Request) -> Result<MintQuoteBolt11Response<String>, Error> {
        let client = self.get_client().await?;
        match client {
            ClientType::Http(http_client) => http_client.post_mint_quote(request).await,
            ClientType::Tor(tor_client) => {
                let base_url = self.get_tor_url();
                let url = format!("{}/v1/mint/quote/bolt11", base_url);
                
                let response = tor_client.post(&url)
                    .json(&request)
                    .send()
                    .await
                    .map_err(|e| Error::TorError(format!("Tor request failed: {}", e)))?;
                
                let quote: MintQuoteBolt11Response<String> = response.json()
                    .await
                    .map_err(|e| Error::TorError(format!("Failed to parse response: {}", e)))?;
                
                Ok(quote)
            }
        }
    }

    async fn get_mint_quote_status(&self, quote_id: &str) -> Result<MintQuoteBolt11Response<String>, Error> {
        let client = self.get_client().await?;
        match client {
            ClientType::Http(http_client) => http_client.get_mint_quote_status(quote_id).await,
            ClientType::Tor(tor_client) => {
                let base_url = self.get_tor_url();
                let url = format!("{}/v1/mint/quote/bolt11/{}", base_url, quote_id);
                
                let response = tor_client.get(&url)
                    .send()
                    .await
                    .map_err(|e| Error::TorError(format!("Tor request failed: {}", e)))?;
                
                let quote: MintQuoteBolt11Response<String> = response.json()
                    .await
                    .map_err(|e| Error::TorError(format!("Failed to parse response: {}", e)))?;
                
                Ok(quote)
            }
        }
    }

    async fn post_mint(&self, request: MintRequest<String>) -> Result<MintResponse, Error> {
        let client = self.get_client().await?;
        match client {
            ClientType::Http(http_client) => http_client.post_mint(request).await,
            ClientType::Tor(tor_client) => {
                let base_url = self.get_tor_url();
                let url = format!("{}/v1/mint/bolt11", base_url);
                
                let response = tor_client.post(&url)
                    .json(&request)
                    .send()
                    .await
                    .map_err(|e| Error::TorError(format!("Tor request failed: {}", e)))?;
                
                let mint_response: MintResponse = response.json()
                    .await
                    .map_err(|e| Error::TorError(format!("Failed to parse response: {}", e)))?;
                
                Ok(mint_response)
            }
        }
    }

    async fn post_melt_quote(&self, request: MeltQuoteBolt11Request) -> Result<MeltQuoteBolt11Response<String>, Error> {
        let client = self.get_client().await?;
        match client {
            ClientType::Http(http_client) => http_client.post_melt_quote(request).await,
            ClientType::Tor(tor_client) => {
                let base_url = self.get_tor_url();
                let url = format!("{}/v1/melt/quote/bolt11", base_url);
                
                let response = tor_client.post(&url)
                    .json(&request)
                    .send()
                    .await
                    .map_err(|e| Error::TorError(format!("Tor request failed: {}", e)))?;
                
                let quote: MeltQuoteBolt11Response<String> = response.json()
                    .await
                    .map_err(|e| Error::TorError(format!("Failed to parse response: {}", e)))?;
                
                Ok(quote)
            }
        }
    }

    async fn get_melt_quote_status(&self, quote_id: &str) -> Result<MeltQuoteBolt11Response<String>, Error> {
        let client = self.get_client().await?;
        match client {
            ClientType::Http(http_client) => http_client.get_melt_quote_status(quote_id).await,
            ClientType::Tor(tor_client) => {
                let base_url = self.get_tor_url();
                let url = format!("{}/v1/melt/quote/bolt11/{}", base_url, quote_id);
                
                let response = tor_client.get(&url)
                    .send()
                    .await
                    .map_err(|e| Error::TorError(format!("Tor request failed: {}", e)))?;
                
                let quote: MeltQuoteBolt11Response<String> = response.json()
                    .await
                    .map_err(|e| Error::TorError(format!("Failed to parse response: {}", e)))?;
                
                Ok(quote)
            }
        }
    }

    async fn post_melt(&self, request: MeltRequest<String>) -> Result<MeltQuoteBolt11Response<String>, Error> {
        let client = self.get_client().await?;
        match client {
            ClientType::Http(http_client) => http_client.post_melt(request).await,
            ClientType::Tor(tor_client) => {
                let base_url = self.get_tor_url();
                let url = format!("{}/v1/melt/bolt11", base_url);
                
                let response = tor_client.post(&url)
                    .json(&request)
                    .send()
                    .await
                    .map_err(|e| Error::TorError(format!("Tor request failed: {}", e)))?;
                
                let melt_response: MeltQuoteBolt11Response<String> = response.json()
                    .await
                    .map_err(|e| Error::TorError(format!("Failed to parse response: {}", e)))?;
                
                Ok(melt_response)
            }
        }
    }

    async fn post_swap(&self, request: SwapRequest) -> Result<SwapResponse, Error> {
        let client = self.get_client().await?;
        match client {
            ClientType::Http(http_client) => http_client.post_swap(request).await,
            ClientType::Tor(tor_client) => {
                let base_url = self.get_tor_url();
                let url = format!("{}/v1/swap", base_url);
                
                let response = tor_client.post(&url)
                    .json(&request)
                    .send()
                    .await
                    .map_err(|e| Error::TorError(format!("Tor request failed: {}", e)))?;
                
                let swap_response: SwapResponse = response.json()
                    .await
                    .map_err(|e| Error::TorError(format!("Failed to parse response: {}", e)))?;
                
                Ok(swap_response)
            }
        }
    }

    async fn get_mint_info(&self) -> Result<MintInfo, Error> {
        let client = self.get_client().await?;
        match client {
            ClientType::Http(http_client) => http_client.get_mint_info().await,
            ClientType::Tor(tor_client) => {
                let base_url = self.get_tor_url();
                let url = format!("{}/v1/info", base_url);
                
                // Make async reqwest GET request through Tor
                let response = tor_client.get(&url)
                    .send()
                    .await
                    .map_err(|e| Error::TorError(format!("Tor request failed: {}", e)))?;
                
                let mint_info: MintInfo = response.json()
                    .await
                    .map_err(|e| Error::TorError(format!("Failed to parse response: {}", e)))?;
                
                Ok(mint_info)
            }
        }
    }

    async fn post_check_state(&self, request: CheckStateRequest) -> Result<CheckStateResponse, Error> {
        let client = self.get_client().await?;
        match client {
            ClientType::Http(http_client) => http_client.post_check_state(request).await,
            ClientType::Tor(tor_client) => {
                let base_url = self.get_tor_url();
                let url = format!("{}/v1/checkstate", base_url);
                
                let response = tor_client.post(&url)
                    .json(&request)
                    .send()
                    .await
                    .map_err(|e| Error::TorError(format!("Tor request failed: {}", e)))?;
                
                let state_response: CheckStateResponse = response.json()
                    .await
                    .map_err(|e| Error::TorError(format!("Failed to parse response: {}", e)))?;
                
                Ok(state_response)
            }
        }
    }

    async fn post_restore(&self, request: RestoreRequest) -> Result<RestoreResponse, Error> {
        let client = self.get_client().await?;
        match client {
            ClientType::Http(http_client) => http_client.post_restore(request).await,
            ClientType::Tor(tor_client) => {
                let base_url = self.get_tor_url();
                let url = format!("{}/v1/restore", base_url);
                
                let response = tor_client.post(&url)
                    .json(&request)
                    .send()
                    .await
                    .map_err(|e| Error::TorError(format!("Tor request failed: {}", e)))?;
                
                let restore_response: RestoreResponse = response.json()
                    .await
                    .map_err(|e| Error::TorError(format!("Failed to parse response: {}", e)))?;
                
                Ok(restore_response)
            }
        }
    }

    #[cfg(feature = "auth")]
    async fn get_auth_wallet(&self) -> Option<AuthWallet> {
        self.auth_wallet.read().unwrap().clone()
    }

    #[cfg(feature = "auth")]
    async fn set_auth_wallet(&self, auth_wallet: Option<AuthWallet>) {
        let mut wallet_guard = self.auth_wallet.write().unwrap();
        *wallet_guard = auth_wallet;
    }
}