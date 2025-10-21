//! HTTP client with Tor support using global configuration

#[cfg(feature = "tor")]
use std::sync::{Arc, RwLock};

#[cfg(feature = "tor")]
use arti_client::{TorClient, TorClientConfig};
#[cfg(feature = "tor")]
use arti_ureq::Connector as ArtiUreqConnector;
#[cfg(feature = "tor")]
use arti_ureq::tor_rtcompat::PreferredRuntime;
#[cfg(feature = "tor")]
use async_trait::async_trait;
#[cfg(feature = "tor")]
use ureq::Agent;

use super::Error;
use crate::mint_url::MintUrl;
use crate::nuts::{
    CheckStateRequest, CheckStateResponse, Id, KeySet, KeysetResponse, MeltQuoteBolt11Request,
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
}

/// Tor manager - singleton instance
#[cfg(feature = "tor")]
pub struct TorManager {
    config: Arc<RwLock<Option<TorConfig>>>,
    tor_client: Arc<RwLock<Option<TorClient<PreferredRuntime>>>>,
    tor_agent: Arc<RwLock<Option<Agent>>>,
}

#[cfg(feature = "tor")]
impl TorManager {
    /// Create new Tor manager
    pub fn new() -> Self {
        Self {
            config: Arc::new(RwLock::new(None)),
            tor_client: Arc::new(RwLock::new(None)),
            tor_agent: Arc::new(RwLock::new(None)),
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
        let config_guard = self.config.read().unwrap();
        match config_guard.as_ref() {
            Some(config) => match config.policy {
                TorPolicy::Never => false,
                TorPolicy::OnionOnly => url.to_string().ends_with(".onion"),
                TorPolicy::Always => true,
            },
            None => false,
        }
    }

    /// Get Tor agent for making requests
    pub async fn get_tor_agent(&self) -> Result<Option<Agent>, Error> {
        let agent_guard = self.tor_agent.read().unwrap();
        Ok(agent_guard.clone())
    }

    /// Initialize Tor client
    async fn initialize_tor_client(&self, config: &TorConfig) -> Result<(), Error> {
        let tor_config = config.client_config.clone().unwrap_or_default();
        
        // Create Tor client
        let tor_client = TorClient::create_bootstrapped(tor_config).await
            .map_err(|e| Error::TorError(format!("Failed to create Tor client: {}", e)))?;

        // Create arti-ureq connector and get agent
        let connector = ArtiUreqConnector::<PreferredRuntime>::builder()
            .map_err(|e| Error::TorError(format!("Failed to create connector builder: {}", e)))?
            .tor_client(tor_client.clone())
            .build()
            .map_err(|e| Error::TorError(format!("Failed to build connector: {}", e)))?;
        
        let tor_agent = connector.agent();

        // Store client and agent
        {
            let mut client_guard = self.tor_client.write().unwrap();
            *client_guard = Some(tor_client);
        }
        {
            let mut agent_guard = self.tor_agent.write().unwrap();
            *agent_guard = Some(tor_agent);
        }

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

/// Get Tor agent for making requests
#[cfg(feature = "tor")]
pub async fn get_tor_agent() -> Result<Option<Agent>, Error> {
    TOR_MANAGER.get_tor_agent().await
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
pub async fn get_tor_agent() -> Result<Option<()>, Error> {
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
            let tor_agent = get_tor_agent().await?;
            match tor_agent {
                Some(agent) => Ok(ClientType::Tor(agent)),
                None => {
                    // Fallback to HTTP if Tor is not available
                    Ok(ClientType::Http(self.http_client.clone()))
                }
            }
        } else {
            Ok(ClientType::Http(self.http_client.clone()))
        }
    }
}

#[cfg(feature = "tor")]
#[derive(Debug)]
enum ClientType {
    Http(HttpClient),
    Tor(Agent),
}

#[cfg(feature = "tor")]
#[async_trait]
impl MintConnector for HttpClientTor {
    async fn get_mint_keys(&self) -> Result<Vec<KeySet>, Error> {
        let client = self.get_client().await?;
        match client {
            ClientType::Http(http_client) => http_client.get_mint_keys().await,
            ClientType::Tor(tor_agent) => {
                // Make request through Tor agent
                let url = format!("{}/keys", self.mint_url);
                let mut response = tor_agent.get(&url).call()
                    .map_err(|e| Error::TorError(format!("Tor request failed: {}", e)))?;
                
                let keys: Vec<KeySet> = serde_json::from_str(&response.body_mut().read_to_string()
                    .map_err(|e| Error::TorError(format!("Failed to read response: {}", e)))?)
                    .map_err(|e| Error::TorError(format!("Failed to parse response: {}", e)))?;
                
                Ok(keys)
            }
        }
    }

    async fn get_mint_keyset(&self, keyset_id: Id) -> Result<KeySet, Error> {
        let client = self.get_client().await?;
        match client {
            ClientType::Http(http_client) => http_client.get_mint_keyset(keyset_id).await,
            ClientType::Tor(tor_agent) => {
                let url = format!("{}/keys/{}", self.mint_url, keyset_id);
                let mut response = tor_agent.get(&url).call()
                    .map_err(|e| Error::TorError(format!("Tor request failed: {}", e)))?;
                
                let keyset: KeySet = serde_json::from_str(&response.body_mut().read_to_string()
                    .map_err(|e| Error::TorError(format!("Failed to read response: {}", e)))?)
                    .map_err(|e| Error::TorError(format!("Failed to parse response: {}", e)))?;
                
                Ok(keyset)
            }
        }
    }

    async fn get_mint_keysets(&self) -> Result<KeysetResponse, Error> {
        let client = self.get_client().await?;
        match client {
            ClientType::Http(http_client) => http_client.get_mint_keysets().await,
            ClientType::Tor(tor_agent) => {
                let url = format!("{}/keysets", self.mint_url);
                let mut response = tor_agent.get(&url).call()
                    .map_err(|e| Error::TorError(format!("Tor request failed: {}", e)))?;
                
                let keysets: KeysetResponse = serde_json::from_str(&response.body_mut().read_to_string()
                    .map_err(|e| Error::TorError(format!("Failed to read response: {}", e)))?)
                    .map_err(|e| Error::TorError(format!("Failed to parse response: {}", e)))?;
                
                Ok(keysets)
            }
        }
    }

    async fn post_mint_quote(&self, request: MintQuoteBolt11Request) -> Result<MintQuoteBolt11Response<String>, Error> {
        let client = self.get_client().await?;
        match client {
            ClientType::Http(http_client) => http_client.post_mint_quote(request).await,
            ClientType::Tor(tor_agent) => {
                let url = format!("{}/mint/quote/bolt11", self.mint_url);
                let mut response = tor_agent.post(&url)
                    .send_json(request)
                    .map_err(|e| Error::TorError(format!("Tor request failed: {}", e)))?;
                
                let quote: MintQuoteBolt11Response<String> = serde_json::from_str(&response.body_mut().read_to_string()
                    .map_err(|e| Error::TorError(format!("Failed to read response: {}", e)))?)
                    .map_err(|e| Error::TorError(format!("Failed to parse response: {}", e)))?;
                
                Ok(quote)
            }
        }
    }

    async fn get_mint_quote_status(&self, quote_id: &str) -> Result<MintQuoteBolt11Response<String>, Error> {
        let client = self.get_client().await?;
        match client {
            ClientType::Http(http_client) => http_client.get_mint_quote_status(quote_id).await,
            ClientType::Tor(tor_agent) => {
                let url = format!("{}/mint/quote/bolt11/{}", self.mint_url, quote_id);
                let mut response = tor_agent.get(&url).call()
                    .map_err(|e| Error::TorError(format!("Tor request failed: {}", e)))?;
                
                let quote: MintQuoteBolt11Response<String> = serde_json::from_str(&response.body_mut().read_to_string()
                    .map_err(|e| Error::TorError(format!("Failed to read response: {}", e)))?)
                    .map_err(|e| Error::TorError(format!("Failed to parse response: {}", e)))?;
                
                Ok(quote)
            }
        }
    }

    async fn post_mint(&self, request: MintRequest<String>) -> Result<MintResponse, Error> {
        let client = self.get_client().await?;
        match client {
            ClientType::Http(http_client) => http_client.post_mint(request).await,
            ClientType::Tor(tor_agent) => {
                let url = format!("{}/mint/bolt11", self.mint_url);
                let mut response = tor_agent.post(&url)
                    .send_json(request)
                    .map_err(|e| Error::TorError(format!("Tor request failed: {}", e)))?;
                
                let mint_response: MintResponse = serde_json::from_str(&response.body_mut().read_to_string()
                    .map_err(|e| Error::TorError(format!("Failed to read response: {}", e)))?)
                    .map_err(|e| Error::TorError(format!("Failed to parse response: {}", e)))?;
                
                Ok(mint_response)
            }
        }
    }

    async fn post_melt_quote(&self, request: MeltQuoteBolt11Request) -> Result<MeltQuoteBolt11Response<String>, Error> {
        let client = self.get_client().await?;
        match client {
            ClientType::Http(http_client) => http_client.post_melt_quote(request).await,
            ClientType::Tor(tor_agent) => {
                let url = format!("{}/melt/quote/bolt11", self.mint_url);
                let mut response = tor_agent.post(&url)
                    .send_json(request)
                    .map_err(|e| Error::TorError(format!("Tor request failed: {}", e)))?;
                
                let quote: MeltQuoteBolt11Response<String> = serde_json::from_str(&response.body_mut().read_to_string()
                    .map_err(|e| Error::TorError(format!("Failed to read response: {}", e)))?)
                    .map_err(|e| Error::TorError(format!("Failed to parse response: {}", e)))?;
                
                Ok(quote)
            }
        }
    }

    async fn get_melt_quote_status(&self, quote_id: &str) -> Result<MeltQuoteBolt11Response<String>, Error> {
        let client = self.get_client().await?;
        match client {
            ClientType::Http(http_client) => http_client.get_melt_quote_status(quote_id).await,
            ClientType::Tor(tor_agent) => {
                let url = format!("{}/melt/quote/bolt11/{}", self.mint_url, quote_id);
                let mut response = tor_agent.get(&url).call()
                    .map_err(|e| Error::TorError(format!("Tor request failed: {}", e)))?;
                
                let quote: MeltQuoteBolt11Response<String> = serde_json::from_str(&response.body_mut().read_to_string()
                    .map_err(|e| Error::TorError(format!("Failed to read response: {}", e)))?)
                    .map_err(|e| Error::TorError(format!("Failed to parse response: {}", e)))?;
                
                Ok(quote)
            }
        }
    }

    async fn post_melt(&self, request: MeltRequest<String>) -> Result<MeltQuoteBolt11Response<String>, Error> {
        let client = self.get_client().await?;
        match client {
            ClientType::Http(http_client) => http_client.post_melt(request).await,
            ClientType::Tor(tor_agent) => {
                let url = format!("{}/melt/bolt11", self.mint_url);
                let mut response = tor_agent.post(&url)
                    .send_json(request)
                    .map_err(|e| Error::TorError(format!("Tor request failed: {}", e)))?;
                
                let melt_response: MeltQuoteBolt11Response<String> = serde_json::from_str(&response.body_mut().read_to_string()
                    .map_err(|e| Error::TorError(format!("Failed to read response: {}", e)))?)
                    .map_err(|e| Error::TorError(format!("Failed to parse response: {}", e)))?;
                
                Ok(melt_response)
            }
        }
    }

    async fn post_swap(&self, request: SwapRequest) -> Result<SwapResponse, Error> {
        let client = self.get_client().await?;
        match client {
            ClientType::Http(http_client) => http_client.post_swap(request).await,
            ClientType::Tor(tor_agent) => {
                let url = format!("{}/swap", self.mint_url);
                let mut response = tor_agent.post(&url)
                    .send_json(request)
                    .map_err(|e| Error::TorError(format!("Tor request failed: {}", e)))?;
                
                let swap_response: SwapResponse = serde_json::from_str(&response.body_mut().read_to_string()
                    .map_err(|e| Error::TorError(format!("Failed to read response: {}", e)))?)
                    .map_err(|e| Error::TorError(format!("Failed to parse response: {}", e)))?;
                
                Ok(swap_response)
            }
        }
    }

    async fn get_mint_info(&self) -> Result<MintInfo, Error> {
        let client = self.get_client().await?;
        match client {
            ClientType::Http(http_client) => http_client.get_mint_info().await,
            ClientType::Tor(tor_agent) => {
                // Make request through Tor agent
                let url = format!("{}/info", self.mint_url);
                let mut response = tor_agent.get(&url).call()
                    .map_err(|e| Error::TorError(format!("Tor request failed: {}", e)))?;
                
                let mint_info: MintInfo = serde_json::from_str(&response.body_mut().read_to_string()
                    .map_err(|e| Error::TorError(format!("Failed to read response: {}", e)))?)
                    .map_err(|e| Error::TorError(format!("Failed to parse response: {}", e)))?;
                
                Ok(mint_info)
            }
        }
    }

    async fn post_check_state(&self, request: CheckStateRequest) -> Result<CheckStateResponse, Error> {
        let client = self.get_client().await?;
        match client {
            ClientType::Http(http_client) => http_client.post_check_state(request).await,
            ClientType::Tor(tor_agent) => {
                let url = format!("{}/check", self.mint_url);
                let mut response = tor_agent.post(&url)
                    .send_json(request)
                    .map_err(|e| Error::TorError(format!("Tor request failed: {}", e)))?;
                
                let state_response: CheckStateResponse = serde_json::from_str(&response.body_mut().read_to_string()
                    .map_err(|e| Error::TorError(format!("Failed to read response: {}", e)))?)
                    .map_err(|e| Error::TorError(format!("Failed to parse response: {}", e)))?;
                
                Ok(state_response)
            }
        }
    }

    async fn post_restore(&self, request: RestoreRequest) -> Result<RestoreResponse, Error> {
        let client = self.get_client().await?;
        match client {
            ClientType::Http(http_client) => http_client.post_restore(request).await,
            ClientType::Tor(tor_agent) => {
                let url = format!("{}/restore", self.mint_url);
                let mut response = tor_agent.post(&url)
                    .send_json(request)
                    .map_err(|e| Error::TorError(format!("Tor request failed: {}", e)))?;
                
                let restore_response: RestoreResponse = serde_json::from_str(&response.body_mut().read_to_string()
                    .map_err(|e| Error::TorError(format!("Failed to read response: {}", e)))?)
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