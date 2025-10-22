#[cfg(feature = "auth")]
use std::collections::HashMap;
use std::sync::Arc;

use bitcoin::bip32::Xpriv;
use bitcoin::Network;
use cdk_common::database;
#[cfg(feature = "auth")]
use cdk_common::AuthToken;
#[cfg(feature = "auth")]
use tokio::sync::RwLock;

use crate::cdk_database::WalletDatabase;
use crate::error::Error;
use crate::mint_url::MintUrl;
use crate::nuts::CurrencyUnit;
#[cfg(feature = "auth")]
use crate::wallet::auth::AuthWallet;
use crate::wallet::{MintConnector, SubscriptionManager, Wallet};
#[cfg(not(feature = "tor"))]
use crate::wallet::HttpClient;
#[cfg(feature = "tor")]
use crate::wallet::mint_connector::HttpClientTor;

/// Builder for creating a new [`Wallet`]
#[derive(Debug)]
pub struct WalletBuilder {
    mint_url: Option<MintUrl>,
    unit: Option<CurrencyUnit>,
    localstore: Option<Arc<dyn WalletDatabase<Err = database::Error> + Send + Sync>>,
    target_proof_count: Option<usize>,
    #[cfg(feature = "auth")]
    auth_wallet: Option<AuthWallet>,
    seed: Option<Vec<u8>>,
    client: Option<Arc<dyn MintConnector + Send + Sync>>,
}

impl Default for WalletBuilder {
    fn default() -> Self {
        Self {
            mint_url: None,
            unit: None,
            localstore: None,
            target_proof_count: Some(3),
            #[cfg(feature = "auth")]
            auth_wallet: None,
            seed: None,
            client: None,
        }
    }
}

impl WalletBuilder {
    /// Create a new WalletBuilder
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the mint URL
    pub fn mint_url(mut self, mint_url: MintUrl) -> Self {
        self.mint_url = Some(mint_url);
        self
    }

    /// Set the currency unit
    pub fn unit(mut self, unit: CurrencyUnit) -> Self {
        self.unit = Some(unit);
        self
    }

    /// Set the local storage backend
    pub fn localstore(
        mut self,
        localstore: Arc<dyn WalletDatabase<Err = database::Error> + Send + Sync>,
    ) -> Self {
        self.localstore = Some(localstore);
        self
    }

    /// Set the target proof count
    pub fn target_proof_count(mut self, count: usize) -> Self {
        self.target_proof_count = Some(count);
        self
    }

    /// Set the auth wallet
    #[cfg(feature = "auth")]
    pub fn auth_wallet(mut self, auth_wallet: AuthWallet) -> Self {
        self.auth_wallet = Some(auth_wallet);
        self
    }

    /// Set the seed bytes
    pub fn seed(mut self, seed: &[u8]) -> Self {
        self.seed = Some(seed.to_vec());
        self
    }

    /// Set a custom client connector
    pub fn client<C: MintConnector + 'static + Send + Sync>(mut self, client: C) -> Self {
        self.client = Some(Arc::new(client));
        self
    }

    /// Set auth CAT (Clear Auth Token)
    #[cfg(feature = "auth")]
    pub fn set_auth_cat(mut self, cat: String) -> Result<Self, Error> {
        self.auth_wallet = Some(AuthWallet::new(
            self.mint_url.clone().ok_or(Error::Custom("Mint URL required".to_string()))?,
            Some(AuthToken::ClearAuth(cat)),
            self.localstore.clone().ok_or(Error::Custom("Localstore required".to_string()))?,
            HashMap::new(),
            None,
        )?);
        Ok(self)
    }

    /// Build the wallet
    pub fn build(self) -> Result<Wallet, Error> {
        let mint_url = self
            .mint_url
            .ok_or(Error::Custom("Mint url required".to_string()))?;
        let unit = self
            .unit
            .ok_or(Error::Custom("Unit required".to_string()))?;
        let localstore = self
            .localstore
            .ok_or(Error::Custom("Localstore required".to_string()))?;
        let seed = self
            .seed
            .as_ref()
            .ok_or(Error::Custom("Seed required".to_string()))?;

        let xpriv = Xpriv::new_master(Network::Bitcoin, seed)?;

        let client = match self.client {
            Some(client) => client,
            None => {
                let url_str = mint_url.to_string();
                #[allow(unused_variables)]
                let is_onion = url_str.contains(".onion");
                
                tracing::info!("WalletBuilder: mint_url={}, is_onion={}", url_str, is_onion);
                
                // Feature combination: tor + auth
                // Always use HttpClientTor to support dynamic Tor policy changes
                #[cfg(all(feature = "tor", feature = "auth"))]
                {
                    tracing::info!("WalletBuilder: Creating HttpClientTor (with auth) for {} - supports dynamic Tor policy", url_str);
                    Arc::new(HttpClientTor::new(mint_url.clone(), self.auth_wallet.clone())?)
                        as Arc<dyn MintConnector + Send + Sync>
                }
                
                // Feature combination: tor + no auth
                // Always use HttpClientTor to support dynamic Tor policy changes
                #[cfg(all(feature = "tor", not(feature = "auth")))]
                {
                    tracing::info!("WalletBuilder: Creating HttpClientTor (no auth) for {} - supports dynamic Tor policy", url_str);
                    Arc::new(HttpClientTor::new(mint_url.clone())?)
                        as Arc<dyn MintConnector + Send + Sync>
                }
                
                // Feature combination: no tor + auth
                #[cfg(all(not(feature = "tor"), feature = "auth"))]
                {
                    tracing::info!("WalletBuilder: Using no-tor+auth branch");
                    // This will fail for .onion addresses with a clear error message
                    Arc::new(HttpClient::new(mint_url.clone(), self.auth_wallet.clone())?)
                        as Arc<dyn MintConnector + Send + Sync>
                }
                
                // Feature combination: no tor + no auth
                #[cfg(all(not(feature = "tor"), not(feature = "auth")))]
                {
                    tracing::info!("WalletBuilder: Using no-tor+no-auth branch");
                    // This will fail for .onion addresses with a clear error message
                    Arc::new(HttpClient::new(mint_url.clone())?)
                        as Arc<dyn MintConnector + Send + Sync>
                }
            }
        };

        Ok(Wallet {
            mint_url,
            unit,
            localstore,
            target_proof_count: self.target_proof_count.unwrap_or(3),
            #[cfg(feature = "auth")]
            auth_wallet: Arc::new(RwLock::new(self.auth_wallet)),
            xpriv,
            client: client.clone(),
            subscription: SubscriptionManager::new(client),
        })
    }
}
