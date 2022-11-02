// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use async_trait::async_trait;
use std::sync::Arc;
use sui_types::{error::SuiResult, messages::VerifiedCertificate};
use tokio::time::sleep;
use tracing::{debug, error, info, warn};

use super::ActiveAuthority;
use crate::authority::AuthorityState;
use crate::authority_client::AuthorityAPI;

#[cfg(test)]
pub(crate) mod tests;

#[async_trait]
pub trait PendCertificateForExecution {
    async fn add_pending_certificates(&self, certs: Vec<VerifiedCertificate>) -> SuiResult<()>;
}

#[async_trait]
impl PendCertificateForExecution for &AuthorityState {
    async fn add_pending_certificates(&self, certs: Vec<VerifiedCertificate>) -> SuiResult<()> {
        AuthorityState::add_pending_certificates(self, certs).await
    }
}

/// A no-op PendCertificateForExecution that we use for testing, when
/// we do not care about certificates actually being executed.
pub struct PendCertificateForExecutionNoop;

#[async_trait]
impl PendCertificateForExecution for PendCertificateForExecutionNoop {
    async fn add_pending_certificates(&self, _certs: Vec<VerifiedCertificate>) -> SuiResult<()> {
        Ok(())
    }
}

/// When a notification that a new pending transaction is received we activate
/// processing the transaction in a loop.
pub async fn execution_process<A>(active_authority: Arc<ActiveAuthority<A>>)
where
    A: AuthorityAPI + Send + Sync + 'static + Clone,
{
    info!("Starting execution driver process.");

    // Loop whenever there is a signal that a new transactions is ready to process.
    loop {
        let digest = if let Some(digest) = active_authority.state.next_ready_digest().await {
            digest
        } else {
            // Should not happen. Only possible if the AuthorityState has shut down.
            warn!("Ready digest stream from authority state is broken. Retry in 10s ...");
            sleep(std::time::Duration::from_secs(10)).await;
            continue;
        };
        debug!(?digest, "Pending certificate execution activated.");

        // Process any tx that failed to commit.
        if let Err(err) = active_authority.state.process_tx_recovery_log(None).await {
            tracing::error!("Error processing tx recovery log: {:?}", err);
        }

        let authority = active_authority.clone();
        tokio::task::spawn(async move {
            let cert = match authority.state.database.get_certified_transaction(&digest) {
                Err(e) => {
                    error!(
                        ?digest,
                        "Unexpected error to get certified transaction: {e}"
                    );
                    return;
                }
                Ok(None) => {
                    error!(?digest, "Certified transaction not found!");
                    return;
                }
                Ok(Some(cert)) => cert,
            };

            if let Err(e) = authority.state.handle_certificate(&cert).await {
                error!(?digest, "Failed to execute certified transaction! {e}");
            }

            // Remove the pending digest after successful execution.
            let _ = authority
                .state
                .database
                .remove_pending_digests(vec![digest]);
        });
    }
}
