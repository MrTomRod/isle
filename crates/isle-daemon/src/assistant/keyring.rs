// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 zickrian

//! The login keyring (Secret Service), as the command-line apps that keep their sign-in there see it.

use std::collections::HashMap;
use std::time::Duration;

use zbus::zvariant::OwnedObjectPath;

/// How long the keyring gets to answer: it is on the session bus, with isled.
const TIMEOUT: Duration = Duration::from_secs(1);

/// Whether the keyring holds an item with every one of `attributes` (`("service", "gemini")` and the like).
/// Only whether the item is there is asked; its secret is never read. No keyring, or one that cannot be
/// asked in time, answers false.
pub async fn has_item(attributes: &[(&str, &str)]) -> bool {
    let attributes: HashMap<&str, &str> = attributes.iter().copied().collect();
    let searched = async {
        let connection = zbus::Connection::session().await?;
        connection
            .call_method(
                Some("org.freedesktop.secrets"),
                "/org/freedesktop/secrets",
                Some("org.freedesktop.Secret.Service"),
                "SearchItems",
                &(attributes,),
            )
            .await
    };
    let Ok(Ok(reply)) = tokio::time::timeout(TIMEOUT, searched).await else {
        return false;
    };
    reply
        .body()
        .deserialize::<(Vec<OwnedObjectPath>, Vec<OwnedObjectPath>)>()
        .is_ok_and(|(unlocked, locked)| !unlocked.is_empty() || !locked.is_empty())
}
