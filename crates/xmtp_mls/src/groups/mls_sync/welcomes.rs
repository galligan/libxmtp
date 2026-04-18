use super::*;

impl<Context> MlsGroup<Context>
where
    Context: XmtpSharedContext,
{
    /**
     * Sends welcome messages to the installations specified in the action
     *
     * Internally, this breaks the request into chunks to avoid exceeding the GRPC max message size limits
     */
    #[cfg_attr(any(test, feature = "test-utils"), tracing::instrument(level = "info", skip_all, fields(who = %self.context.inbox_id())))]
    #[cfg_attr(not(any(test, feature = "test-utils")), tracing::instrument(skip_all))]
    pub(in crate::groups) async fn send_welcomes(
        &self,
        action: SendWelcomesAction,
        message_cursor: Option<i64>,
    ) -> Result<(), GroupError> {
        let added_by_inbox_is_pending_remove = self
            .context
            .db()
            .get_user_pending_remove_status(&self.group_id, self.context.inbox_id())?;
        // Only encode welcome metadata once
        let welcome_metadata = WelcomeMetadata {
            message_cursor: message_cursor.unwrap_or(0) as u64,
            added_by_inbox_is_pending_remove,
        };
        let welcome_metadata_bytes = welcome_metadata.encode_to_vec();

        let wp_capable = action
            .installations
            .iter()
            .filter(|installation| {
                installation
                    .welcome_pointee_encryption_aead_types
                    .compatible()
            })
            .count();

        let (welcome_pointer_bytes, welcome_pointee) = if wp_capable
            > xmtp_configuration::INSTALLATION_THRESHOLD_FOR_WELCOME_POINTER_SENDING
        {
            let destination = xmtp_common::rand_array::<32>();
            tracing::debug!(
                wp_capable,
                destination = %hex::encode(destination),
                "Using welcome pointers"
            );
            let symmetric_key = Zeroizing::new(xmtp_common::rand_array::<32>());
            let data_nonce = Zeroizing::new(xmtp_common::rand_array::<12>());
            let mut welcome_metadata_nonce = Zeroizing::new(xmtp_common::rand_array::<12>());
            // ensure that the welcome pointer nonce is different from the data nonce
            while welcome_metadata_nonce == data_nonce {
                welcome_metadata_nonce = Zeroizing::new(xmtp_common::rand_array::<12>());
            }

            let aead_type = crate::groups::mls_ext::WelcomePointersExtension::preferred_type();
            let data = crate::groups::mls_ext::wrap_welcome_symmetric(
                &action.welcome_message,
                aead_type,
                symmetric_key.as_ref(),
                data_nonce.as_ref(),
            )?;
            let welcome_metadata = crate::groups::mls_ext::wrap_welcome_symmetric(
                &welcome_metadata_bytes,
                aead_type,
                symmetric_key.as_ref(),
                welcome_metadata_nonce.as_ref(),
            )?;

            let welcome_pointee = WelcomeMessageInput {
                version: Some(WelcomeMessageInputVersion::V1(WelcomeMessageInputV1 {
                    installation_key: destination.into(),
                    data,
                    hpke_public_key: vec![],
                    wrapper_algorithm: xmtp_proto::xmtp::mls::message_contents::WelcomeWrapperAlgorithm::SymmetricKey.into(),
                    welcome_metadata,
                })),
            };
            let welcome_pointer_bytes = Zeroizing::new(
                WelcomePointerProto {
                    version: Some(
                        xmtp_proto::xmtp::mls::message_contents::welcome_pointer::Version::WelcomeV1Pointer(
                            xmtp_proto::xmtp::mls::message_contents::welcome_pointer::WelcomeV1Pointer {
                                destination: destination.into(),
                                aead_type: xmtp_proto::xmtp::mls::message_contents::WelcomePointeeEncryptionAeadType::Chacha20Poly1305.into(),
                                encryption_key: symmetric_key.as_ref().to_vec(),
                                data_nonce: data_nonce.as_ref().to_vec(),
                                welcome_metadata_nonce: welcome_metadata_nonce.as_ref().to_vec(),
                            },
                        ),
                    ),
                }
                .encode_to_vec(),
            );

            (Some(welcome_pointer_bytes), Some(welcome_pointee))
        } else {
            (None, None)
        };

        let total_installations = action.installations.len();

        let welcomes_iter = action.installations.into_iter().map(
            |installation| -> Result<WelcomeMessageInput, WrapWelcomeError> {
                // Unconditionally use the wrapper algorithm for the welcome pointer because it will always be post quantum compatible.
                let algorithm = installation.welcome_wrapper_algorithm;
                let wp_cap = installation.welcome_pointee_encryption_aead_types;
                if let Some(welcome_pointer) = &welcome_pointer_bytes
                    && wp_cap.compatible()
                {
                    Ok(WelcomeMessageInput {
                        version: Some(WelcomeMessageInputVersion::WelcomePointer(
                            WelcomePointerInput {
                                installation_key: installation.installation_key,
                                welcome_pointer: wrap_welcome(
                                    welcome_pointer.as_ref(),
                                    &[],
                                    &installation.hpke_public_key,
                                    algorithm,
                                )?
                                .0,
                                hpke_public_key: installation.hpke_public_key,
                                wrapper_algorithm: algorithm.into(),
                            },
                        )),
                    })
                } else {
                    let installation_key = installation.installation_key;

                    let (data, welcome_metadata) = wrap_welcome(
                        &action.welcome_message,
                        &welcome_metadata_bytes,
                        &installation.hpke_public_key,
                        algorithm,
                    )?;
                    Ok(WelcomeMessageInput {
                        version: Some(WelcomeMessageInputVersion::V1(WelcomeMessageInputV1 {
                            installation_key,
                            data,
                            hpke_public_key: installation.hpke_public_key,
                            wrapper_algorithm: algorithm.into(),
                            welcome_metadata,
                        })),
                    })
                }
            },
        );

        let welcomes = welcome_pointee
            .into_iter()
            .map(Ok)
            .chain(welcomes_iter)
            .collect::<Result<Vec<WelcomeMessageInput>, WrapWelcomeError>>()?;

        assert_eq!(
            welcomes.len(),
            total_installations + usize::from(welcome_pointer_bytes.is_some())
        );

        let welcome = welcomes.first().ok_or(GroupError::NoWelcomesToSend)?;

        // Compute the estimated bytes for one welcome message.
        let welcome_calculated_payload_size = welcome
            .version
            .as_ref()
            .map(|w| match w {
                WelcomeMessageInputVersion::V1(w) => {
                    let size = w.installation_key.len()
                        + w.data.len()
                        + w.hpke_public_key.len()
                        + w.welcome_metadata.len();
                    tracing::debug!("total welcome message proto bytes={size}");
                    size
                }
                WelcomeMessageInputVersion::WelcomePointer(welcome_pointer) => {
                    let size = welcome_pointer.installation_key.len()
                        + welcome_pointer.welcome_pointer.len()
                        + welcome_pointer.hpke_public_key.len();
                    tracing::debug!("total welcome pointer proto bytes={size}");
                    size
                }
            })
            // Fallback if the version is missing
            .unwrap_or(GRPC_PAYLOAD_LIMIT / MAX_GROUP_SIZE);

        // Ensure the denominator is at least 1 to avoid div-by-zero.
        let per_welcome = welcome_calculated_payload_size.max(1);

        // Compute chunk_size and ensure it's at least 1 so chunks(n) won't panic.
        let chunk_size = (GRPC_PAYLOAD_LIMIT / per_welcome).clamp(1, 50);

        tracing::debug!("welcome chunk_size={chunk_size}");
        let api = self.context.api();
        let mut futures = vec![];
        for welcomes in welcomes.chunks(chunk_size) {
            futures.push(api.send_welcome_messages(welcomes));
        }
        try_join_all(futures).await?;
        Ok(())
    }

    /// Provides hmac keys for a range of epochs around current epoch
    /// `group.hmac_keys(-1..=1)`` will provide 3 keys consisting of last epoch, current epoch, and next epoch
    /// `group.hmac_keys(0..=0) will provide 1 key, consisting of only the current epoch
    #[tracing::instrument(level = "trace", skip_all)]
    pub fn hmac_keys(
        &self,
        epoch_delta_range: RangeInclusive<i64>,
    ) -> Result<Vec<HmacKey>, StorageError> {
        let conn = self.context.db();

        let preferences = StoredUserPreferences::load(&conn)?;
        let mut ikm = match preferences.hmac_key {
            Some(ikm) => ikm,
            None => {
                let key = HmacKey::random_key();
                StoredUserPreferences::store_hmac_key(&conn, &key, None)?;
                key
            }
        };
        ikm.extend(&self.group_id);
        let hkdf = Hkdf::<Sha256>::new(Some(HMAC_SALT), &ikm);

        let mut result = vec![];
        let current_epoch = hmac_epoch();
        for delta in epoch_delta_range {
            let epoch = current_epoch + delta;

            let mut info = self.group_id.clone();
            info.extend(&epoch.to_le_bytes());

            let mut key = [0; 42];
            hkdf.expand(&info, &mut key).expect("Length is correct");

            result.push(HmacKey { key, epoch });
        }

        Ok(result)
    }

    #[tracing::instrument(level = "trace", skip_all)]
    pub(in crate::groups) fn prepare_group_messages(
        &self,
        payloads: Vec<(&[u8], bool)>,
    ) -> Result<Vec<GroupMessageInput>, GroupError> {
        let hmac_key = self
            .hmac_keys(0..=0)?
            .pop()
            .expect("Range of count 1 was provided.");
        let sender_hmac =
            Hmac::<Sha256>::new_from_slice(&hmac_key.key).expect("HMAC can take key of any size");

        let mut result = vec![];
        for (payload, should_push) in payloads {
            let mut sender_hmac = sender_hmac.clone();
            sender_hmac.update(payload);
            let sender_hmac = sender_hmac.finalize();

            result.push(GroupMessageInput {
                version: Some(GroupMessageInputVersion::V1(GroupMessageInputV1 {
                    data: payload.to_vec(),
                    sender_hmac: sender_hmac.into_bytes().to_vec(),
                    should_push,
                })),
            });
        }

        Ok(result)
    }
}
