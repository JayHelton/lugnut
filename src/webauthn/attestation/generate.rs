use base64;
use serde::{Deserialize, Serialize};

use super::{
    AttestationConveyancePreference, AuthenticationExtensionsClientInputs,
    AuthenticatorSelectionCriteria, PublicKeyCredentialCreationOptions,
    PublicKeyCredentialDescriptor, PublicKeyCredentialParameters, PublicKeyCredentialRpEntity,
    PublicKeyCredentialType, PublicKeyCredentialUserEntity, ResidentKeyRequirement,
    UserVerificationRequirement,
};

static DEFAULT_COSE_ALG_ID: [i32; 10] = [
    // TODO clean up these comments being one above the correct alg
    // ECDSA w/ SHA-256
    -7,   // EdDSA
    -8,   // ECDSA w/ SHA-512
    -36,  // RSASSA-PSS w/ SHA-256
    -37,  // RSASSA-PSS w/ SHA-384
    -38,  // RSASSA-PSS w/ SHA-512
    -39,  // RSASSA-PKCS1-v1_5 w/ SHA-256
    -257, // RSASSA-PKCS1-v1_5 w/ SHA-384
    -258, // RSASSA-PKCS1-v1_5 w/ SHA-512
    -259, // RSASSA-PKCS1-v1_5 w/ SHA-1 (Deprecated; here for legacy support)
    -65535,
];

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AssertionOptions {
    rp_id: String,
    rp_name: String,
    user_id: String,
    user_name: String,
    user_display_name: Option<String>,
    challenge: String,                                         // will have default
    timeout: Option<usize>,                                    // will have default
    attestation_type: Option<AttestationConveyancePreference>, // will have default
    exclude_credentials: Option<Vec<PublicKeyCredentialDescriptor>>, // will have default
    authenticator_selection: Option<AuthenticatorSelectionCriteria>, // will have default
    extensions: Option<AuthenticationExtensionsClientInputs>,
    supported_algorithm_ids: Vec<i32>, // will have default
}

impl AssertionOptions {
    pub fn new(
        rp_id: String,
        rp_name: String,
        challenge: String,
        user_id: String,
        user_name: String,
    ) -> Self {
        AssertionOptions {
            rp_id,
            rp_name,
            user_id,
            user_name,
            challenge,
            timeout: Some(60000),
            attestation_type: Some(AttestationConveyancePreference::None),
            exclude_credentials: Some(Vec::new()),
            authenticator_selection: Some(AuthenticatorSelectionCriteria {
                require_resident_key: Some(false),
                user_verification: Some(UserVerificationRequirement::Preferred),
                resident_key: None,
                authenticator_attachment: None,
            }),
            extensions: None,
            user_display_name: None,
            supported_algorithm_ids: DEFAULT_COSE_ALG_ID.clone().to_vec(),
        }
    }

    pub fn with_supported_algorithm_ids(&mut self, supported_algorithm_ids: Vec<i32>) -> &mut Self {
        self.supported_algorithm_ids = supported_algorithm_ids;
        self
    }
    pub fn with_user_display_name(&mut self, user_display_name: String) -> &mut Self {
        self.user_display_name = Some(user_display_name);
        self
    }

    pub fn with_extensions(
        &mut self,
        extensions: AuthenticationExtensionsClientInputs,
    ) -> &mut Self {
        self.extensions = Some(extensions);
        self
    }

    pub fn with_exclude_credentials(
        &mut self,
        exclude_credentials: Vec<PublicKeyCredentialDescriptor>,
    ) -> &mut Self {
        self.exclude_credentials = Some(exclude_credentials);
        self
    }

    pub fn with_timeout(&mut self, timeout: usize) -> &mut Self {
        self.timeout = Some(timeout);
        self
    }

    pub fn with_attestation_type(
        &mut self,
        attestation_type: AttestationConveyancePreference,
    ) -> &mut Self {
        self.attestation_type = Some(attestation_type);
        self
    }
}

pub fn generate_attestation_options(
    options: AssertionOptions,
) -> PublicKeyCredentialCreationOptions {
    let mut exclude_credentials = None;
    let mut authenticator_selection = None;
    //
    //  "Relying Parties SHOULD set [requireResidentKey] to true if, and only if, residentKey is set
    //  to "required""
    //
    //  See https://www.w3.org/TR/webauthn-2/#dom-authenticatorselectioncriteria-requireresidentkey
    //
    if let Some(mut auth_selection) = options.authenticator_selection {
        if let Some(ResidentKeyRequirement::Required) = auth_selection.resident_key {
            auth_selection.require_resident_key = Some(true);
            authenticator_selection = Some(auth_selection);
        } else {
            authenticator_selection = options.authenticator_selection;
        }
    }

    // Maybe this doesnt need to me an Option type since we will always map,
    // but keep as such since the spec denotes it as optional
    if let Some(creds) = options.exclude_credentials {
        exclude_credentials = Some(
            creds
                .into_iter()
                .map(|mut c| {
                    c.id = base64::encode(c.id);
                    c
                })
                .collect(),
        )
    }

    PublicKeyCredentialCreationOptions {
        rp: PublicKeyCredentialRpEntity {
            name: options.rp_name,
            id: options.rp_id,
        },
        user: PublicKeyCredentialUserEntity {
            id: options.user_id,
            display_name: options.user_display_name,
            name: options.user_name,
        },
        challenge: base64::encode(options.challenge),
        pub_key_cred_params: options
            .supported_algorithm_ids
            .into_iter()
            .map(|alg| PublicKeyCredentialParameters {
                alg,
                credential_type: PublicKeyCredentialType::PublicKey,
            })
            .collect(),
        exclude_credentials,
        extensions: options.extensions,
        attestation: options.attestation_type,
        authenticator_selection: authenticator_selection,
        timeout: options.timeout,
    }
}

#[cfg(test)]
mod test_generate_attestation_options {

    #[test]
    fn test_default_option_generation() {}

    #[test]
    fn test_extenstions() {}

    #[test]
    fn test_attestation() {}

    #[test]
    fn test_authenticator_selection() {}

    #[test]
    fn test_timeout() {}
}
