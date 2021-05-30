use serde::{Deserialize, Serialize};
use serde_json;

use super::{AttestationConveyancePreference, AuthenticationExtensionsClientInputs, AuthenticatorSelectionCriteria, PublicKeyCredentialCreationOptions, PublicKeyCredentialDescriptor, PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity};

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GenerateAssertionOptions {
    rp_id: String,
    rp_name: String,
    user_handle: String,
    user_name: String,
    user_display_name: String,
    challenge: Option<String>,
    timeout: Option<usize>,
    attestation_type: Option<PublicKeyCredentialUserEntity>,
    exclude_credentials: Option<Vec<PublicKeyCredentialDescriptor>>,
    authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    extensions: Option<AuthenticationExtensionsClientInputs>,
    supported_algorithm_ids: Option<Vec<usize>>,
}

pub fn generate_attestation_options(options: GenerateAssertionOptions) -> PublicKeyCredentialCreationOptions {
    PublicKeyCredentialCreationOptions {
        rp: PublicKeyCredentialRpEntity {
            id: options.rp_id,
            name: options.rp_name,
        },
        attestation: options.attestation_type,
        exclude_credentials:
    }
}
