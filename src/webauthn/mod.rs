use serde::{Deserialize, Serialize};

pub mod attestation;

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PublicKeyCredentialType {
    PublicKey,
}
#[derive(Debug, PartialEq, Serialize, Deserialize, Copy, Clone)]
#[serde(rename_all = "lowercase")]
pub enum ResidentKeyRequirement {
    Discouraged,
    Preferred,
    Required,
}
#[derive(Debug, PartialEq, Serialize, Deserialize, Copy, Clone)]
#[serde(rename_all = "kebab-case")]
pub enum AuthenticatorAttachment {
    CrossPlatform,
    Platform,
}
#[derive(Debug, PartialEq, Serialize, Deserialize, Copy, Clone)]
#[serde(rename_all = "lowercase")]
pub enum UserVerificationRequirement {
    Discouraged,
    Preferred,
    Required,
}
#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthenticatorTransport {
    Ble,
    Internal,
    Nfc,
    Usb,
}
#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AttestationConveyancePreference {
    Direct,
    Enterprise,
    Indirect,
    None,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GenerateAssertionOptions {
    rp_id: String,
    challenge: String,
    timeout: usize,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Copy, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticatorSelectionCriteria {
    #[serde(skip_serializing_if = "Option::is_none")]
    authenticator_attachment: Option<AuthenticatorAttachment>,
    #[serde(skip_serializing_if = "Option::is_none")]
    require_resident_key: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    resident_key: Option<ResidentKeyRequirement>,
    user_verification: Option<UserVerificationRequirement>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyCredentialDescriptor {
    id: String,
    transports: Option<AuthenticatorTransport>,
    #[serde(rename(serialize = "type", deserialize = "credential_type"))]
    credential_type: PublicKeyCredentialType,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticationExtensionsClientInputs {
    appid: Option<String>,
    appid_exculde: Option<String>,
    cred_props: Option<bool>,
    uvm: Option<bool>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyCredentialParameters {
    alg: i32,
    #[serde(rename(serialize = "type", deserialize = "credential_type"))]
    credential_type: PublicKeyCredentialType,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyCredentialRpEntity {
    id: String,
    name: String,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyCredentialUserEntity {
    id: String,
    display_name: Option<String>,
    name: String,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyCredentialCreationOptions {
    rp: PublicKeyCredentialRpEntity,                         // required
    user: PublicKeyCredentialUserEntity,                     // required
    challenge: String,                                       // required
    pub_key_cred_params: Vec<PublicKeyCredentialParameters>, // required
    // Optional
    exclude_credentials: Option<Vec<PublicKeyCredentialDescriptor>>,
    extensions: Option<AuthenticationExtensionsClientInputs>,
    attestation: Option<AttestationConveyancePreference>,
    authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    timeout: Option<usize>,
}
