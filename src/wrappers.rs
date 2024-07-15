use wasm_bindgen::prelude::*;
use ark_ec::pairing::{Pairing, PairingOutput};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_wasm_bindgen::{from_value, to_value};
use std::fmt::{self};
use std::marker::PhantomData;

use crate::setup::{AggregateKey, SecretKey, PublicKey};
use crate::encryption::Ciphertext;
use crate::kzg::UniversalParams;

type E = ark_bls12_381::Bls12_381;

// Wrapper for PublicKey
#[wasm_bindgen]
#[derive(Serialize, Deserialize, Clone)]
pub struct PublicKeyWrapper {
    data: Vec<u8>,
}

impl From<PublicKey<E>> for PublicKeyWrapper {
    fn from(pk: PublicKey<E>) -> Self {
        let mut data = Vec::new();
        pk.serialize_uncompressed(&mut data).unwrap();
        Self { data }
    }
}

impl From<PublicKeyWrapper> for PublicKey<E> {
    fn from(val: PublicKeyWrapper) -> Self {
        PublicKey::deserialize_uncompressed(&val.data[..]).unwrap()
    }
}

#[wasm_bindgen]
impl PublicKeyWrapper {
    #[wasm_bindgen(getter)]
    pub fn data(&self) -> Box<[u8]> {
        self.data.clone().into_boxed_slice()
    }

    #[wasm_bindgen(setter)]
    pub fn set_data(&mut self, data: Box<[u8]>) {
        self.data = data.into_vec();
    }
}

// Wrapper for SecretKey
#[wasm_bindgen]
#[derive(Serialize, Deserialize, Clone)]
pub struct SecretKeyWrapper {
    data: Vec<u8>,
}

impl From<SecretKey<E>> for SecretKeyWrapper {
    fn from(sk: SecretKey<E>) -> Self {
        let mut data = Vec::new();
        sk.serialize_uncompressed(&mut data).unwrap();
        Self { data }
    }
}

#[wasm_bindgen]
impl SecretKeyWrapper {
    #[wasm_bindgen(getter)]
    pub fn data(&self) -> Box<[u8]> {
        self.data.clone().into_boxed_slice()
    }

    #[wasm_bindgen(setter)]
    pub fn set_data(&mut self, data: Box<[u8]>) {
        self.data = data.into_vec();
    }

    #[wasm_bindgen]
    pub fn to_secret_key(&self) -> SecretKey<E> {
        SecretKey::deserialize_uncompressed(&self.data[..]).unwrap()
    }

    #[wasm_bindgen]
    pub fn from_js_value(js_value: JsValue) -> SecretKeyWrapper {
        from_value(js_value).unwrap()
    }

    pub fn to_js_value(&self) -> JsValue {
        to_value(&self).unwrap()
    }

    pub fn partial_decryption_js(&self, ct: JsValue) -> JsValue {
        let sk = self.to_secret_key();
        let ct: CiphertextWrapper = from_value(ct).unwrap();
        let ct = ct.to_ciphertext();
        let result = sk.partial_decryption(&ct);
        to_value(&ProjectiveG2Wrapper::from_g2::<E>(result)).unwrap()
    }
}

// Wrapper for UniversalParams
#[derive(Serialize, Deserialize, Clone)]
pub struct UniversalParamsWrapper {
    data: Vec<u8>,
}

impl From<UniversalParams<E>> for UniversalParamsWrapper {
    fn from(params: UniversalParams<E>) -> Self {
        let mut data = Vec::new();
        params.serialize_uncompressed(&mut data).unwrap();
        Self { data }
    }
}

impl From<UniversalParamsWrapper> for UniversalParams<E> {
    fn from(val: UniversalParamsWrapper) -> Self {
        UniversalParams::deserialize_uncompressed(&val.data[..]).unwrap()
    }
}

impl UniversalParamsWrapper {
    pub fn data(&self) -> Box<[u8]> {
        self.data.clone().into_boxed_slice()
    }

    pub fn set_data(&mut self, data: Box<[u8]>) {
        self.data = data.into_vec();
    }
}

// Wrapper for Ciphertext
#[wasm_bindgen]
#[derive(Serialize, Deserialize, Clone)]
pub struct CiphertextWrapper {
    data: Vec<u8>,
}

impl From<Ciphertext<E>> for CiphertextWrapper {
    fn from(ct: Ciphertext<E>) -> Self {
        let mut data = Vec::new();
        ct.serialize_uncompressed(&mut data).unwrap();
        Self { data }
    }
}

impl CiphertextWrapper {
    pub fn to_ciphertext(&self) -> Ciphertext<E> {
        Ciphertext::deserialize_uncompressed(&self.data[..]).unwrap()
    }
}

impl From<CiphertextWrapper> for Ciphertext<E> {
    fn from(wrapper: CiphertextWrapper) -> Self {
        wrapper.to_ciphertext()
    }
}

#[wasm_bindgen]
impl CiphertextWrapper {
    #[wasm_bindgen(getter)]
    pub fn data(&self) -> Box<[u8]> {
        self.data.clone().into_boxed_slice()
    }

    #[wasm_bindgen(setter)]
    pub fn set_data(&mut self, data: Box<[u8]>) {
        self.data = data.into_vec();
    }
}

// Wrapper for PairingOutput
#[derive(Serialize, Deserialize, Clone)]
pub struct PairingOutputWrapper<PE: Pairing> {
    #[serde(serialize_with = "serialize_pairing_output", deserialize_with = "deserialize_pairing_output")]
    pub inner: PairingOutput<PE>,
}

// Custom serialization for PairingOutput
fn serialize_pairing_output<S, PE>(value: &PairingOutput<PE>, serializer: S) -> Result<S::Ok, S::Error>
where
    PE: Pairing,
    S: Serializer,
{
    let mut bytes = Vec::new();
    value.serialize_uncompressed(&mut bytes).map_err(serde::ser::Error::custom)?;
    serializer.serialize_bytes(&bytes)
}

fn deserialize_pairing_output<'de, PE, D>(deserializer: D) -> Result<PairingOutput<PE>, D::Error>
where
    PE: Pairing,
    D: Deserializer<'de>,
{
    struct PairingOutputVisitor<PE: Pairing>(PhantomData<PE>);

    impl<'de, PE: Pairing> Visitor<'de> for PairingOutputVisitor<PE> {
        type Value = PairingOutput<PE>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a valid byte array representing PairingOutput")
        }

        fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            PairingOutput::deserialize_uncompressed(v).map_err(E::custom)
        }
    }

    deserializer.deserialize_bytes(PairingOutputVisitor(PhantomData))
}

// SerializableAggregateKey using wrapper types
#[derive(Serialize, Deserialize, Clone)]
pub struct SerializableAggregateKey {
    pub pk: Vec<PublicKeyWrapper>,
    pub agg_sk_li_by_z: Vec<Vec<u8>>, // Serialize G1Projective manually
    pub ask: Vec<u8>, // Serialize G1Projective manually
    pub z_g2: Vec<u8>, // Serialize G2Projective manually
    pub h_minus1: Vec<u8>, // Serialize G2Projective manually
    #[serde(serialize_with = "serialize_pairing_output", deserialize_with = "deserialize_pairing_output")]
    pub e_gh: PairingOutput<E>, // Serialize PairingOutput manually
}

impl From<AggregateKey<E>> for SerializableAggregateKey {
    fn from(key: AggregateKey<E>) -> Self {
        Self {
            pk: key.pk.into_iter().map(PublicKeyWrapper::from).collect(),
            agg_sk_li_by_z: key.agg_sk_li_by_z.into_iter().map(|g| {
                let mut data = Vec::new();
                g.serialize_uncompressed(&mut data).unwrap();
                data
            }).collect(),
            ask: {
                let mut data = Vec::new();
                key.ask.serialize_uncompressed(&mut data).unwrap();
                data
            },
            z_g2: {
                let mut data = Vec::new();
                key.z_g2.serialize_uncompressed(&mut data).unwrap();
                data
            },
            h_minus1: {
                let mut data = Vec::new();
                key.h_minus1.serialize_uncompressed(&mut data).unwrap();
                data
            },
            e_gh: key.e_gh,
        }
    }
}

impl From<SerializableAggregateKey> for AggregateKey<E> {
    fn from(val: SerializableAggregateKey) -> Self {
        AggregateKey {
            pk: val.pk.into_iter().map(|p| p.into()).collect(),
            agg_sk_li_by_z: val.agg_sk_li_by_z.into_iter().map(|g| {
                <<ark_ec::bls12::Bls12<ark_bls12_381::Config> as ark_ec::pairing::Pairing>::G1 as CanonicalDeserialize>::deserialize_uncompressed(&g[..]).unwrap()
            }).collect(),
            ask: <<ark_ec::bls12::Bls12<ark_bls12_381::Config> as ark_ec::pairing::Pairing>::G1 as CanonicalDeserialize>::deserialize_uncompressed(&val.ask[..]).unwrap(),
            z_g2: <<ark_ec::bls12::Bls12<ark_bls12_381::Config> as ark_ec::pairing::Pairing>::G2 as CanonicalDeserialize>::deserialize_uncompressed(&val.z_g2[..]).unwrap(),
            h_minus1: <<ark_ec::bls12::Bls12<ark_bls12_381::Config> as ark_ec::pairing::Pairing>::G2 as CanonicalDeserialize>::deserialize_uncompressed(&val.h_minus1[..]).unwrap(),
            e_gh: val.e_gh,
        }
    }
}

// Wrapper for ProjectiveG2

#[derive(Serialize, Deserialize, Clone)]
pub struct ProjectiveG2Wrapper {
    pub data: Vec<u8>,
}

impl ProjectiveG2Wrapper {
    pub fn from_g2<E: Pairing>(point: E::G2) -> Self {
        let mut data = Vec::new();
        point.serialize_uncompressed(&mut data).unwrap();
        Self { data }
    }
}


impl ProjectiveG2Wrapper {
    pub fn data(&self) -> Box<[u8]> {
        self.data.clone().into_boxed_slice()
    }

    pub fn set_data(&mut self, data: Box<[u8]>) {
        self.data = data.into_vec();
    }

    pub fn new(data: Vec<u8>) -> ProjectiveG2Wrapper {
        ProjectiveG2Wrapper { data }
    }

    pub fn to_g2_js(&self) -> JsValue {
        to_value(&self).unwrap()
    }

    pub fn from_g2_js(js_value: JsValue) -> ProjectiveG2Wrapper {
        from_value(js_value).unwrap()
    }
}
