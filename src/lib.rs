pub mod decryption;
pub mod encryption;
pub mod kzg;
pub mod setup;
pub mod utils;
pub mod wrappers;

use ark_poly::univariate::DensePolynomial;
use ark_serialize::CanonicalDeserialize;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsValue;
use ark_bls12_381::Bls12_381;
use ark_ec::pairing::{Pairing};
use serde_wasm_bindgen::{from_value, to_value};
use web_sys::console;

use crate::setup::{AggregateKey, SecretKey};
use crate::encryption::{Ciphertext, encrypt};
use crate::decryption::agg_dec;
use crate::kzg::{UniversalParams, KZG10};
use wrappers::*;

type E = Bls12_381;
type UniPoly381 = DensePolynomial<<E as Pairing>::ScalarField>;

// Logging helper
fn log(s: &str) {
    console::log_1(&JsValue::from_str(s));
}

#[wasm_bindgen]
pub fn setup_wasm(size: usize) -> JsValue {
    log("Initializing RNG...");
    let mut rng = ark_std::test_rng();
    
    let adjusted_size = size + 2; // Ensure sufficient powers
    log(&format!("Setting up KZG10 parameters with size: {}", adjusted_size));
    let params = KZG10::<E, UniPoly381>::setup(adjusted_size, &mut rng).unwrap();
    
    log("KZG10 parameters setup complete.");
    let wrapped_params = UniversalParamsWrapper::from(params);
    
    log("Serializing KZG10 parameters...");
    let serialized_params = to_value(&wrapped_params).unwrap();
    
    log("Serialization complete.");
    serialized_params
}

#[wasm_bindgen]
pub fn generate_keys_wasm(params: JsValue) -> JsValue {
    log("Deserializing KZG10 parameters...");
    let params: UniversalParamsWrapper = from_value(params).unwrap();
    let params: UniversalParams<E> = params.into();

    log("KZG10 parameters deserialized.");
    let mut rng = ark_std::test_rng();
    let num_powers = params.powers_of_g.len();

    log(&format!("Number of powers in KZG10 parameters: {}", num_powers));

    if num_powers < 5 { // Ensure sufficient number of powers
        log("Error: Insufficient number of powers in the setup parameters.");
        panic!("Insufficient number of powers in the setup parameters");
    }

    let mut sk: Vec<SecretKeyWrapper> = Vec::new();
    let mut pk: Vec<PublicKeyWrapper> = Vec::new();

    for i in 0..4 { // Generate exactly 4 keys
        log(&format!("Generating secret key and public key for index: {}", i));
        let sk_i = SecretKey::<E>::new(&mut rng);
        let pk_i = sk_i.get_pk(i, &params, 4);
        sk.push(SecretKeyWrapper::from(sk_i));
        pk.push(PublicKeyWrapper::from(pk_i));
    }

    log("All secret and public keys generated.");
    let agg_key = AggregateKey::<E>::new(pk.iter().map(|p| (*p).clone().into()).collect(), &params);
    let serializable_agg_key: SerializableAggregateKey = agg_key.into();

    log("Aggregated key generated.");
    let result = js_sys::Object::new();
    js_sys::Reflect::set(&result, &JsValue::from_str("sk"), &to_value(&sk).unwrap()).unwrap();
    js_sys::Reflect::set(&result, &JsValue::from_str("agg_key"), &to_value(&serializable_agg_key).unwrap()).unwrap();

    log("Keys and aggregated key serialized.");
    result.into()
}

#[wasm_bindgen]
pub fn encrypt_wasm(agg_key: JsValue, t: usize, params: JsValue) -> JsValue {
    let agg_key: SerializableAggregateKey = from_value(agg_key).unwrap();
    let params: UniversalParamsWrapper = from_value(params).unwrap();
    let agg_key: AggregateKey<E> = agg_key.into();
    let params: UniversalParams<E> = params.into();
    let ct = encrypt::<E>(&agg_key, t, &params);
    to_value(&CiphertextWrapper::from(ct)).unwrap()
}

pub fn convert_partial_decryptions(js_array: JsValue) -> Result<Vec<Vec<u8>>, JsValue> {
    let array = js_sys::Array::from(&js_array);

    let mut result: Vec<Vec<u8>> = Vec::new();

    for i in 0..array.length() {
        let element = array.get(i);
        let data_array = js_sys::Reflect::get(&element, &JsValue::from_str("data"))?;
        let uint8_array = js_sys::Uint8Array::new(&data_array);
        let mut vec = vec![0; uint8_array.length() as usize];
        uint8_array.copy_to(&mut vec[..]);
        result.push(vec);
    }

    Ok(result)
}

#[wasm_bindgen]
pub fn decrypt_wasm(partial_decryptions: JsValue, ct: JsValue, selector: JsValue, agg_key: JsValue, params: JsValue) -> JsValue {
    log("Starting decryption process...");

    log("Deserializing partial decryptions...");
    let partial_decryptions: Vec<Vec<u8>> = match convert_partial_decryptions(partial_decryptions) {
        Ok(value) => value,
        Err(err) => {
            log(&format!("Error deserializing partial_decryptions: {:?}", err));
            panic!("Deserialization error");
        }
    };
    log("Partial decryptions (after conversion): deserialized");

    log("Deserializing ciphertext...");
    let ct: CiphertextWrapper = from_value(ct).unwrap();
    log("Ciphertext deserialized");

    log("Deserializing selector...");
    let selector: Vec<bool> = from_value(selector).unwrap();
    log("Selector deserialized");

    log("Deserializing aggregated key...");
    let agg_key: SerializableAggregateKey = from_value(agg_key).unwrap();
    log("Aggregated key deserialized");

    log("Deserializing universal parameters...");
    let params: UniversalParamsWrapper = from_value(params).unwrap();
    log("Universal parameters deserialized");

    log("Converting partial decryptions to G2 elements...");
    let partial_decryptions: Vec<<E as Pairing>::G2> = partial_decryptions.into_iter()
        .map(|g| {
            <<ark_ec::bls12::Bls12<ark_bls12_381::Config> as ark_ec::pairing::Pairing>::G2 as CanonicalDeserialize>::deserialize_uncompressed(&g[..]).unwrap()
        })
        .collect();
    log("Partial decryptions converted to G2 elements");

    log("Converting ciphertext wrapper to Ciphertext...");
    let ct: Ciphertext<E> = ct.into();
    log("Ciphertext converted");

    log("Converting aggregated key wrapper to AggregateKey...");
    let agg_key: AggregateKey<E> = agg_key.into();
    log("Aggregated key converted");

    log("Converting universal parameters wrapper to UniversalParams...");
    let params: UniversalParams<E> = params.into();
    log("Universal parameters converted");

    log("Performing aggregated decryption...");
    let dec_key = agg_dec(&partial_decryptions, &ct, &selector, &agg_key, &params);
    log("Decryption key computed");

    // Drop the partial_decryptions variable after its last use
    drop(partial_decryptions);

    log("Wrapping decryption key in PairingOutputWrapper...");
    let dec_key_wrapper = PairingOutputWrapper { inner: dec_key };

    log("Converting decryption key wrapper to JsValue...");
    let result = to_value(&dec_key_wrapper).unwrap();
    log("Decryption process completed.");

    result
}
