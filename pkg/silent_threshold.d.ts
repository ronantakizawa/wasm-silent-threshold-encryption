/* tslint:disable */
/* eslint-disable */
/**
* @param {number} size
* @returns {any}
*/
export function setup_wasm(size: number): any;
/**
* @param {any} params
* @returns {any}
*/
export function generate_keys_wasm(params: any): any;
/**
* @param {any} agg_key
* @param {number} t
* @param {any} params
* @returns {any}
*/
export function encrypt_wasm(agg_key: any, t: number, params: any): any;
/**
* @param {any} partial_decryptions
* @param {any} ct
* @param {any} selector
* @param {any} agg_key
* @param {any} params
* @returns {any}
*/
export function decrypt_wasm(partial_decryptions: any, ct: any, selector: any, agg_key: any, params: any): any;
/**
*/
export function main(): void;
/**
*/
export class CiphertextWrapper {
  free(): void;
/**
*/
  data: Uint8Array;
}
/**
*/
export class PublicKeyWrapper {
  free(): void;
/**
*/
  data: Uint8Array;
}
/**
*/
export class SecretKeyWrapper {
  free(): void;
/**
* @returns {number}
*/
  to_secret_key(): number;
/**
* @param {any} js_value
* @returns {SecretKeyWrapper}
*/
  static from_js_value(js_value: any): SecretKeyWrapper;
/**
* @returns {any}
*/
  to_js_value(): any;
/**
* @param {any} ct
* @returns {any}
*/
  partial_decryption_js(ct: any): any;
/**
*/
  data: Uint8Array;
}

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
  readonly memory: WebAssembly.Memory;
  readonly secretkeywrapper_to_secret_key: (a: number) => number;
  readonly secretkeywrapper_from_js_value: (a: number) => number;
  readonly secretkeywrapper_to_js_value: (a: number) => number;
  readonly secretkeywrapper_partial_decryption_js: (a: number, b: number) => number;
  readonly __wbg_ciphertextwrapper_free: (a: number) => void;
  readonly ciphertextwrapper_data: (a: number, b: number) => void;
  readonly ciphertextwrapper_set_data: (a: number, b: number, c: number) => void;
  readonly secretkeywrapper_data: (a: number, b: number) => void;
  readonly publickeywrapper_data: (a: number, b: number) => void;
  readonly __wbg_secretkeywrapper_free: (a: number) => void;
  readonly __wbg_publickeywrapper_free: (a: number) => void;
  readonly secretkeywrapper_set_data: (a: number, b: number, c: number) => void;
  readonly publickeywrapper_set_data: (a: number, b: number, c: number) => void;
  readonly setup_wasm: (a: number) => number;
  readonly generate_keys_wasm: (a: number) => number;
  readonly encrypt_wasm: (a: number, b: number, c: number) => number;
  readonly decrypt_wasm: (a: number, b: number, c: number, d: number, e: number) => number;
  readonly main: () => void;
  readonly __wbindgen_malloc: (a: number, b: number) => number;
  readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
  readonly __wbindgen_add_to_stack_pointer: (a: number) => number;
  readonly __wbindgen_free: (a: number, b: number, c: number) => void;
  readonly __wbindgen_exn_store: (a: number) => void;
  readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;
/**
* Instantiates the given `module`, which can either be bytes or
* a precompiled `WebAssembly.Module`.
*
* @param {SyncInitInput} module
*
* @returns {InitOutput}
*/
export function initSync(module: SyncInitInput): InitOutput;

/**
* If `module_or_path` is {RequestInfo} or {URL}, makes a request and
* for everything else, calls `WebAssembly.instantiate` directly.
*
* @param {InitInput | Promise<InitInput>} module_or_path
*
* @returns {Promise<InitOutput>}
*/
export default function __wbg_init (module_or_path?: InitInput | Promise<InitInput>): Promise<InitOutput>;
