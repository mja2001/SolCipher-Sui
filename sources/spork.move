module spork::spork {
    use sui::object::{Self, UID};
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};
    use std::vector;

    // Errors
    const EInvalidKeyLength: u64 = 1;
    const EWrongKey: u64 = 2;

    // Your eternal encryption key — a real Move resource
    struct SporkKey has key, store {
        id: UID,
        secret: vector<u8>, // 32 bytes recommended for real crypto
    }

    // Encrypted blob — gets burned on decrypt for safety
    struct CipherText has key {
        id: UID,
        data: vector<u8>,
    }

    // Create a new key (32-byte random recommended in prod)
    public entry fun mint_key(secret_hex: vector<u8>, ctx: &mut TxContext) {
        assert!(vector::length(&secret_hex) == 32, EInvalidKeyLength);
        let key = SporkKey {
            id: object::new(ctx),
            secret: secret_hex,
        };
        transfer::transfer(key, tx_context::sender(ctx));
    }

    // Encrypt with repeating-key XOR (fast demo — replace with AES later)
    public entry fun encrypt(key: &SporkKey, plaintext: vector<u8>, ctx: &mut TxContext) {
        let ciphertext = xor_encrypt(&key.secret, &plaintext);
        let ct = CipherText {
            id: object::new(ctx),
            data: ciphertext,
        };
        transfer::public_transfer(ct, tx_context::sender(ctx));
    }

    // Decrypt + burn ciphertext
    public entry fun decrypt(key: &SporkKey, ct: CipherText): vector<u8> {
        let plaintext = xor_encrypt(&key.secret, &ct.data);
        let CipherText { id, data: _ } = ct;
        object::delete(id);
        plaintext
    }

    // Internal XOR (repeating key)
    fun xor_encrypt(key: &vector<u8>, data: &vector<u8>): vector<u8> {
        let result = vector::empty<u8>();
        let key_len = vector::length(key);
        let mut i = 0;
        while (i < vector::length(data)) {
            let k = *vector::borrow(key, i % key_len);
            let b = *vector::borrow(data, i);
            vector::push_back(&mut result, k ^ b);
            i = i + 1;
        };
        result
    }
}
