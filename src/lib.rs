use chacha20::cipher::{KeyIvInit, StreamCipher};

// X25519 key sizes
pub const SMP25519_PRIVATE_KEY_SIZE: usize = 32;
pub const SMP25519_PUBLIC_KEY_SIZE: usize = 32;

// SMP25519 Handshakes
pub const SMP25519_HANDSHAKE_REQUEST: [u8; 2] = [0xff, 0x13];
pub const SMP25519_HANDSHAKE_REQUEST_SIZE: usize = SMP25519_HANDSHAKE_REQUEST.len();
pub const SMP25519_HANDSHAKE_REQUEST_MESSAGE_SIZE: usize = SMP25519_HANDSHAKE_REQUEST_SIZE + SMP25519_PUBLIC_KEY_SIZE;

// CHACHA20 sizes
pub const SMP25519_CHACHA20_KEY_SIZE: usize = 32;
pub const SMP25519_CHACHA20_NONCE_SIZE: usize = 12;

// Derived sizes
pub const SMP25519_SHARED_SECRET_SIZE: usize = SMP25519_CHACHA20_KEY_SIZE + SMP25519_CHACHA20_NONCE_SIZE;
pub const SMP25519_CONNECTION_ID_SIZE: usize = 8; // std::mem::size_of::<u64>();

/// Derives the public key from a private key.
///
/// # Arguments
/// * `private_key` - A reference to the private key as a byte array of size
///   [`SMP25519_PRIVATE_KEY_SIZE`].
///
/// # Returns
/// The corresponding public key as a byte array of size [`SMP25519_PUBLIC_KEY_SIZE`].
/// 
/// # Example
/// ```
/// let (private_key, public_key, _) = smp25519::generate_identity();
/// 
/// let derived_public_key = smp25519::get_public_key_from_private(&private_key);
/// 
/// assert_eq!(public_key, derived_public_key);
/// ```
#[inline]
pub fn get_public_key_from_private(private_key: &[u8; SMP25519_PRIVATE_KEY_SIZE]) -> [u8; SMP25519_PUBLIC_KEY_SIZE] {
    let static_secret = x25519_dalek::StaticSecret::from(*private_key);
    let public_key = x25519_dalek::PublicKey::from(&static_secret);

    *public_key.as_bytes()
}

/// Generates a connection ID from a public key using the BLAKE3 hash function.
///
/// This function takes a reference to a public key (as a fixed-size byte array) and computes a
/// connection ID by hashing the public key using the BLAKE3 extendable-output function (XOF).
/// The resulting connection ID is returned as a `u64` value.
///
/// # Arguments
/// * `public_key` - A reference to the public key as a byte array of size
///   [`SMP25519_PUBLIC_KEY_SIZE`].
///
/// # Returns
/// A connection ID as a `u64` value.
///
/// # Example
/// ```
/// let (_, public_key, connection_id) = smp25519::generate_identity();
/// 
/// let generated_connection_id = smp25519::generate_connection_id_from_public_key(&public_key);
/// assert_eq!(generated_connection_id, connection_id);
/// 
/// println!("Connection ID: {:#x}", connection_id);
/// ```
#[inline]
pub fn generate_connection_id_from_public_key(public_key: &[u8; SMP25519_PUBLIC_KEY_SIZE]) -> u64 {
    let mut out: std::mem::MaybeUninit<[u8; SMP25519_CONNECTION_ID_SIZE]> = std::mem::MaybeUninit::uninit();

    let mut hasher = blake3::Hasher::new();
    hasher.update(public_key);

    unsafe {
        let out_ptr = out.as_mut_ptr().cast::<u8>();
        hasher.finalize_xof().fill(std::slice::from_raw_parts_mut(out_ptr, SMP25519_CONNECTION_ID_SIZE));
        u64::from_le_bytes(out.assume_init())
    }
}

/// Generates a unique identity consisting of a private key, public key, and connection ID.
///
/// The connection ID is generated from the public key using a hash function, and the function
/// ensures that the connection ID does not start with the specific handshake request pattern.
///
/// # Returns
/// A tuple containing:
/// - The private key as a byte array of size [`SMP25519_PRIVATE_KEY_SIZE`].
/// - The public key as a byte array of size [`SMP25519_PUBLIC_KEY_SIZE`].
/// - The connection ID as a `u64`.
///
/// # Example
/// ```
/// let (private_key, public_key, connection_id) = smp25519::generate_identity();
/// 
/// println!("Private key: {:?}", private_key);
/// println!("Public key: {:?}", public_key);
/// println!("Connection ID: {:?}", connection_id);
/// ```
#[inline]
pub fn generate_identity() -> ([u8; SMP25519_PRIVATE_KEY_SIZE], [u8; SMP25519_PUBLIC_KEY_SIZE], u64) {
    loop {
        let private_key = x25519_dalek::StaticSecret::random();
        let public_key = x25519_dalek::PublicKey::from(&private_key);
        let connection_id = generate_connection_id_from_public_key(public_key.as_bytes());

        if !connection_id.to_le_bytes().starts_with(&SMP25519_HANDSHAKE_REQUEST) {
            return (*private_key.as_bytes(), *public_key.as_bytes(), connection_id);
        }
    }
}

/// Creates a handshake message by concatenating the handshake request and the public key.
///
/// This function constructs a handshake message by prepending the fixed handshake request
/// (`SMP25519_HANDSHAKE_REQUEST`) to the provided public key. The resulting message is
/// a fixed-size byte array of [`SMP25519_HANDSHAKE_REQUEST_MESSAGE_SIZE`] bytes.
///
/// # Arguments
/// * `public_key` - A reference to the public key as a byte array of size
///   [`SMP25519_PUBLIC_KEY_SIZE`].
///
/// # Returns
/// A fixed-size byte array (`[u8; SMP25519_HANDSHAKE_REQUEST_MESSAGE_SIZE]`) containing
/// the handshake request followed by the public key.
/// # Example
/// ```
/// let public_key = [0u8; smp25519::SMP25519_PUBLIC_KEY_SIZE]; // Example public key
/// let handshake_message = smp25519::create_handshake_message(&public_key);
///
/// // Verify the handshake message is constructed correctly
/// assert_eq!(
///     handshake_message,
///     [
///         0xff, 0x13, // Handshake request
///         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // Public key
///         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
///     ]
/// );
/// ```
#[inline]
pub fn create_handshake_message(public_key: &[u8; SMP25519_PUBLIC_KEY_SIZE]) -> [u8; SMP25519_HANDSHAKE_REQUEST_MESSAGE_SIZE] {
    let mut out: std::mem::MaybeUninit<[u8; SMP25519_HANDSHAKE_REQUEST_MESSAGE_SIZE]> = std::mem::MaybeUninit::uninit();

    let out_ptr = out.as_mut_ptr().cast::<u8>();

    unsafe {
        std::ptr::copy_nonoverlapping(SMP25519_HANDSHAKE_REQUEST.as_ptr(), out_ptr, SMP25519_HANDSHAKE_REQUEST_SIZE);
        std::ptr::copy_nonoverlapping(public_key.as_ptr(), out_ptr.add(SMP25519_HANDSHAKE_REQUEST_SIZE), SMP25519_PUBLIC_KEY_SIZE);
        out.assume_init()
    }
}

/// Checks if the given data is a valid handshake message.
///
/// A handshake message is valid if:
/// 1. Its length is at least [`SMP25519_HANDSHAKE_REQUEST_MESSAGE_SIZE`].
/// 2. It starts with the fixed handshake request (`SMP25519_HANDSHAKE_REQUEST`).
///
/// # Arguments
/// * `data` - The data to check.
///
/// # Returns
/// `true` if the data is a valid handshake message, otherwise `false`.
///
/// # Example
/// ```
/// let public_key = [0u8; smp25519::SMP25519_PUBLIC_KEY_SIZE]; // Example public key
/// 
/// let valid_handshake_message = smp25519::create_handshake_message(&public_key);
/// assert!(smp25519::is_handshake_message(&valid_handshake_message));
///
/// let too_short_message = [0xff, 0x13]; // Missing public key
/// assert!(!smp25519::is_handshake_message(&too_short_message));
/// ```
#[inline]
pub fn is_handshake_message(data: &[u8]) -> bool {
    if data.len() < SMP25519_HANDSHAKE_REQUEST_MESSAGE_SIZE {
        return false;
    }

    data.starts_with(&SMP25519_HANDSHAKE_REQUEST)
}

/// Checks if the given data is valid based on its length.
///
/// Data is considered valid if its length is greater than [`SMP25519_CONNECTION_ID_SIZE`].
///
/// # Arguments
/// * `data` - The data to check.
///
/// # Returns
/// `true` if the data is valid (i.e., its length is greater than [`SMP25519_CONNECTION_ID_SIZE`]),
/// otherwise `false`.
///
/// # Example
/// ```
/// // Valid data: longer than `smp25519::SMP25519_CONNECTION_ID_SIZE`
/// let valid_data = [0u8; 10]; // 10 bytes
/// assert!(smp25519::is_valid_data(&valid_data));
///
/// // Invalid data: shorter than or equal to `smp25519::SMP25519_CONNECTION_ID_SIZE`
/// let invalid_data = [0u8; 8]; // 8 bytes (equal to `smp25519::SMP25519_CONNECTION_ID_SIZE`)
/// assert!(!smp25519::is_valid_data(&invalid_data));
///
/// let too_short_data = [0u8; 5]; // 5 bytes (shorter than `smp25519::SMP25519_CONNECTION_ID_SIZE`)
/// assert!(!smp25519::is_valid_data(&too_short_data));
/// ```
#[inline]
pub fn is_valid_data(data: &[u8]) -> bool {
    data.len() > SMP25519_CONNECTION_ID_SIZE
}

/// Extracts the public key from a handshake message.
///
/// # Arguments
/// * `handshake` - The handshake message from which to extract the public key.
///
/// # Returns
/// A byte array containing the public key.
///
/// # Panics
/// Panics in debug mode if the handshake message is invalid (i.e., `is_handshake_message(handshake)` returns `false`).
///
/// # Safety
/// The caller must ensure that the handshake message is valid (i.e., `is_handshake_message(handshake)` returns `true`).
/// Otherwise, the behavior is undefined.
/// 
/// # Example
/// ```
/// let (private_key, public_key, connection_id) = smp25519::generate_identity();
/// 
/// let handshake = smp25519::create_handshake_message(&public_key);
/// let extracted_public_key = smp25519::extract_public_key_from_handshake(&handshake);
/// 
/// assert_eq!(extracted_public_key, public_key);
/// ```
#[inline]
pub fn extract_public_key_from_handshake(handshake: &[u8]) -> [u8; SMP25519_PUBLIC_KEY_SIZE] {
    debug_assert!(is_handshake_message(handshake), "Forgot to check for is_handshake_message.");

    let mut public_key: std::mem::MaybeUninit<[u8; SMP25519_PUBLIC_KEY_SIZE]> = std::mem::MaybeUninit::uninit();

    let public_key_ptr = public_key.as_mut_ptr().cast::<u8>();

    unsafe {
        std::ptr::copy_nonoverlapping(&handshake[SMP25519_HANDSHAKE_REQUEST_SIZE], public_key_ptr, SMP25519_PUBLIC_KEY_SIZE);
        public_key.assume_init()
    }
}

/// Extracts the connection ID from the given data.
///
/// The connection ID is assumed to be the first [`SMP25519_CONNECTION_ID_SIZE`] bytes of the data.
///
/// # Arguments
/// * `data` - The data from which to extract the connection ID.
///
/// # Returns
/// The connection ID as a `u64`.
///
/// # Panics
/// Panics in debug mode if the data is invalid (i.e., `is_valid_data(data)` returns `false`).
///
/// # Safety
/// The caller must ensure that the data is valid (i.e., `is_valid_data(data)` returns `true`).
/// Otherwise, the behavior is undefined.
/// 
/// # Example
/// ```
/// let data = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A]; // Example data
/// 
/// let connection_id = smp25519::extract_connection_id_from_data(&data);
/// 
/// assert_eq!(connection_id, 0x0807060504030201); // Little-endian interpretation
/// ```
#[inline]
pub fn extract_connection_id_from_data(data: &[u8]) -> u64 {
    debug_assert!(is_valid_data(data), "Forgot to check for is_valid_data.");

    let connection_id = &data[..SMP25519_CONNECTION_ID_SIZE];

    u64::from_le_bytes(connection_id.try_into().unwrap())
}

/// Derives a shared secret using the X25519 elliptic curve and BLAKE3 hashing.
///
/// The shared secret is computed as follows:
/// 1. Perform a Diffie-Hellman key exchange using the private key and handshake public key.
/// 2. Concatenate the resulting shared secret with the string "SMP25519" and the provided salt (if any).
/// 3. Hash the concatenated data using BLAKE3 to produce the final shared secret.
///
/// # Arguments
/// * `private_key` - A reference to the private key as a byte array of size [`SMP25519_PRIVATE_KEY_SIZE`].
/// * `handshake_public_key` - A reference to the handshake public key as a byte array of size [`SMP25519_PUBLIC_KEY_SIZE`].
/// * `salt` - An optional byte slice containing additional data to include in the hash.
///
/// # Returns
/// A byte array containing the derived shared secret of size [`SMP25519_SHARED_SECRET_SIZE`].
///
/// # Example
/// ```
/// let (alice_private, alice_public, _) = smp25519::generate_identity();
/// let (bob_private, bob_public, _) = smp25519::generate_identity();
/// 
/// // Derive shared secret without salt
/// let shared_secret_a = smp25519::derive_shared_secret(&alice_private, &bob_public, None);
/// let shared_secret_b = smp25519::derive_shared_secret(&bob_private, &alice_public, None);
/// assert_eq!(shared_secret_a, shared_secret_b);
/// 
/// // Derive shared secret with salt
/// let salt = b"example_salt";
/// let shared_secret_a_with_salt = smp25519::derive_shared_secret(&alice_private, &bob_public, Some(salt));
/// let shared_secret_b_with_salt = smp25519::derive_shared_secret(&bob_private, &alice_public, Some(salt));
/// assert_eq!(shared_secret_a_with_salt, shared_secret_b_with_salt);
/// 
/// assert_ne!(shared_secret_a, shared_secret_a_with_salt);
/// assert_ne!(shared_secret_b, shared_secret_b_with_salt);
/// ```
#[inline]
pub fn derive_shared_secret(private_key: &[u8; SMP25519_PRIVATE_KEY_SIZE], handshake_public_key: &[u8; SMP25519_PUBLIC_KEY_SIZE], salt: Option<&[u8]>) -> [u8; SMP25519_SHARED_SECRET_SIZE] {
    let static_secret = x25519_dalek::StaticSecret::from(*private_key);
    let public_key = x25519_dalek::PublicKey::from(*handshake_public_key);
    
    let raw_shared_secret = static_secret.diffie_hellman(&public_key);

    let mut hasher = blake3::Hasher::new();
    hasher.update(raw_shared_secret.as_bytes());
    hasher.update(b"SMP25519");

    if let Some(salt) = salt {
        hasher.update(salt);
    }

    let mut shared_secret: std::mem::MaybeUninit<[u8; SMP25519_SHARED_SECRET_SIZE]> = std::mem::MaybeUninit::uninit();
    let shared_secret_ptr = shared_secret.as_mut_ptr().cast::<u8>();

    unsafe {
        hasher.finalize_xof().fill(std::slice::from_raw_parts_mut(shared_secret_ptr, SMP25519_SHARED_SECRET_SIZE));
        shared_secret.assume_init()
    }
}

/// Encrypts the provided data using the ChaCha20 stream cipher and writes the result to the output buffer.
///
/// This function performs the following steps:
/// 1. Splits the shared secret into a key and nonce for ChaCha20 encryption.
/// 2. Writes the connection ID to the beginning of the output buffer.
/// 3. Encrypts the input data using the ChaCha20 cipher and writes the result to the output buffer.
///
/// # Arguments
/// * `connection_id` - A unique identifier for the connection, written to the output buffer in little-endian format.
/// * `data` - The data to encrypt. Must be non-empty.
/// * `shared_secret` - A shared secret used to derive the ChaCha20 key and nonce. Must be exactly
///   [`SMP25519_SHARED_SECRET_SIZE`] bytes long.
/// * `out` - The output buffer where the connection ID and encrypted data will be written. Must be at least
///   [`SMP25519_CONNECTION_ID_SIZE`] + `data.len()` bytes long.
///
/// # Returns
/// The total number of bytes written to the output buffer, which is [`SMP25519_CONNECTION_ID_SIZE`] + `data.len()`.
///
/// # Panics
/// Panics in debug mode if the `out` buffer is too small to hold the connection ID and encrypted data.
/// 
/// # Example
/// ```
/// let (alice_private, _, alice_connection_id) = smp25519::generate_identity();
/// let (_, bob_public, _) = smp25519::generate_identity();
/// 
/// let data = b"Hello, world!";
/// let shared_secret = smp25519::derive_shared_secret(&alice_private, &bob_public, None);
/// let mut out = [0u8; 1024]; // Output buffer
///
/// let bytes_written = smp25519::encrypt_and_send_data(alice_connection_id, data, &shared_secret, &mut out);
///
/// assert_eq!(bytes_written, smp25519::SMP25519_CONNECTION_ID_SIZE + data.len());
/// println!("Output buffer: {:?}", out);
/// ```
#[inline]
pub fn encrypt_and_send_data(connection_id: u64, data: &[u8], shared_secret: &[u8; SMP25519_SHARED_SECRET_SIZE], out: &mut [u8]) -> usize {
    debug_assert!(data.len() > 0, "Data can't be nothing.");
    debug_assert!(out.len() >= SMP25519_CONNECTION_ID_SIZE + data.len(), "Output buffer is too small.");

    let (key, nonce) = shared_secret.split_at(SMP25519_CHACHA20_KEY_SIZE);

    let mut cipher = chacha20::ChaCha20::new(key.try_into().unwrap(), nonce.try_into().unwrap());

    out[0..SMP25519_CONNECTION_ID_SIZE].copy_from_slice(&connection_id.to_le_bytes());

    let encrypted_data = &mut out[SMP25519_CONNECTION_ID_SIZE..SMP25519_CONNECTION_ID_SIZE + data.len()];
    encrypted_data.copy_from_slice(data);
    cipher.apply_keystream(encrypted_data);

    SMP25519_CONNECTION_ID_SIZE + data.len()
}

/// Decrypts the received data using the provided shared secret and writes the result to the output buffer.
///
/// This function performs the following steps:
/// 1. Validates that the output buffer is large enough to hold the decrypted data.
/// 2. Splits the shared secret into a key and nonce for ChaCha20 decryption.
/// 3. Skips the connection ID at the beginning of the input data.
/// 4. Decrypts the remaining data using the ChaCha20 cipher and writes the result to the output buffer.
///
/// # Arguments
/// * `data` - The data to decrypt. Must be longer than [`SMP25519_CONNECTION_ID_SIZE`] bytes.
/// * `shared_secret` - The shared secret used for decryption. Must be exactly [`SMP25519_SHARED_SECRET_SIZE`] bytes long.
/// * `out` - The output buffer where the decrypted data will be written. Must be at least
///   `data.len() - SMP25519_CONNECTION_ID_SIZE` bytes long.
///
/// # Returns
/// The number of bytes written to the output buffer, which is `data.len() - SMP25519_CONNECTION_ID_SIZE`.
///
/// # Panics
/// This function will panic in the following cases:
/// - In debug mode, if the `data` length is not greater than [`SMP25519_CONNECTION_ID_SIZE`]. Check [`is_valid_data`].
/// - In debug mode, if the output buffer is too small to hold the decrypted data.
///
/// # Example
/// ```
/// // Example encrypted data (connection ID + encrypted payload)
/// let data = [
///     0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // Connection ID
///     0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, // Encrypted payload
/// ];
///
/// // Example shared secret (44 bytes)
/// let shared_secret = [0u8; smp25519::SMP25519_SHARED_SECRET_SIZE];
///
/// // Output buffer for decrypted data
/// let mut out = [0u8; 6]; // Size matches the encrypted payload
///
/// let bytes_written = smp25519::decrypt_received_data(&data, &shared_secret, &mut out);
///
/// assert_eq!(bytes_written, data.len() - smp25519::SMP25519_CONNECTION_ID_SIZE);
/// println!("Decrypted data: {:?}", out);
/// ```
#[inline]
pub fn decrypt_received_data(data: &[u8], shared_secret: &[u8; SMP25519_SHARED_SECRET_SIZE], out: &mut [u8]) -> usize {
    debug_assert!(is_valid_data(data), "Forgot to check for is_valid_data.");
    debug_assert!(out.len() >= data.len() - SMP25519_CONNECTION_ID_SIZE, "Output buffer is too small.");

    let (key, nonce) = shared_secret.split_at(SMP25519_CHACHA20_KEY_SIZE);

    let mut cipher = chacha20::ChaCha20::new(key.try_into().unwrap(), nonce.try_into().unwrap());

    let encrypted_data = &data[SMP25519_CONNECTION_ID_SIZE..];
    let decrypted_data = &mut out[..encrypted_data.len()];
    decrypted_data.copy_from_slice(encrypted_data);
    cipher.apply_keystream(decrypted_data);

    decrypted_data.len()
}