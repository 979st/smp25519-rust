use smp25519;
use std::io::Write;
use base64::Engine;

const KNOWN_SERVER_PUBLIC_KEY: &str = "Vh4DBTYyDbwTqg1eZzTnuTxThscIoNQgLpxgsBCOFCU=";
const SERVER_ADDR: &str = "127.0.0.1:12000";
const BUFFER_SIZE: usize = 1024;
const MAX_RESPONSE_SIZE: usize = BUFFER_SIZE + smp25519::SMP25519_CONNECTION_ID_SIZE;

// Secure UDP client example using the smp25519 crate.
// This example demonstrates how to establish a secure communication channel
// with a server using key exchange and encryption. 
fn main() -> std::io::Result<()> {
    // Step 1: Generate client identity (private key, public key, and connection ID).
    let (private_key, public_key, connection_id) = smp25519::generate_identity();

    // Step 2 (RECOMMENDED): Define the server's known public key (Base64 encoded).
    let known_server_public_key = base64::prelude::BASE64_STANDARD.decode(KNOWN_SERVER_PUBLIC_KEY).unwrap();

    // Step 3: Create a UDP socket.
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();

    println!("Secure UDP Client: Attempting connection to {}", SERVER_ADDR);

    // Step 4: Send handshake message containing the client's public key.
    let handshake = smp25519::create_handshake_message(&public_key);
    socket.send_to(&handshake, SERVER_ADDR).unwrap();

    // Step 5: Receive and validate handshake response from the server.
    let mut buf = [0u8; BUFFER_SIZE];
    let (amt, _) = socket.recv_from(&mut buf).unwrap();
    if smp25519::is_handshake_message(&buf[..amt]) == false {
        eprintln!("Error: Handshake failed. Invalid response received.");
        return Ok(());
    }

    // Extract the server's public key from the handshake message.
    let server_public_key = smp25519::extract_public_key_from_handshake(&buf[..amt]);

    // (RECOMMENDED) Verify the server's public key.
    if server_public_key != known_server_public_key.as_slice() {
        eprintln!("Error: Known server public key mismatch. Aborting connection.");
        return Ok(());
    }

    // Step 6: Derive the shared secret using the server's public key and a salt.
    // let shared_secret = smp25519::derive_shared_secret(&private_key, &server_public_key, Some(b"examplesalt"));
    let shared_secret = smp25519::derive_shared_secret(&private_key, &server_public_key, None);

    // Step 7: Exchange encrypted messages with the server.
    loop {
        // Input message from the user.
        println!("Enter a message to send (or press Enter to retry): ");
        std::io::stdout().flush().unwrap();
        let mut line = String::new();
        std::io::stdin().read_line(&mut line).unwrap();
        let line = line.trim();

        if line.is_empty() {
            continue;
        }

        if line.eq_ignore_ascii_case("exit") {
            break;
        }

        // Encrypt and send the message.
        let mut buf = [0u8; BUFFER_SIZE];
        let bytes_written = smp25519::encrypt_and_send_data(connection_id, line.as_bytes(), &shared_secret, &mut buf);
        socket.send_to(&buf[..bytes_written], SERVER_ADDR).unwrap();

        // Receive and decrypt the server's response.
        let mut buf2 = [0u8; MAX_RESPONSE_SIZE];
        let (amt, src) = socket.recv_from(&mut buf2).unwrap();
        let bytes_written = smp25519::decrypt_received_data(&buf2[..amt], &shared_secret, &mut buf);
        println!("Server response from {}: {}", src.to_string(), std::str::from_utf8(&buf[..bytes_written]).unwrap());
    }

    Ok(())
}