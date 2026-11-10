# Local End-to-End Encrypted Chat

This classroom prototype provides local username/password accounts, browser-held
encryption/signing keys, peer fingerprint pinning, and real-time encrypted text
and file transfer. The relay stores account password hashes and public keys but
has no private keys or message-decryption operation.

## Authentication and key verification

- Usernames and salted `scrypt` password hashes are stored in the local SQLite
  database. Passwords are not stored in plaintext.
- New accounts require passwords of at least 12 characters.
- Each browser profile generates non-exportable RSA-OAEP-2048 encryption and
  ECDSA P-256 signing keys. The private `CryptoKey` objects are persisted in
  IndexedDB; only public JWKs are sent to the server.
- Accounts cannot be recovered if browser profile data or the local database is
  lost. There is no password reset or private-key backup.
- Before sending, compare the complete public-key fingerprint with the named
  person over an independent trusted channel, then confirm it in the UI.
  Fingerprints are pinned in that browser profile; a changed key blocks sending
  until the new fingerprint is independently checked and explicitly confirmed.
- ECDSA-SHA-256 signatures cover sender and recipient identities, ciphertext,
  wrapped key, IV, and (for files) filename and media type. Receivers verify the
  sender signature against the pinned signing key before displaying decrypted
  content.
- Incoming messages and files remain encrypted and hidden until the recipient
  clicks their individual **Decrypt Message** or **Decrypt File** button. The
  browser checks the sender's pinned fingerprint and signature before decrypting;
  failed checks never reveal plaintext. Pending payloads are not persisted, so
  refreshing the page does not decrypt them.

## Encryption design

- A fresh AES-256-GCM key and random 96-bit IV encrypt each message or file.
- RSA-OAEP with SHA-256 wraps the AES key to the recipient.
- GCM tags detect ciphertext tampering; ECDSA signatures authenticate the sender
  and bind the envelope and file metadata.
- The relay forwards ciphertext and public keys only; it cannot decrypt content.
- Files are limited to 10 MiB.

## Run locally (Windows)

For the combined detector and chat experience, start both services from the
project root with `start_all.bat`. Sign in at `http://127.0.0.1:5001/` and
choose Chat or Detector. Detector access requires the active sign-in session.

To run chat by itself for development:

```powershell
cd e2ee_chat
.\start_server.bat
```

Open `http://127.0.0.1:5001/` in two browser profiles or windows. Create an
account in each, then choose Chat. After selecting a peer, compare the
displayed fingerprint by phone or in person before checking the confirmation
box. Never verify by comparing fingerprints shown only by this chat.

The server binds to loopback and uses local HTTP; passwords are not protected
against other software with access to the machine. Do not expose the server to a
network or the public internet.

## Presentation walkthrough

1. Open the chat in two separate browser profiles and create accounts named
   `Lereng` and `John`, using separate passwords.
2. Compare the complete fingerprint shown in each account's **Your
   public-key fingerprint** section over an independent channel (for example,
   in person or by phone). In each profile, select the other user, verify the
   peer fingerprint matches what that user shared, and confirm it before
   sending.
3. Send a message. Expand **Encrypted payload sent through the relay** in
   Lereng's sent bubble to show the ciphertext, wrapped key, IV, and signature
   that are transmitted. John should first see only an encrypted-message
   notification and a **Decrypt Message** button. After John clicks it and
   verification succeeds, the plaintext is displayed. Incoming files follow
   the same flow with **Decrypt File**. The server does not store message
   history or have a decryption endpoint.
4. Demonstrate the automated checks with
   `node tests\test_chat_crypto.js`: plaintext remains hidden before each
   recipient's click, then decrypts in the independent recipient context;
   separate messages and files have separate controls, and signature,
   ciphertext, fingerprint, and decryption-key failures do not reveal content.
5. Demonstrate authentication and access controls with
   `python -m unittest discover -s e2ee_chat\tests -p test_server.py`: incorrect
   passwords, unregistered sends, and unauthenticated user enumeration are
   rejected.

## Tests

```powershell
python -m unittest discover -s e2ee_chat\tests -p test_server.py
node tests\test_chat_crypto.js
```

Tests cover password authentication, persisted account/key binding, ciphertext
relay, end-to-end sender/recipient encryption, manual message/file decryption,
ECDSA message/file signatures, modified envelope rejection, fingerprint
pinning/key changes, and blocked unauthenticated access. This is not a formal
cryptographic review. Forward secrecy, metadata protection, secure remote
transport, recovery, rate limiting, and protection against a compromised server
serving modified browser code are not provided.
