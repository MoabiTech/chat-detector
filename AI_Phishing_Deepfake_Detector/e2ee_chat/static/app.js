let socket;
let keyPair;
let signingKeyPair;
let myUsername;
let sessionToken;
let selectedUser = null;
let users = [];

const MAX_FILE_BYTES = 10 * 1024 * 1024;
const KEY_DATABASE_NAME = 'local-e2ee-chat-keys';
const TRUSTED_PEERS_KEY = 'local-e2ee-chat-trusted-peers';
const encoder = new TextEncoder();

document.getElementById('generateKeysBtn').addEventListener('click', generateKeys);
document.getElementById('registerBtn').addEventListener('click', register);
document.getElementById('authMode').addEventListener('change', updateAuthMode);
document.getElementById('sendBtn').addEventListener('click', sendMessage);
document.getElementById('sendFileBtn').addEventListener('click', sendFile);
document.getElementById('verifyPeerBtn').addEventListener('click', trustSelectedPeer);
document.getElementById('peerFingerprintConfirmed').addEventListener('change', updateTrustButton);
document.getElementById('logoutBtn').addEventListener('click', logout);
document.getElementById('backToChoicesBtn').addEventListener('click', showChoices);
document.getElementById('openChatBtn').addEventListener('click', showChat);
document.getElementById('openDetectorBtn').addEventListener('click', openDetector);
document.getElementById('messageInput').addEventListener('keypress', (event) => {
    if (event.key === 'Enter') sendMessage();
});
updateAuthMode();

function updateAuthMode() {
    const creating = document.getElementById('authMode').value === 'create';
    document.getElementById('registerBtn').textContent = creating
        ? 'Create Account and Sign In'
        : 'Sign In';
    document.getElementById('password').autocomplete = creating ? 'new-password' : 'current-password';
}

function normalizedUsername(username) {
    return username.trim().toLowerCase();
}

function openKeyDatabase() {
    return new Promise((resolve, reject) => {
        if (!('indexedDB' in window)) {
            reject(new Error('This browser does not support persistent local encryption keys.'));
            return;
        }
        const request = indexedDB.open(KEY_DATABASE_NAME, 1);
        request.onupgradeneeded = () => {
            request.result.createObjectStore('keyPairs', { keyPath: 'username' });
        };
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error || new Error('Could not open local key storage.'));
        request.onblocked = () => reject(new Error('Local key storage is blocked by another browser tab.'));
    });
}

async function loadStoredKeyPairs(username) {
    const database = await openKeyDatabase();
    try {
        return await new Promise((resolve, reject) => {
            const transaction = database.transaction('keyPairs', 'readonly');
            const request = transaction.objectStore('keyPairs').get(normalizedUsername(username));
            request.onsuccess = () => resolve(request.result || null);
            request.onerror = () => reject(request.error || new Error('Could not load local encryption keys.'));
        });
    } finally {
        database.close();
    }
}

async function storeKeyPairs(username, encryptionKeys, signingKeys) {
    const database = await openKeyDatabase();
    try {
        await new Promise((resolve, reject) => {
            const transaction = database.transaction('keyPairs', 'readwrite');
            transaction.objectStore('keyPairs').put({
                username: normalizedUsername(username),
                encryptionKeys,
                signingKeys
            });
            transaction.oncomplete = resolve;
            transaction.onerror = () => reject(transaction.error || new Error('Could not save local encryption keys.'));
            transaction.onabort = () => reject(transaction.error || new Error('Saving local encryption keys was cancelled.'));
        });
    } finally {
        database.close();
    }
}

async function generateKeys() {
    const button = document.getElementById('generateKeysBtn');
    const status = document.getElementById('keyStatus');
    const username = document.getElementById('username').value.trim();
    if (!/^[A-Za-z0-9_.-]{3,32}$/.test(username)) {
        showStatus('Choose a username with 3-32 letters, numbers, dots, underscores, or hyphens.');
        return;
    }
    button.disabled = true;
    status.textContent = 'Loading or generating local encryption and signing keys...';
    status.className = 'status';

    try {
        const storedKeys = await loadStoredKeyPairs(username);
        if (storedKeys) {
            keyPair = storedKeys.encryptionKeys;
            signingKeyPair = storedKeys.signingKeys;
        } else {
            keyPair = await crypto.subtle.generateKey(
                {
                    name: 'RSA-OAEP',
                    modulusLength: 2048,
                    publicExponent: new Uint8Array([1, 0, 1]),
                    hash: 'SHA-256'
                },
                false,
                ['encrypt', 'decrypt']
            );
            signingKeyPair = await crypto.subtle.generateKey(
                { name: 'ECDSA', namedCurve: 'P-256' },
                false,
                ['sign', 'verify']
            );
        }
        await verifyLocalKeyPairs(keyPair, signingKeyPair);
        if (!storedKeys) await storeKeyPairs(username, keyPair, signingKeyPair);
        status.textContent = storedKeys
            ? 'Existing non-exportable keys loaded and verified in this browser profile.'
            : 'Non-exportable keys generated, verified, and stored in this browser profile.';
        status.className = 'status success';
        button.disabled = false;
        document.getElementById('registerBtn').disabled = false;
    } catch (error) {
        keyPair = null;
        signingKeyPair = null;
        button.disabled = false;
        status.textContent = `Key setup failed: ${error.message}`;
        status.className = 'status error';
    }
}

async function verifyLocalKeyPairs(encryptionKeys, signingKeys) {
    if (
        !encryptionKeys?.privateKey
        || !encryptionKeys?.publicKey
        || !signingKeys?.privateKey
        || !signingKeys?.publicKey
        || encryptionKeys.privateKey.extractable
        || signingKeys.privateKey.extractable
        || encryptionKeys.privateKey.algorithm.name !== 'RSA-OAEP'
        || signingKeys.privateKey.algorithm.name !== 'ECDSA'
    ) {
        throw new Error('Stored identity keys are missing, exportable, or use an unsupported algorithm.');
    }

    const challenge = crypto.getRandomValues(new Uint8Array(32));
    const signingJwk = await crypto.subtle.exportKey('jwk', signingKeys.publicKey);
    const signingPublicKey = await crypto.subtle.importKey(
        'jwk',
        signingJwk,
        { name: 'ECDSA', namedCurve: 'P-256' },
        false,
        ['verify']
    );
    const signature = await crypto.subtle.sign(
        { name: 'ECDSA', hash: 'SHA-256' },
        signingKeys.privateKey,
        challenge
    );
    if (!await crypto.subtle.verify(
        { name: 'ECDSA', hash: 'SHA-256' },
        signingPublicKey,
        signature,
        challenge
    )) {
        throw new Error('The saved signing public key does not match its private key.');
    }

    const wrappedChallenge = await crypto.subtle.encrypt(
        { name: 'RSA-OAEP' },
        encryptionKeys.publicKey,
        challenge
    );
    const unwrappedChallenge = await crypto.subtle.decrypt(
        { name: 'RSA-OAEP' },
        encryptionKeys.privateKey,
        wrappedChallenge
    );
    if (new Uint8Array(unwrappedChallenge).some((byte, index) => byte !== challenge[index])) {
        throw new Error('The saved encryption public key does not match its private key.');
    }
}

async function exportPublicKeys() {
    if (!keyPair || !signingKeyPair) throw new Error('Generate or load keys before signing in.');
    return {
        encryption: await crypto.subtle.exportKey('jwk', keyPair.publicKey),
        signing: await crypto.subtle.exportKey('jwk', signingKeyPair.publicKey)
    };
}

function register() {
    myUsername = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value;
    const mode = document.getElementById('authMode').value;
    if (!/^[A-Za-z0-9_.-]{3,32}$/.test(myUsername)) {
        showStatus('Choose a username with 3-32 letters, numbers, dots, underscores, or hyphens.');
        return;
    }
    if (password.length < 12 || encoder.encode(password).length > 1024) {
        showStatus('Use a password of at least 12 characters and no more than 1024 UTF-8 bytes.');
        return;
    }
    if (!keyPair || !signingKeyPair) {
        showStatus('Load or generate this account’s encryption keys before connecting.');
        return;
    }

    document.getElementById('registerBtn').disabled = true;
    socket = io({ autoConnect: false });
    socket.on('connect', async () => {
        try {
            socket.emit('register', {
                mode,
                username: myUsername,
                password,
                public_keys: await exportPublicKeys()
            });
        } catch (error) {
            showStatus(`Could not authenticate: ${error.message}`);
            document.getElementById('registerBtn').disabled = false;
            socket.disconnect();
        }
    });
    socket.on('user_registered', async (result) => {
        if (!result || !result.success) {
            showStatus(result?.error || 'Authentication failed.');
            document.getElementById('registerBtn').disabled = false;
            socket.disconnect();
            return;
        }
        if (typeof result.session_token !== 'string') {
            showStatus('The server did not create an app session. Please try signing in again.');
            document.getElementById('registerBtn').disabled = false;
            socket.disconnect();
            return;
        }
        myUsername = result.username;
        sessionToken = result.session_token;
        try {
            document.getElementById('myFingerprint').textContent = await keyFingerprint(
                await exportPublicKeys()
            );
        } catch (error) {
            showStatus(`Could not calculate your public-key fingerprint: ${error.message}`);
            document.getElementById('registerBtn').disabled = false;
            socket.disconnect();
            return;
        }
        document.getElementById('password').value = '';
        document.getElementById('setupPanel').style.display = 'none';
        document.getElementById('choicePanel').style.display = 'block';
        document.getElementById('choiceUsername').textContent = myUsername;
        document.getElementById('myUsername').textContent = myUsername;
        showStatus('Signed in. Choose Chat or Detector to continue.', true);
    });
    socket.on('user_list', async (userList) => {
        try {
            users = await Promise.all(userList
                .filter((user) => user.sid !== socket.id)
                .map(async (user) => ({
                    ...user,
                    fingerprint: await keyFingerprint(user.public_keys)
                })));
            updateUserList();
            if (selectedUser) {
                selectedUser = users.find((user) => user.username === selectedUser.username) || null;
                await updatePeerVerification();
            }
        } catch (error) {
            users = [];
            updateUserList();
            showStatus(`Could not verify the received public keys: ${error.message}`);
        }
    });
    socket.on('receive_message', async (data) => {
        await handleReceivedMessage(data);
    });
    socket.on('receive_file', async (data) => {
        await handleReceivedFile(data);
    });
    socket.on('message_sent', handleMessageSent);
    socket.on('file_sent', handleFileSent);
    socket.on('connect_error', (error) => {
        showStatus(`Could not connect to the local chat server: ${error.message}`);
        document.getElementById('registerBtn').disabled = false;
    });
    socket.connect();
}

function readTrustedPeers() {
    if (!myUsername) throw new Error('Sign in before loading peer-verification data.');
    const accountKey = trustedPeersStorageKey();
    const accountValue = localStorage.getItem(accountKey);
    if (accountValue) return validateTrustedPeers(JSON.parse(accountValue));

    const legacyValue = localStorage.getItem(TRUSTED_PEERS_KEY);
    if (!legacyValue) return {};
    const legacy = JSON.parse(legacyValue);
    if (!legacy || typeof legacy !== 'object' || Array.isArray(legacy)) {
        throw new Error('Stored peer-verification data is invalid; fingerprints were not trusted.');
    }

    let peers;
    if (legacy.version === 2 && legacy.accounts && typeof legacy.accounts === 'object') {
        peers = validateTrustedPeers(legacy.accounts[normalizedUsername(myUsername)] || {});
    } else {
        peers = {};
        for (const [username, fingerprint] of Object.entries(legacy)) {
            if (!/^[A-Za-z0-9_.-]{3,32}$/.test(username) || !isValidFingerprint(fingerprint)) {
                throw new Error('Stored peer-verification data is invalid; fingerprints were not trusted.');
            }
            peers[normalizedUsername(username)] = fingerprint;
        }
        localStorage.removeItem(TRUSTED_PEERS_KEY);
    }
    localStorage.setItem(accountKey, JSON.stringify(peers));
    return peers;
}

function trustedPeersStorageKey() {
    if (!myUsername) throw new Error('Sign in before loading peer-verification data.');
    return `${TRUSTED_PEERS_KEY}:${normalizedUsername(myUsername)}`;
}

function validateTrustedPeers(peers) {
    if (!peers || typeof peers !== 'object' || Array.isArray(peers)) {
        throw new Error('Stored peer-verification data is invalid; fingerprints were not trusted.');
    }
    for (const [username, fingerprint] of Object.entries(peers)) {
        if (!/^[a-z0-9_.-]{3,32}$/.test(username) || !isValidFingerprint(fingerprint)) {
            throw new Error('Stored peer-verification data is invalid; fingerprints were not trusted.');
        }
    }
    return peers;
}

function isValidFingerprint(fingerprint) {
    return typeof fingerprint === 'string'
        && /^(?:[A-F0-9]{4} ){15}[A-F0-9]{4}$/.test(fingerprint);
}

function saveTrustedPeer(username, fingerprint) {
    if (!isValidFingerprint(fingerprint)) throw new Error('The peer fingerprint is invalid.');
    const peers = readTrustedPeers();
    peers[normalizedUsername(username)] = fingerprint;
    localStorage.setItem(trustedPeersStorageKey(), JSON.stringify(peers));
}

function updateUserList() {
    const userListDiv = document.getElementById('userList');
    userListDiv.replaceChildren();

    users.forEach((user) => {
        const item = document.createElement('button');
        item.type = 'button';
        item.className = 'user-item';
        item.textContent = user.display_name;
        item.addEventListener('click', () => selectUser(user, item));
        userListDiv.appendChild(item);
    });
}

async function selectUser(user, item) {
    document.querySelectorAll('.user-item').forEach((element) => element.classList.remove('active'));
    item.classList.add('active');
    selectedUser = user;
    document.getElementById('chatWith').textContent = `Chatting with: ${user.display_name}`;
    try {
        await updatePeerVerification();
    } catch (error) {
        setChatControlsEnabled(false);
        showStatus(`Could not load peer trust data: ${error.message}`);
    }
}

async function updatePeerVerification() {
    const panel = document.getElementById('peerVerification');
    const checkbox = document.getElementById('peerFingerprintConfirmed');
    const button = document.getElementById('verifyPeerBtn');
    const status = document.getElementById('peerTrustStatus');
    checkbox.checked = false;
    checkbox.disabled = false;

    if (!selectedUser) {
        panel.style.display = 'none';
        setChatControlsEnabled(false);
        return;
    }

    panel.style.display = 'block';
    document.getElementById('peerFingerprint').textContent = selectedUser.fingerprint;
    document.getElementById('peerFingerprintIdentity').textContent = selectedUser.username;
    const trustScope = `This pin applies only to ${myUsername} in this browser profile at ${window.location.origin}.`;
    const pinnedFingerprint = readTrustedPeers()[normalizedUsername(selectedUser.username)];
    if (pinnedFingerprint === selectedUser.fingerprint) {
        status.textContent =
            `You verified ${selectedUser.username}'s full fingerprint. ${trustScope} `
            + 'The other user must verify your fingerprint separately.';
        status.className = 'status success';
        checkbox.disabled = true;
        button.textContent = 'Fingerprint previously confirmed';
        button.disabled = true;
        setChatControlsEnabled(true);
    } else {
        status.textContent = pinnedFingerprint
            ? `WARNING: this account’s key changed. ${trustScope} `
                + 'Do not accept messages until you verify the new fingerprint independently.'
            : `Unverified user. ${trustScope} Compare the complete fingerprint through a separate trusted channel before confirming.`;
        status.className = 'status error';
        button.textContent = pinnedFingerprint ? 'Replace trusted key after re-verifying' : 'Trust fingerprint after checking';
        button.disabled = true;
        setChatControlsEnabled(false);
    }
}

function updateTrustButton() {
    const checkbox = document.getElementById('peerFingerprintConfirmed');
    document.getElementById('verifyPeerBtn').disabled = !selectedUser || !checkbox.checked;
}

async function getVerifiedSelectedPeer() {
    if (!selectedUser || !socket?.connected) {
        throw new Error('Connect and select a peer before sending.');
    }
    const peer = users.find((user) => (
        user.username === selectedUser.username && user.sid === selectedUser.sid
    ));
    if (!peer) throw new Error('The selected peer is no longer online.');

    const fingerprint = await keyFingerprint(peer.public_keys);
    if (
        fingerprint !== peer.fingerprint
        || readTrustedPeers()[normalizedUsername(peer.username)] !== fingerprint
    ) {
        throw new Error('Verify this peer’s current fingerprint out of band before sending.');
    }
    return peer;
}

async function trustSelectedPeer() {
    if (!selectedUser || !document.getElementById('peerFingerprintConfirmed').checked) return;
    try {
        const fingerprint = await keyFingerprint(selectedUser.public_keys);
        if (fingerprint !== selectedUser.fingerprint) {
            throw new Error('The peer key changed while it was being verified. Select the peer again.');
        }
        saveTrustedPeer(selectedUser.username, fingerprint);
        selectedUser.fingerprint = fingerprint;
        document.getElementById('peerFingerprintConfirmed').checked = false;
        await updatePeerVerification();
    } catch (error) {
        showStatus(`Could not save peer verification: ${error.message}`);
    }
}

function setChatControlsEnabled(enabled) {
    document.getElementById('messageInput').disabled = !enabled;
    document.getElementById('sendBtn').disabled = !enabled;
    document.getElementById('fileInput').disabled = !enabled;
    document.getElementById('sendFileBtn').disabled = !enabled;
}

async function verifyIncoming(data, type) {
    if (!data || data.recipient_username !== myUsername) {
        throw new Error('The message recipient does not match this account.');
    }
    const sender = users.find((user) => (
        user.username === data.from_username && user.sid === data.from_sid
    ));
    if (!sender) throw new Error('Sender is not currently authenticated and online.');
    const fingerprint = await keyFingerprint(sender.public_keys);
    if (fingerprint !== sender.fingerprint) {
        throw new Error('The sender public key changed during verification; select the peer again.');
    }
    const pinnedFingerprint = readTrustedPeers()[normalizedUsername(sender.username)];
    if (!pinnedFingerprint) {
        const error = new Error(
            `The sender fingerprint has not been independently verified for ${myUsername} `
            + `in this browser profile at ${window.location.origin}.`
        );
        error.code = 'UNVERIFIED_SENDER';
        throw error;
    }
    if (pinnedFingerprint !== fingerprint) {
        const error = new Error(
            'The sender public key changed since it was verified. Do not accept this message; '
            + 'verify the new fingerprint out of band.'
        );
        error.code = 'CHANGED_SENDER_KEY';
        throw error;
    }

    let payload;
    if (type === 'message') {
        payload = messageSignaturePayload(data);
    } else {
        payload = fileSignaturePayload(data);
    }
    let signatureValid;
    try {
        signatureValid = await verifyPayloadSignature(
            payload,
            data.signature,
            sender.public_keys.signing
        );
    } catch (error) {
        throw new Error(`The sender signature could not be checked: ${error.message}`);
    }
    if (!signatureValid) throw new Error('The sender signature is invalid.');
    return sender;
}

async function keyFingerprint(publicKeys) {
    const digest = await crypto.subtle.digest('SHA-256', encoder.encode(canonicalJson(publicKeys)));
    const hex = Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('');
    return hex.toUpperCase().match(/.{1,4}/g).join(' ');
}

function canonicalJson(value) {
    if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
    if (value && typeof value === 'object') {
        return `{${Object.keys(value).sort().map(
            (key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`
        ).join(',')}}`;
    }
    return JSON.stringify(value);
}

function messageSignaturePayload(data) {
    return {
        from_username: data.from_username,
        recipient_username: data.recipient_username,
        message_type: data.message_type,
        encrypted_message: data.encrypted_message,
        encrypted_key: data.encrypted_key,
        iv: data.iv
    };
}

function fileSignaturePayload(data) {
    return {
        from_username: data.from_username,
        recipient_username: data.recipient_username,
        filename: data.filename,
        file_type: data.file_type,
        encrypted_file: data.encrypted_file,
        encrypted_key: data.encrypted_key,
        iv: data.iv
    };
}

async function signPayload(payload) {
    if (!signingKeyPair) throw new Error('Signing key is not available.');
    const signature = await crypto.subtle.sign(
        { name: 'ECDSA', hash: 'SHA-256' },
        signingKeyPair.privateKey,
        encoder.encode(canonicalJson(payload))
    );
    return bytesToBase64(new Uint8Array(signature));
}

async function verifyPayloadSignature(payload, signature, signingPublicJwk) {
    const publicKey = await crypto.subtle.importKey(
        'jwk',
        signingPublicJwk,
        { name: 'ECDSA', namedCurve: 'P-256' },
        false,
        ['verify']
    );
    return crypto.subtle.verify(
        { name: 'ECDSA', hash: 'SHA-256' },
        publicKey,
        base64ToBytes(signature),
        encoder.encode(canonicalJson(payload))
    );
}

function handleReceivedMessage(data) {
    createEncryptedIncomingItem(data, 'message');
}

function handleReceivedFile(data) {
    createEncryptedIncomingItem(data, 'file');
}

function createEncryptedIncomingItem(data, type) {
    const senderName = typeof data?.from_user === 'string'
        ? data.from_user
        : (typeof data?.from_username === 'string' ? data.from_username : 'Unknown sender');
    const item = document.createElement('div');
    item.className = 'message received encrypted-pending';

    const title = document.createElement('div');
    title.className = 'message-info';
    title.textContent = type === 'message' ? 'Encrypted message received' : 'Encrypted file received';
    const sender = document.createElement('div');
    sender.className = 'message-sender';
    sender.textContent = `FROM: ${senderName}`;
    const payloadLabel = document.createElement('div');
    payloadLabel.className = 'encrypted-payload-label';
    payloadLabel.textContent = 'Encrypted payload';
    const content = document.createElement('div');
    content.className = 'encrypted-content';
    content.textContent = type === 'message'
        ? 'Message content is hidden until you decrypt it.'
        : `File content is hidden until you decrypt it. ${data?.filename || ''}`;
    const signatureStatus = document.createElement('div');
    signatureStatus.className = 'message-security-status';
    signatureStatus.textContent = 'Signature not verified';
    const decryptionStatus = document.createElement('div');
    decryptionStatus.className = 'message-security-status';
    decryptionStatus.textContent = 'Not decrypted';
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'decrypt-button';
    button.textContent = type === 'message' ? 'Decrypt Message' : 'Decrypt File';
    button.addEventListener('click', () => decryptIncomingItem(data, type, {
        item,
        content,
        signatureStatus,
        decryptionStatus,
        button
    }));

    item.append(title, sender, payloadLabel, content, signatureStatus, decryptionStatus, button);
    appendMessage(item);
    showStatus(
        type === 'message'
            ? `Encrypted message received from ${senderName}.`
            : `Encrypted file received from ${senderName}.`,
        true
    );
}

async function decryptIncomingItem(data, type, elements) {
    const { item, content, signatureStatus, decryptionStatus, button } = elements;
    if (button.disabled) return;

    button.disabled = true;
    let signatureVerified = false;
    signatureStatus.textContent = 'Verifying sender fingerprint and signature...';
    signatureStatus.className = 'message-security-status';
    decryptionStatus.textContent = 'Not decrypted';
    decryptionStatus.className = 'message-security-status';
    try {
        const sender = await verifyIncoming(data, type);
        signatureVerified = true;
        signatureStatus.textContent = 'Signature successfully verified';
        signatureStatus.className = 'message-security-status success';

        const encryptedData = type === 'message' ? data.encrypted_message : data.encrypted_file;
        const bytes = await decryptPayload(encryptedData, data.iv, data.encrypted_key);
        if (type === 'message') {
            try {
                content.textContent = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
            } catch {
                throw new Error('The decrypted message is not valid UTF-8 text.');
            }
        } else {
            content.replaceChildren();
            displayFile(sender.display_name, bytes, data.filename, data.file_type, 'received', content);
        }
        item.classList.remove('encrypted-pending');
        item.classList.add('decrypted');
        decryptionStatus.textContent = type === 'message'
            ? 'Message decrypted successfully'
            : 'File decrypted successfully';
        decryptionStatus.className = 'message-security-status success';
        button.textContent = type === 'message' ? 'Decrypted' : 'File decrypted';
        showStatus(type === 'message'
            ? 'Signature successfully verified. Message decrypted successfully.'
            : 'Signature successfully verified. File decrypted successfully.', true);
    } catch (error) {
        await focusPeerForVerification(data?.from_username, error);
        if (!signatureVerified) {
            signatureStatus.textContent = `Signature not verified: ${error.message}`;
            signatureStatus.className = 'message-security-status error';
        }
        decryptionStatus.textContent = `Rejected: ${error.message}`;
        decryptionStatus.className = 'message-security-status error';
        const nextStep = error.code === 'UNVERIFIED_SENDER'
            ? ' Compare and confirm this sender’s fingerprint above, then click Decrypt again.'
            : error.code === 'CHANGED_SENDER_KEY'
                ? ' Do not accept the changed key until you verify it out of band.'
                : '';
        showStatus(`${type === 'message' ? 'Message' : 'File'} rejected: ${error.message}${nextStep}`);
        button.disabled = false;
        return;
    }
    button.disabled = true;
}

async function focusPeerForVerification(username, error) {
    if (!['UNVERIFIED_SENDER', 'CHANGED_SENDER_KEY'].includes(error?.code)) return;
    const sender = users.find((user) => user.username === username);
    if (!sender) return;
    selectedUser = sender;
    document.getElementById('chatWith').textContent = `Chatting with: ${sender.display_name}`;
    try {
        await updatePeerVerification();
    } catch (verificationError) {
        showStatus(`Message was rejected. Could not open sender verification: ${verificationError.message}`);
    }
}

async function encryptPayload(data, recipientPublicJwk) {
    const recipientKey = await crypto.subtle.importKey(
        'jwk',
        recipientPublicJwk,
        { name: 'RSA-OAEP', hash: 'SHA-256' },
        false,
        ['encrypt']
    );
    const aesKey = await crypto.subtle.generateKey(
        { name: 'AES-GCM', length: 256 },
        true,
        ['encrypt', 'decrypt']
    );
    const rawAesKey = await crypto.subtle.exportKey('raw', aesKey);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, data);
    const encryptedKey = await crypto.subtle.encrypt(
        { name: 'RSA-OAEP' },
        recipientKey,
        rawAesKey
    );
    return {
        ciphertext: bytesToBase64(new Uint8Array(ciphertext)),
        encryptedKey: bytesToBase64(new Uint8Array(encryptedKey)),
        iv: bytesToBase64(iv)
    };
}

async function decryptPayload(ciphertext, iv, encryptedKey) {
    if (!keyPair || !ciphertext || !iv || !encryptedKey) {
        throw new Error('Encrypted payload is incomplete.');
    }
    const ivBytes = base64ToBytes(iv);
    const ciphertextBytes = base64ToBytes(ciphertext);
    const encryptedKeyBytes = base64ToBytes(encryptedKey);
    if (ivBytes.length !== 12) throw new Error('The AES-GCM IV must be exactly 12 bytes.');
    if (ciphertextBytes.length < 16) throw new Error('The AES-GCM ciphertext is incomplete.');

    let rawAesKey;
    try {
        rawAesKey = await crypto.subtle.decrypt(
            { name: 'RSA-OAEP' },
            keyPair.privateKey,
            encryptedKeyBytes
        );
    } catch {
        throw new Error('The encrypted message key could not be opened with this account’s private key.');
    }
    if (rawAesKey.byteLength !== 32) throw new Error('The encrypted message key is not a valid AES-256 key.');
    const aesKey = await crypto.subtle.importKey(
        'raw',
        rawAesKey,
        { name: 'AES-GCM' },
        false,
        ['decrypt']
    );
    let plaintext;
    try {
        plaintext = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: ivBytes },
            aesKey,
            ciphertextBytes
        );
    } catch {
        throw new Error('AES-GCM authentication failed; the ciphertext or IV was modified, or the wrong key was used.');
    }
    return new Uint8Array(plaintext);
}

async function sendMessage() {
    const input = document.getElementById('messageInput');
    const message = input.value.trim();
    if (!message || !selectedUser || !socket?.connected) return;

    try {
        const peer = await getVerifiedSelectedPeer();
        const encrypted = await encryptPayload(encoder.encode(message), peer.public_keys.encryption);
        const signedPayload = {
            from_username: myUsername,
            recipient_username: peer.username,
            message_type: 'text',
            encrypted_message: encrypted.ciphertext,
            encrypted_key: encrypted.encryptedKey,
            iv: encrypted.iv
        };
        const signature = await signPayload(signedPayload);
        const relayPayload = {
            recipient_sid: peer.sid,
            recipient_username: peer.username,
            encrypted_message: encrypted.ciphertext,
            encrypted_key: encrypted.encryptedKey,
            iv: encrypted.iv,
            signature,
            message_type: 'text'
        };
        const currentPeer = await getVerifiedSelectedPeer();
        if (currentPeer.sid !== peer.sid || currentPeer.fingerprint !== peer.fingerprint) {
            throw new Error('The selected peer changed while the message was being encrypted.');
        }
        socket.emit('send_message', relayPayload);
        displayMessage('You', message, 'sent', relayPayload);
        input.value = '';
    } catch (error) {
        showStatus(`Message encryption or signing failed: ${error.message}`);
    }
}

async function sendFile() {
    const fileInput = document.getElementById('fileInput');
    const file = fileInput.files[0];
    if (!file || !selectedUser || !socket?.connected) return;
    if (file.size > MAX_FILE_BYTES) {
        showStatus('Files must be 10 MiB or smaller.');
        return;
    }

    try {
        const peer = await getVerifiedSelectedPeer();
        const encrypted = await encryptPayload(
            new Uint8Array(await file.arrayBuffer()),
            peer.public_keys.encryption
        );
        const signedPayload = {
            from_username: myUsername,
            recipient_username: peer.username,
            filename: file.name,
            file_type: file.type || 'application/octet-stream',
            encrypted_file: encrypted.ciphertext,
            encrypted_key: encrypted.encryptedKey,
            iv: encrypted.iv
        };
        const signature = await signPayload(signedPayload);
        const relayPayload = {
            recipient_sid: peer.sid,
            recipient_username: peer.username,
            encrypted_file: encrypted.ciphertext,
            encrypted_key: encrypted.encryptedKey,
            iv: encrypted.iv,
            signature,
            filename: file.name,
            file_type: file.type || 'application/octet-stream'
        };
        const currentPeer = await getVerifiedSelectedPeer();
        if (currentPeer.sid !== peer.sid || currentPeer.fingerprint !== peer.fingerprint) {
            throw new Error('The selected peer changed while the file was being encrypted.');
        }
        socket.emit('send_file', relayPayload);
        displayMessage('You', `[File: ${file.name}]`, 'sent', relayPayload);
        fileInput.value = '';
    } catch (error) {
        showStatus(`File encryption or signing failed: ${error.message}`);
    }
}

function showChat() {
    document.getElementById('choicePanel').style.display = 'none';
    document.getElementById('chatPanel').style.display = 'flex';
    showStatus('Signed in. Verify each peer fingerprint out of band before sending.', true);
}

function showChoices() {
    document.getElementById('chatPanel').style.display = 'none';
    document.getElementById('choicePanel').style.display = 'block';
}

function openDetector() {
    const url = new URL(document.body.dataset.detectorUrl || 'http://127.0.0.1:8502/');
    url.searchParams.set('session', sessionToken);
    window.open(url.toString(), '_blank', 'noopener');
}

async function logout() {
    if (!sessionToken) {
        showStatus('No active app session is available to sign out.');
        return;
    }
    try {
        const response = await fetch('/api/session/revoke', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ token: sessionToken })
        });
        const result = await response.json();
        if (!response.ok || !result.success) {
            showStatus(result.error || 'Could not end the app session.');
            return;
        }
    } catch (error) {
        showStatus(`Could not sign out: ${error.message}`);
        return;
    }
    if (socket) socket.disconnect();
    socket = null;
    keyPair = null;
    signingKeyPair = null;
    myUsername = null;
    sessionToken = null;
    selectedUser = null;
    users = [];
    document.getElementById('chatPanel').style.display = 'none';
    document.getElementById('choicePanel').style.display = 'none';
    document.getElementById('setupPanel').style.display = 'block';
    document.getElementById('generateKeysBtn').disabled = false;
    document.getElementById('registerBtn').disabled = true;
    document.getElementById('keyStatus').textContent = 'Sign out complete. Browser keys remain in this profile.';
    document.getElementById('keyStatus').className = 'status';
    document.getElementById('chatStatus').textContent = '';
}

function displayMessage(sender, message, type, encryptedEnvelope = null) {
    const item = document.createElement('div');
    item.className = `message ${type}`;
    const senderLabel = document.createElement('div');
    senderLabel.className = 'message-info';
    senderLabel.textContent = sender;
    item.append(senderLabel, document.createTextNode(message));
    if (encryptedEnvelope) {
        const details = document.createElement('details');
        details.className = 'encrypted-envelope';
        const summary = document.createElement('summary');
        summary.textContent = 'Encrypted payload sent through the relay';
        const payload = document.createElement('pre');
        payload.textContent = JSON.stringify(encryptedEnvelope, null, 2);
        details.append(summary, payload);
        item.appendChild(details);
    }
    appendMessage(item);
}

function displayFile(sender, bytes, filename, fileType, type, container = document.getElementById('messages')) {
    const item = document.createElement('div');
    item.className = `message ${type}`;
    if (sender) {
        const senderLabel = document.createElement('div');
        senderLabel.className = 'message-info';
        senderLabel.textContent = sender;
        item.appendChild(senderLabel);
    }

    const safeType = typeof fileType === 'string' ? fileType : 'application/octet-stream';
    const fileUrl = URL.createObjectURL(new Blob([bytes], { type: safeType }));
    if (safeType.startsWith('image/')) {
        const image = document.createElement('img');
        image.src = fileUrl;
        image.alt = filename;
        image.style.maxWidth = '200px';
        image.style.maxHeight = '200px';
        item.appendChild(image);
    }
    const link = document.createElement('a');
    link.href = fileUrl;
    link.download = filename || 'download';
    link.textContent = `Download ${filename || 'file'}`;
    item.appendChild(link);
    container.appendChild(item);
}

function appendMessage(item) {
    const messages = document.getElementById('messages');
    messages.appendChild(item);
    messages.scrollTop = messages.scrollHeight;
}

function bytesToBase64(bytes) {
    let binary = '';
    const chunkSize = 0x8000;
    for (let index = 0; index < bytes.length; index += chunkSize) {
        binary += String.fromCharCode(...bytes.subarray(index, index + chunkSize));
    }
    return btoa(binary);
}

function base64ToBytes(value) {
    if (
        typeof value !== 'string'
        || !value.length
        || value.length % 4 !== 0
        || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)
    ) {
        throw new Error('Encrypted data is not valid canonical base64.');
    }
    const binary = atob(value);
    return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function showStatus(message, success = false) {
    const chatPanel = document.getElementById('chatPanel');
    const status = chatPanel.style.display === 'none'
        ? document.getElementById('keyStatus')
        : document.getElementById('chatStatus');
    status.textContent = message;
    status.className = success ? 'status success' : 'status error';
}

function handleMessageSent(result) {
    if (result?.status === 'delivered') {
        showStatus('Encrypted payload sent successfully.', true);
    } else {
        showStatus(result?.error || 'Message was not delivered.');
    }
}

function handleFileSent(result) {
    if (result?.status === 'delivered') {
        showStatus('Encrypted file payload sent successfully.', true);
    } else {
        showStatus(result?.error || 'File was not delivered.');
    }
}
