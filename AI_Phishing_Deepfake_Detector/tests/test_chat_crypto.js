const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');
const { webcrypto } = require('node:crypto');

const projectRoot = path.resolve(__dirname, '..');
const source = fs.readFileSync(
    path.join(projectRoot, 'e2ee_chat', 'static', 'app.js'),
    'utf8'
);
function createClientContext() {
    const elements = new Map();
    const localValues = new Map();
    const missingElements = new Set();
    const emissions = [];
    function element() {
        return {
            children: [],
            listeners: {},
            addEventListener(name, callback) {
                this.listeners[name] = callback;
            },
            click() {
                if (this.disabled) return;
                return this.listeners.click?.();
            },
            appendChild(child) { this.children.push(child); },
            append(...children) { this.children.push(...children); },
            replaceChildren(...children) { this.children = children; },
            style: { display: 'none' },
            classList: { add() {}, remove() {} }
        };
    }
    const document = {
        getElementById(id) {
            if (missingElements.has(id)) return null;
            if (!elements.has(id)) elements.set(id, element());
            return elements.get(id);
        },
        createElement(tagName) {
            const created = element();
            created.tagName = tagName.toUpperCase();
            return created;
        },
        createTextNode(text) {
            return { textContent: text };
        },
        querySelectorAll() {
            return [];
        }
    };
    const localStorage = {
        getItem(key) {
            return localValues.has(key) ? localValues.get(key) : null;
        },
        setItem(key, value) {
            localValues.set(key, value);
        },
        removeItem(key) {
            localValues.delete(key);
        }
    };
    const context = vm.createContext({
        document,
        localStorage,
        testElements: elements,
        testEmissions: emissions,
        testMissingElements: missingElements,
        crypto: webcrypto,
        TextEncoder,
        TextDecoder,
        Uint8Array,
        ArrayBuffer,
        btoa,
        atob,
        Blob,
        URL,
        window: { location: { origin: 'http://127.0.0.1:5001' } },
        fetch: async () => ({
            ok: true,
            json: async () => ({ success: true })
        }),
        console
    });

    vm.runInContext(
        `${source}\nglobalThis.chatCryptoTests = {
            encryptPayload, decryptPayload, bytesToBase64, base64ToBytes,
            signPayload, verifyPayloadSignature, keyFingerprint,
            getVerifiedSelectedPeer, verifyIncoming, handleReceivedMessage,
            handleReceivedFile, verifyLocalKeyPairs, updatePeerVerification,
            saveTrustedPeer, trustSelectedPeer, logout, handleMessageSent, handleFileSent,
            setPrivateKey: (privateKey) => { keyPair = { privateKey }; },
            setSigningKey: (privateKey) => { signingKeyPair = { privateKey }; },
            setSessionToken: (token) => { sessionToken = token; },
            setPeerState: (peer, trustedFingerprint) => {
                myUsername = 'alice';
                users = [peer];
                selectedUser = peer;
                socket = { connected: true };
                localStorage.removeItem('local-e2ee-chat-trusted-peers:alice');
                localStorage.setItem('local-e2ee-chat-trusted-peers',
                    JSON.stringify(trustedFingerprint ? { [peer.username]: trustedFingerprint } : {}));
            },
            setAuthenticatedState: (username, encryptionKeys, signingKeys, onlineUsers, peer) => {
                myUsername = username;
                keyPair = encryptionKeys;
                signingKeyPair = signingKeys;
                users = onlineUsers;
                selectedUser = peer;
                socket = { connected: true, emit: (name, payload) => testEmissions.push({ name, payload }) };
                document.getElementById('chatPanel').style.display = 'flex';
            },
            clearTrustedPeerStore: () => localStorage.removeItem(
                'local-e2ee-chat-trusted-peers:' + normalizedUsername(myUsername)
            ),
            markElementMissing: (id) => {
                testMissingElements.add(id);
                testElements.delete(id);
            },
            emissions: testEmissions,
            disconnectSocket: () => { socket = null; }
        };`,
        context
    );

    function textContent(node) {
        return `${node.textContent || ''}${(node.children || []).map(textContent).join('')}`;
    }
    function findButton(node, label) {
        if (node.tagName === 'BUTTON' && node.textContent === label) return node;
        for (const child of node.children || []) {
            const match = findButton(child, label);
            if (match) return match;
        }
        return null;
    }
    return {
        context,
        elements,
        localValues,
        displayedMessages: () => (elements.get('messages')?.children || []).map(textContent),
        clickButton: (cardIndex, label) => {
            const card = (elements.get('messages')?.children || [])[cardIndex];
            const button = card && findButton(card, label);
            assert.ok(button, `Could not find "${label}" on message card ${cardIndex}`);
            return button.click();
        },
        findButton
    };
}

const client = createClientContext();
const { context } = client;

async function createAuthenticatedConversation() {
    const alice = createClientContext();
    const bob = createClientContext();
    async function createIdentity() {
        const encryption = await webcrypto.subtle.generateKey(
            {
                name: 'RSA-OAEP',
                modulusLength: 2048,
                publicExponent: new Uint8Array([1, 0, 1]),
                hash: 'SHA-256'
            },
            false,
            ['encrypt', 'decrypt']
        );
        const signing = await webcrypto.subtle.generateKey(
            { name: 'ECDSA', namedCurve: 'P-256' },
            false,
            ['sign', 'verify']
        );
        return {
            encryption,
            signing,
            publicKeys: {
                encryption: await webcrypto.subtle.exportKey('jwk', encryption.publicKey),
                signing: await webcrypto.subtle.exportKey('jwk', signing.publicKey)
            }
        };
    }

    const aliceIdentity = await createIdentity();
    const bobIdentity = await createIdentity();
    const aliceApi = alice.context.chatCryptoTests;
    const bobApi = bob.context.chatCryptoTests;
    const alicePeer = {
        username: 'alice',
        display_name: 'alice',
        sid: 'alice-session',
        public_keys: aliceIdentity.publicKeys,
        fingerprint: await aliceApi.keyFingerprint(aliceIdentity.publicKeys)
    };
    const bobPeer = {
        username: 'bob',
        display_name: 'bob',
        sid: 'bob-session',
        public_keys: bobIdentity.publicKeys,
        fingerprint: await bobApi.keyFingerprint(bobIdentity.publicKeys)
    };
    aliceApi.setAuthenticatedState(
        'alice', aliceIdentity.encryption, aliceIdentity.signing, [bobPeer], bobPeer
    );
    bobApi.setAuthenticatedState(
        'bob', bobIdentity.encryption, bobIdentity.signing, [alicePeer], alicePeer
    );
    for (const [client, peer] of [[alice, bobPeer], [bob, alicePeer]]) {
        client.elements.get('peerFingerprintConfirmed').checked = true;
        await client.context.chatCryptoTests.trustSelectedPeer();
        assert.match(
            client.elements.get('peerTrustStatus').textContent,
            new RegExp(`You verified ${peer.username}'s full fingerprint`)
        );
    }
    return { alice, bob, aliceIdentity, bobIdentity, alicePeer, bobPeer };
}

test('AES-GCM and RSA-OAEP round-trip text and binary payloads', async () => {
    const { chatCryptoTests } = context;
    const pair = await webcrypto.subtle.generateKey(
        {
            name: 'RSA-OAEP',
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: 'SHA-256'
        },
        false,
        ['encrypt', 'decrypt']
    );
    const publicJwk = await webcrypto.subtle.exportKey('jwk', pair.publicKey);
    chatCryptoTests.setPrivateKey(pair.privateKey);

    for (const original of [
        new TextEncoder().encode('hello encrypted world'),
        new Uint8Array([0, 1, 127, 128, 254, 255])
    ]) {
        const encrypted = await chatCryptoTests.encryptPayload(original, publicJwk);
        const decrypted = await chatCryptoTests.decryptPayload(
            encrypted.ciphertext,
            encrypted.iv,
            encrypted.encryptedKey
        );
        assert.deepEqual(Array.from(decrypted), Array.from(original));
    }
});

test('AES-GCM rejects modified ciphertext', async () => {
    const { chatCryptoTests } = context;
    const pair = await webcrypto.subtle.generateKey(
        {
            name: 'RSA-OAEP',
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: 'SHA-256'
        },
        false,
        ['encrypt', 'decrypt']
    );
    const publicJwk = await webcrypto.subtle.exportKey('jwk', pair.publicKey);
    chatCryptoTests.setPrivateKey(pair.privateKey);

    const encrypted = await chatCryptoTests.encryptPayload(
        new TextEncoder().encode('must detect tampering'),
        publicJwk
    );
    const bytes = chatCryptoTests.base64ToBytes(encrypted.ciphertext);
    bytes[0] ^= 1;
    const modified = chatCryptoTests.bytesToBase64(bytes);

    await assert.rejects(
        chatCryptoTests.decryptPayload(modified, encrypted.iv, encrypted.encryptedKey)
    );
    await assert.rejects(
        chatCryptoTests.decryptPayload(
            encrypted.ciphertext,
            chatCryptoTests.bytesToBase64(new Uint8Array(8)),
            encrypted.encryptedKey
        ),
        /IV must be exactly 12 bytes/
    );
});

test('stored identity keys are checked against their public keys', async () => {
    const { chatCryptoTests } = context;
    const encryption = await webcrypto.subtle.generateKey(
        {
            name: 'RSA-OAEP',
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: 'SHA-256'
        },
        false,
        ['encrypt', 'decrypt']
    );
    const signing = await webcrypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' },
        false,
        ['sign', 'verify']
    );
    const otherSigning = await webcrypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' },
        false,
        ['sign', 'verify']
    );
    await chatCryptoTests.verifyLocalKeyPairs(encryption, signing);
    await assert.rejects(
        chatCryptoTests.verifyLocalKeyPairs(encryption, {
            privateKey: signing.privateKey,
            publicKey: otherSigning.publicKey
        }),
        /saved signing public key does not match/
    );
});

test('Alice sends ciphertext only and only Bob can decrypt the signed message', async () => {
    const { chatCryptoTests } = context;
    const aliceEncryption = await webcrypto.subtle.generateKey(
        {
            name: 'RSA-OAEP',
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: 'SHA-256'
        },
        false,
        ['encrypt', 'decrypt']
    );
    const bobEncryption = await webcrypto.subtle.generateKey(
        {
            name: 'RSA-OAEP',
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: 'SHA-256'
        },
        false,
        ['encrypt', 'decrypt']
    );
    const aliceSigning = await webcrypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' },
        false,
        ['sign', 'verify']
    );
    const bobPublicJwk = await webcrypto.subtle.exportKey('jwk', bobEncryption.publicKey);
    const aliceSigningPublicJwk = await webcrypto.subtle.exportKey('jwk', aliceSigning.publicKey);
    const plaintext = 'Please send me the assignment.';
    chatCryptoTests.setPrivateKey(bobEncryption.privateKey);
    chatCryptoTests.setSigningKey(aliceSigning.privateKey);

    const encrypted = await chatCryptoTests.encryptPayload(
        new TextEncoder().encode(plaintext),
        bobPublicJwk
    );
    const signedPayload = {
        from_username: 'alice',
        recipient_username: 'bob',
        message_type: 'text',
        encrypted_message: encrypted.ciphertext,
        encrypted_key: encrypted.encryptedKey,
        iv: encrypted.iv
    };
    const signature = await chatCryptoTests.signPayload(signedPayload);
    const relayEnvelope = JSON.stringify({ ...signedPayload, signature });

    assert.equal(relayEnvelope.includes(plaintext), false);
    assert.equal(
        await chatCryptoTests.verifyPayloadSignature(
            signedPayload,
            signature,
            aliceSigningPublicJwk
        ),
        true
    );
    chatCryptoTests.setPrivateKey(aliceEncryption.privateKey);
    await assert.rejects(
        chatCryptoTests.decryptPayload(
            encrypted.ciphertext,
            encrypted.iv,
            encrypted.encryptedKey
        ),
        /could not be opened with this account’s private key/
    );
    chatCryptoTests.setPrivateKey(bobEncryption.privateKey);
    const decrypted = await chatCryptoTests.decryptPayload(
        encrypted.ciphertext,
        encrypted.iv,
        encrypted.encryptedKey
    );
    assert.equal(new TextDecoder().decode(decrypted), plaintext);
});

test('messages stay encrypted until each receiver clicks Decrypt Message', async () => {
    const { alice, bob } = await createAuthenticatedConversation();
    const plaintext = 'Hello John, how are you?';
    const aliceApi = alice.context.chatCryptoTests;
    const bobApi = bob.context.chatCryptoTests;
    alice.elements.get('messageInput').value = plaintext;

    await alice.context.sendMessage();
    const sent = aliceApi.emissions.find((event) => event.name === 'send_message');
    assert.ok(sent);
    assert.equal(JSON.stringify(sent.payload).includes(plaintext), false);
    assert.equal(sent.payload.recipient_sid, 'bob-session');

    const relayed = {
        ...sent.payload,
        from_sid: 'alice-session',
        from_username: 'alice',
        from_user: 'alice',
        recipient_username: 'bob'
    };
    bobApi.handleReceivedMessage(relayed);
    assert.equal(bob.displayedMessages().some((message) => message.includes(plaintext)), false);
    assert.match(bob.elements.get('chatStatus').textContent, /Encrypted message received from alice/);
    assert.ok(bob.findButton(bob.elements.get('messages').children[0], 'Decrypt Message'));
    assert.match(bob.displayedMessages()[0], /Message content is hidden until you decrypt it/);

    await bob.clickButton(0, 'Decrypt Message');
    assert.ok(bob.displayedMessages().some((message) => message.includes(plaintext)));
    assert.match(bob.displayedMessages()[0], /Signature successfully verified/);
    assert.match(bob.displayedMessages()[0], /Message decrypted successfully/);
    assert.match(bob.elements.get('chatStatus').textContent, /Signature successfully verified\. Message decrypted successfully/);

    bob.elements.get('messageInput').value = 'Hello Alice, I verified and decrypted your message.';
    await bob.context.sendMessage();
    const replies = bobApi.emissions.filter((event) => event.name === 'send_message');
    const reply = replies[replies.length - 1];
    assert.ok(reply);
    assert.equal(JSON.stringify(reply.payload).includes('Hello Alice'), false);
    aliceApi.handleReceivedMessage({
        ...reply.payload,
        from_sid: 'bob-session',
        from_username: 'bob',
        recipient_username: 'alice'
    });
    assert.equal(alice.displayedMessages().some((message) => message.includes('Hello Alice')), false);
    await alice.clickButton(1, 'Decrypt Message');
    assert.ok(alice.displayedMessages().some(
        (message) => message.includes('Hello Alice, I verified and decrypted your message.')
    ));
    assert.match(alice.elements.get('chatStatus').textContent, /Signature successfully verified\. Message decrypted successfully/);
});

test('an invalid message signature is rejected before plaintext is displayed', async () => {
    const { alice, bob } = await createAuthenticatedConversation();
    alice.elements.get('messageInput').value = 'Never show this without a valid signature.';
    await alice.context.sendMessage();
    const sent = alice.context.chatCryptoTests.emissions.find((event) => event.name === 'send_message');
    const signature = bob.context.chatCryptoTests.base64ToBytes(sent.payload.signature);
    signature[0] ^= 1;
    bob.context.chatCryptoTests.handleReceivedMessage({
        ...sent.payload,
        signature: bob.context.chatCryptoTests.bytesToBase64(signature),
        from_sid: 'alice-session',
        from_username: 'alice',
        recipient_username: 'bob'
    });

    assert.equal(bob.displayedMessages().some((message) => message.includes('Never show this')), false);
    await bob.clickButton(0, 'Decrypt Message');
    assert.equal(bob.displayedMessages().some((message) => message.includes('Never show this')), false);
    assert.match(bob.elements.get('chatStatus').textContent, /signature is invalid/);
});

test('multiple incoming messages have separate buttons and reveal only the selected message', async () => {
    const { alice, bob } = await createAuthenticatedConversation();
    const aliceApi = alice.context.chatCryptoTests;
    const bobApi = bob.context.chatCryptoTests;
    const messages = ['First private message', 'Second private message'];

    for (const plaintext of messages) {
        alice.elements.get('messageInput').value = plaintext;
        await alice.context.sendMessage();
        const sent = aliceApi.emissions.filter((event) => event.name === 'send_message').slice(-1)[0];
        bobApi.handleReceivedMessage({
            ...sent.payload,
            from_sid: 'alice-session',
            from_username: 'alice',
            recipient_username: 'bob'
        });
    }

    assert.equal(bob.elements.get('messages').children.length, 2);
    assert.deepEqual(bob.displayedMessages().map((message) => messages.some((text) => message.includes(text))), [false, false]);
    await bob.clickButton(0, 'Decrypt Message');
    assert.ok(bob.displayedMessages()[0].includes(messages[0]));
    assert.equal(bob.displayedMessages()[1].includes(messages[1]), false);
    await bob.clickButton(1, 'Decrypt Message');
    assert.ok(bob.displayedMessages()[1].includes(messages[1]));
});

test('a wrong recipient private key never reveals plaintext after signature verification', async () => {
    const { alice, bob } = await createAuthenticatedConversation();
    const plaintext = 'Wrong-key plaintext remains hidden.';
    alice.elements.get('messageInput').value = plaintext;
    await alice.context.sendMessage();
    const sent = alice.context.chatCryptoTests.emissions.find((event) => event.name === 'send_message');
    const wrongEncryptionKeys = await webcrypto.subtle.generateKey(
        {
            name: 'RSA-OAEP',
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: 'SHA-256'
        },
        false,
        ['encrypt', 'decrypt']
    );
    bob.context.chatCryptoTests.setPrivateKey(wrongEncryptionKeys);
    bob.context.chatCryptoTests.handleReceivedMessage({
        ...sent.payload,
        from_sid: 'alice-session',
        from_username: 'alice',
        recipient_username: 'bob'
    });

    const decryptButton = bob.findButton(bob.elements.get('messages').children[0], 'Decrypt Message');
    const firstAttempt = decryptButton.click();
    assert.equal(decryptButton.disabled, true);
    decryptButton.listeners.click();
    await firstAttempt;

    assert.equal(bob.displayedMessages().some((message) => message.includes(plaintext)), false);
    assert.match(bob.displayedMessages()[0], /Signature successfully verified/);
    assert.match(bob.displayedMessages()[0], /could not be opened with this account’s private key/);
    assert.equal(decryptButton.disabled, false);
});

test('incoming files remain hidden until Decrypt File is clicked', async () => {
    const { alice, bob } = await createAuthenticatedConversation();
    const plaintext = 'encrypted-file-content';
    const file = new Blob([plaintext], { type: 'text/plain' });
    file.name = 'message.txt';
    alice.elements.get('fileInput').files = [file];
    await alice.context.sendFile();
    const sent = alice.context.chatCryptoTests.emissions.find((event) => event.name === 'send_file');
    assert.ok(sent);
    assert.equal(JSON.stringify(sent.payload).includes(plaintext), false);
    bob.context.chatCryptoTests.handleReceivedFile({
        ...sent.payload,
        from_sid: 'alice-session',
        from_username: 'alice',
        from_user: 'alice',
        recipient_username: 'bob'
    });

    assert.equal(bob.displayedMessages().some((message) => message.includes('Download message.txt')), false);
    assert.match(bob.displayedMessages()[0], /File content is hidden until you decrypt it/);
    assert.ok(bob.findButton(bob.elements.get('messages').children[0], 'Decrypt File'));
    await bob.clickButton(0, 'Decrypt File');

    assert.match(bob.displayedMessages()[0], /Download message\.txt/);
    assert.match(bob.displayedMessages()[0], /File decrypted successfully/);
    assert.match(bob.elements.get('chatStatus').textContent, /Signature successfully verified\. File decrypted successfully/);
});

test('send acknowledgements describe encrypted payload delivery', () => {
    const { chatCryptoTests } = context;
    const status = context.document.getElementById('chatStatus');
    context.document.getElementById('chatPanel').style.display = 'flex';

    chatCryptoTests.handleMessageSent({ status: 'delivered' });
    assert.equal(status.textContent, 'Encrypted payload sent successfully.');
    chatCryptoTests.handleFileSent({ status: 'delivered' });
    assert.equal(status.textContent, 'Encrypted file payload sent successfully.');
});

test('one user trust pin does not trust the sender for the receiving account', async () => {
    const { alice, bob, alicePeer } = await createAuthenticatedConversation();
    const plaintext = 'Untrusted content stays hidden until Bob confirms Alice.';
    alice.elements.get('messageInput').value = plaintext;
    await alice.context.sendMessage();
    const sent = alice.context.chatCryptoTests.emissions.find((event) => event.name === 'send_message');
    bob.context.chatCryptoTests.clearTrustedPeerStore();

    const relayed = {
        ...sent.payload,
        from_sid: 'alice-session',
        from_username: 'alice',
        recipient_username: 'bob'
    };
    await assert.doesNotReject(alice.context.chatCryptoTests.getVerifiedSelectedPeer());

    bob.context.chatCryptoTests.handleReceivedMessage(relayed);

    assert.equal(bob.displayedMessages().some((message) => message.includes(plaintext)), false);
    await bob.clickButton(0, 'Decrypt Message');
    assert.equal(bob.displayedMessages().some((message) => message.includes(plaintext)), false);
    assert.match(bob.elements.get('chatStatus').textContent, /not been independently verified/);
    assert.match(bob.elements.get('chatStatus').textContent, /not been independently verified for bob/);
    assert.equal(bob.elements.get('peerVerification').style.display, 'block');
    assert.equal(bob.elements.get('peerFingerprint').textContent, alicePeer.fingerprint);
    assert.match(bob.elements.get('peerTrustStatus').textContent, /bob.*http:\/\/127\.0\.0\.1:5001/);

    bob.elements.get('peerFingerprintConfirmed').checked = true;
    await bob.context.chatCryptoTests.trustSelectedPeer();
    assert.match(bob.elements.get('peerTrustStatus').textContent, /You verified alice's full fingerprint/);
    await bob.clickButton(0, 'Decrypt Message');
    assert.ok(bob.displayedMessages().some((message) => message.includes(plaintext)));
    assert.match(bob.elements.get('chatStatus').textContent, /Signature successfully verified\. Message decrypted successfully/);
});

test('saving trust updates the panel when an older page lacks the optional scope element', async () => {
    const { alice, bob, alicePeer } = await createAuthenticatedConversation();
    bob.context.chatCryptoTests.clearTrustedPeerStore();
    bob.context.chatCryptoTests.markElementMissing('peerTrustScope');
    bob.elements.get('peerFingerprintConfirmed').checked = true;
    await assert.doesNotReject(bob.context.chatCryptoTests.trustSelectedPeer());

    assert.match(bob.elements.get('peerTrustStatus').textContent, /You verified alice's full fingerprint/);
    assert.match(bob.elements.get('peerTrustStatus').textContent, /http:\/\/127\.0\.0\.1:5001/);
    assert.equal(bob.elements.get('sendBtn').disabled, false);
    await assert.doesNotReject(bob.context.chatCryptoTests.getVerifiedSelectedPeer());
    assert.equal(bob.elements.get('peerFingerprint').textContent, alicePeer.fingerprint);
    assert.ok(alice.elements.get('peerTrustStatus').textContent);
});

test('a tampered ciphertext with a recomputed signature still fails AES-GCM authentication', async () => {
    const { alice, bob } = await createAuthenticatedConversation();
    const plaintext = 'Do not display modified ciphertext.';
    alice.elements.get('messageInput').value = plaintext;
    await alice.context.sendMessage();
    const sent = alice.context.chatCryptoTests.emissions.find((event) => event.name === 'send_message');
    const tampered = { ...sent.payload };
    const bytes = alice.context.chatCryptoTests.base64ToBytes(tampered.encrypted_message);
    bytes[0] ^= 1;
    tampered.encrypted_message = alice.context.chatCryptoTests.bytesToBase64(bytes);
    tampered.signature = await alice.context.chatCryptoTests.signPayload({
        from_username: 'alice',
        recipient_username: 'bob',
        message_type: 'text',
        encrypted_message: tampered.encrypted_message,
        encrypted_key: tampered.encrypted_key,
        iv: tampered.iv
    });

    bob.context.chatCryptoTests.handleReceivedMessage({
        ...tampered,
        from_sid: 'alice-session',
        from_username: 'alice',
        recipient_username: 'bob'
    });
    assert.equal(bob.displayedMessages().some((message) => message.includes(plaintext)), false);
    await bob.clickButton(0, 'Decrypt Message');
    assert.equal(bob.displayedMessages().some((message) => message.includes(plaintext)), false);
    assert.match(bob.elements.get('chatStatus').textContent, /AES-GCM authentication failed/);
});

test('a changed sender public key is rejected without replacing the saved trust pin', async () => {
    const { alice, bob, bobIdentity, alicePeer } = await createAuthenticatedConversation();
    alice.elements.get('messageInput').value = 'Changed-key message must not display.';
    await alice.context.sendMessage();
    const sent = alice.context.chatCryptoTests.emissions.find((event) => event.name === 'send_message');
    const replacementSigning = await webcrypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' },
        false,
        ['sign', 'verify']
    );
    const replacementKeys = {
        ...alicePeer.public_keys,
        signing: await webcrypto.subtle.exportKey('jwk', replacementSigning.publicKey)
    };
    const changedPeer = {
        ...alicePeer,
        public_keys: replacementKeys,
        fingerprint: await bob.context.chatCryptoTests.keyFingerprint(replacementKeys)
    };
    bob.context.chatCryptoTests.setAuthenticatedState(
        'bob',
        bobIdentity.encryption,
        bobIdentity.signing,
        [changedPeer],
        changedPeer
    );
    bob.context.chatCryptoTests.handleReceivedMessage({
        ...sent.payload,
        from_sid: 'alice-session',
        from_username: 'alice',
        recipient_username: 'bob'
    });

    assert.equal(bob.displayedMessages().some((message) => message.includes('Changed-key message')), false);
    await bob.clickButton(0, 'Decrypt Message');
    assert.equal(bob.displayedMessages().some((message) => message.includes('Changed-key message')), false);
    assert.match(bob.elements.get('chatStatus').textContent, /changed since it was verified/);
});

test('trusted fingerprints are isolated by signed-in account', async () => {
    const { chatCryptoTests } = context;
    const keys = {
        encryption: { kty: 'RSA', n: 'modulus', e: 'AQAB' },
        signing: { kty: 'EC', crv: 'P-256', x: 'first', y: 'point' }
    };
    const peer = {
        username: 'carol',
        sid: 'carol-session',
        public_keys: keys,
        fingerprint: await chatCryptoTests.keyFingerprint(keys)
    };
    chatCryptoTests.setAuthenticatedState('alice', {}, {}, [peer], peer);
    chatCryptoTests.saveTrustedPeer('carol', peer.fingerprint);
    chatCryptoTests.setAuthenticatedState('bob', {}, {}, [peer], peer);

    await assert.rejects(
        chatCryptoTests.getVerifiedSelectedPeer(),
        /Verify this peer’s current fingerprint/
    );
});

test('ECDSA signatures authenticate the sender and reject altered message fields', async () => {
    const { chatCryptoTests } = context;
    const pair = await webcrypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' },
        false,
        ['sign', 'verify']
    );
    const publicJwk = await webcrypto.subtle.exportKey('jwk', pair.publicKey);
    chatCryptoTests.setSigningKey(pair.privateKey);
    const signed = {
        from_username: 'alice',
        recipient_username: 'bob',
        message_type: 'text',
        encrypted_message: 'ciphertext',
        encrypted_key: 'wrapped-key',
        iv: 'nonce'
    };
    const signature = await chatCryptoTests.signPayload(signed);

    assert.equal(
        await chatCryptoTests.verifyPayloadSignature(signed, signature, publicJwk),
        true
    );
    assert.equal(
        await chatCryptoTests.verifyPayloadSignature(
            { ...signed, encrypted_message: 'changed-ciphertext' },
            signature,
            publicJwk
        ),
        false
    );
});

test('ECDSA file signatures cover filenames and recipient identity', async () => {
    const { chatCryptoTests } = context;
    const pair = await webcrypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' },
        false,
        ['sign', 'verify']
    );
    const publicJwk = await webcrypto.subtle.exportKey('jwk', pair.publicKey);
    chatCryptoTests.setSigningKey(pair.privateKey);
    const signed = {
        from_username: 'alice',
        recipient_username: 'bob',
        filename: 'report.pdf',
        file_type: 'application/pdf',
        encrypted_file: 'ciphertext',
        encrypted_key: 'wrapped-key',
        iv: 'nonce'
    };
    const signature = await chatCryptoTests.signPayload(signed);

    assert.equal(
        await chatCryptoTests.verifyPayloadSignature(signed, signature, publicJwk),
        true
    );
    assert.equal(
        await chatCryptoTests.verifyPayloadSignature(
            { ...signed, filename: 'other.pdf' },
            signature,
            publicJwk
        ),
        false
    );
});

test('public-key fingerprint changes when a signing key changes', async () => {
    const { chatCryptoTests } = context;
    const keys = {
        encryption: { kty: 'RSA', n: 'modulus', e: 'AQAB' },
        signing: { kty: 'EC', crv: 'P-256', x: 'first', y: 'point' }
    };
    const first = await chatCryptoTests.keyFingerprint(keys);
    const changed = await chatCryptoTests.keyFingerprint({
        ...keys,
        signing: { ...keys.signing, x: 'changed' }
    });

    assert.notEqual(first, changed);
});

test('sending is blocked until the current peer fingerprint is pinned', async () => {
    const { chatCryptoTests } = context;
    const keys = {
        encryption: { kty: 'RSA', n: 'modulus', e: 'AQAB' },
        signing: { kty: 'EC', crv: 'P-256', x: 'first', y: 'point' }
    };
    const peer = {
        username: 'bob',
        sid: 'bob-session',
        public_keys: keys,
        fingerprint: await chatCryptoTests.keyFingerprint(keys)
    };
    chatCryptoTests.setPeerState(peer, null);
    await assert.rejects(
        chatCryptoTests.getVerifiedSelectedPeer(),
        /Verify this peer’s current fingerprint/
    );

    chatCryptoTests.setPeerState(peer, peer.fingerprint);
    assert.equal(await chatCryptoTests.getVerifiedSelectedPeer(), peer);

    peer.public_keys = {
        ...keys,
        signing: { ...keys.signing, x: 'changed' }
    };
    await assert.rejects(
        chatCryptoTests.getVerifiedSelectedPeer(),
        /Verify this peer’s current fingerprint/
    );
});

test('sign out revokes the app session and resets local controls', async () => {
    const { chatCryptoTests } = context;
    const keyButton = context.document.getElementById('generateKeysBtn');
    const registerButton = context.document.getElementById('registerBtn');
    const setupPanel = context.document.getElementById('setupPanel');
    const chatPanel = context.document.getElementById('chatPanel');
    chatCryptoTests.setSessionToken('a'.repeat(43));
    keyButton.disabled = true;
    registerButton.disabled = false;
    setupPanel.style.display = 'none';
    chatPanel.style.display = 'flex';

    chatCryptoTests.disconnectSocket();
    await chatCryptoTests.logout();

    assert.equal(keyButton.disabled, false);
    assert.equal(registerButton.disabled, true);
    assert.equal(setupPanel.style.display, 'block');
    assert.equal(chatPanel.style.display, 'none');
});
