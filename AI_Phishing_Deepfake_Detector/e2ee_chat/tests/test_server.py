import base64
import importlib.util
import io
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path


SERVER_PATH = Path(__file__).resolve().parents[1] / 'server' / 'app.py'
SPEC = importlib.util.spec_from_file_location('e2ee_server_app', SERVER_PATH)
server = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(server)


def public_keys(seed='A'):
    modulus = bytes([0x80]) + bytes([0x31]) * 254 + b'\x01'
    return {
        'encryption': {
            'kty': 'RSA',
            'alg': 'RSA-OAEP-256',
            'n': base64.urlsafe_b64encode(modulus).decode().rstrip('='),
            'e': 'AQAB',
            'key_ops': ['encrypt'],
            'ext': True,
        },
        'signing': {
            'kty': 'EC',
            'crv': 'P-256',
            'x': seed * 43,
            'y': 'B' * 43,
            'key_ops': ['verify'],
            'ext': True,
        },
    }


def authenticate(client, username, mode='create', password='correct horse battery staple', keys=None):
    client.emit('register', {
        'mode': mode,
        'username': username,
        'password': password,
        'public_keys': keys or public_keys(),
    })
    return next(
        event['args'][0]
        for event in client.get_received()
        if event['name'] == 'user_registered'
    )


class ChatRelayTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.previous_database = server.app.config['DATABASE']
        server.app.config['DATABASE'] = str(Path(self.temporary_directory.name) / 'accounts.sqlite3')
        server.users.clear()
        self.sender = server.socketio.test_client(server.app)
        self.recipient = server.socketio.test_client(server.app)
        self.sender_keys = public_keys('C')
        self.recipient_keys = public_keys('D')
        self.assertTrue(authenticate(self.sender, 'sender', keys=self.sender_keys)['success'])
        self.assertTrue(authenticate(self.recipient, 'recipient', keys=self.recipient_keys)['success'])
        self.recipient_sid = next(
            user['sid'] for user in server.get_user_list() if user['username'] == 'recipient'
        )

    def tearDown(self):
        if self.sender.is_connected():
            self.sender.disconnect()
        if self.recipient.is_connected():
            self.recipient.disconnect()
        server.users.clear()
        server.app.config['DATABASE'] = self.previous_database
        self.temporary_directory.cleanup()

    def test_authenticated_message_and_file_ciphertext_are_relayed(self):
        self.sender.emit('send_message', {
            'recipient_sid': self.recipient_sid,
            'recipient_username': 'recipient',
            'encrypted_message': 'ciphertext',
            'encrypted_key': 'wrapped-key',
            'iv': 'nonce',
            'signature': 'signature',
            'message_type': 'text',
        })
        received_message = next(
            event for event in self.recipient.get_received()
            if event['name'] == 'receive_message'
        )
        self.assertEqual(received_message['args'][0]['encrypted_message'], 'ciphertext')
        self.assertEqual(received_message['args'][0]['encrypted_key'], 'wrapped-key')
        self.assertEqual(received_message['args'][0]['iv'], 'nonce')
        self.assertEqual(received_message['args'][0]['from_username'], 'sender')
        self.assertEqual(received_message['args'][0]['signature'], 'signature')

        self.sender.emit('send_file', {
            'recipient_sid': self.recipient_sid,
            'recipient_username': 'recipient',
            'encrypted_file': 'encrypted-bytes',
            'encrypted_key': 'wrapped-key',
            'iv': 'nonce',
            'signature': 'file-signature',
            'filename': 'sample.bin',
            'file_type': 'application/octet-stream',
        })
        received_file = next(
            event for event in self.recipient.get_received()
            if event['name'] == 'receive_file'
        )
        self.assertEqual(received_file['args'][0]['encrypted_file'], 'encrypted-bytes')
        self.assertEqual(received_file['args'][0]['encrypted_key'], 'wrapped-key')
        self.assertEqual(received_file['args'][0]['iv'], 'nonce')
        self.assertEqual(received_file['args'][0]['signature'], 'file-signature')

    def test_relay_rejects_plaintext_and_private_key_fields(self):
        self.sender.emit('send_message', {
            'recipient_sid': self.recipient_sid,
            'recipient_username': 'recipient',
            'encrypted_message': 'ciphertext',
            'encrypted_key': 'wrapped-key',
            'iv': 'nonce',
            'signature': 'signature',
            'message_type': 'text',
            'plaintext': 'must not reach the relay',
            'private_key': 'must not reach the relay',
        })
        result = next(
            event['args'][0]
            for event in self.sender.get_received()
            if event['name'] == 'message_sent'
        )
        self.assertEqual(result['status'], 'failed')
        self.assertFalse(any(
            event['name'] == 'receive_message'
            for event in self.recipient.get_received()
        ))

        self.sender.emit('send_file', {
            'recipient_sid': self.recipient_sid,
            'recipient_username': 'recipient',
            'encrypted_file': 'encrypted-bytes',
            'encrypted_key': 'wrapped-key',
            'iv': 'nonce',
            'signature': 'file-signature',
            'filename': 'sample.bin',
            'file_type': 'application/octet-stream',
            'file_plaintext': 'must not reach the relay',
        })
        result = next(
            event['args'][0]
            for event in self.sender.get_received()
            if event['name'] == 'file_sent'
        )
        self.assertEqual(result['status'], 'failed')
        self.assertFalse(any(
            event['name'] == 'receive_file'
            for event in self.recipient.get_received()
        ))

    def test_password_authentication_and_public_key_binding_are_enforced(self):
        wrong_password = server.socketio.test_client(server.app)
        self.addCleanup(wrong_password.disconnect)
        active_sessions = len(server.users)
        result = authenticate(
            wrong_password,
            'sender',
            mode='login',
            password='wrong password value',
            keys=self.sender_keys,
        )
        self.assertFalse(result['success'])
        self.assertEqual(result['error'], 'Invalid username or password.')
        self.assertEqual(len(server.users), active_sessions)

        missing_key = server.socketio.test_client(server.app)
        self.addCleanup(missing_key.disconnect)
        result = authenticate(
            missing_key,
            'sender',
            mode='login',
            keys=public_keys('E'),
        )
        self.assertFalse(result['success'])
        self.assertIn('encryption keys', result['error'])
        self.assertEqual(len(server.users), active_sessions)

    def test_account_persists_and_duplicate_registration_is_rejected(self):
        duplicate = server.socketio.test_client(server.app)
        self.addCleanup(duplicate.disconnect)
        result = authenticate(duplicate, 'sender', keys=self.sender_keys)
        self.assertFalse(result['success'])
        self.assertIn('already exists', result['error'])

        self.sender.disconnect()
        replacement = server.socketio.test_client(server.app)
        self.addCleanup(replacement.disconnect)
        result = authenticate(
            replacement,
            'sender',
            mode='login',
            keys=self.sender_keys,
        )
        self.assertTrue(result['success'])
        self.assertEqual(result['username'], 'sender')

    def test_portal_session_can_validate_and_be_revoked(self):
        client = server.socketio.test_client(server.app)
        self.addCleanup(client.disconnect)
        result = authenticate(client, 'portal-user', keys=public_keys('H'))
        self.assertTrue(result['success'])
        token = result['session_token']

        http_client = server.app.test_client()
        response = http_client.post('/api/session/validate', json={'token': token})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()['username'], 'portal-user')

        response = http_client.post('/api/session/revoke', json={'token': token})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.get_json()['success'])
        response = http_client.post('/api/session/validate', json={'token': token})
        self.assertEqual(response.status_code, 401)

    def test_invalid_registration_and_unregistered_sender_are_rejected(self):
        unregistered = server.socketio.test_client(server.app)
        self.addCleanup(unregistered.disconnect)
        unregistered.emit('register', {
            'mode': 'create',
            'username': 'bad',
            'password': 'short',
            'public_keys': {},
        })
        registration = next(
            event for event in unregistered.get_received()
            if event['name'] == 'user_registered'
        )
        self.assertFalse(registration['args'][0]['success'])

        unregistered.emit('send_message', {
            'recipient_sid': self.recipient_sid,
            'recipient_username': 'recipient',
            'encrypted_message': 'ciphertext',
            'encrypted_key': 'wrapped-key',
            'iv': 'nonce',
            'signature': 'signature',
        })
        rejected = next(
            event for event in unregistered.get_received()
            if event['name'] == 'message_sent'
        )
        self.assertEqual(rejected['args'][0]['status'], 'failed')

    def test_unauthenticated_connections_cannot_enumerate_or_receive_user_lists(self):
        visitor = server.socketio.test_client(server.app)
        self.addCleanup(visitor.disconnect)
        visitor.get_received()

        visitor.emit('get_users')
        user_list = next(
            event['args'][0]
            for event in visitor.get_received()
            if event['name'] == 'user_list'
        )
        self.assertEqual(user_list, [])

        visitor.emit('send_message', {
            'recipient_sid': self.recipient_sid,
            'recipient_username': 'recipient',
            'encrypted_message': 'ciphertext',
            'encrypted_key': 'wrapped-key',
            'iv': 'nonce',
            'signature': 'signature',
        })
        self.assertEqual(
            next(
                event['args'][0]['status']
                for event in visitor.get_received()
                if event['name'] == 'message_sent'
            ),
            'failed',
        )
        self.sender.emit('send_message', {
            'recipient_sid': self.recipient_sid,
            'recipient_username': 'recipient',
            'encrypted_message': 'ciphertext',
            'encrypted_key': 'wrapped-key',
            'iv': 'nonce',
            'signature': 'signature',
        })
        self.assertFalse(any(
            event['name'] == 'receive_message'
            for event in visitor.get_received()
        ))

        new_user = server.socketio.test_client(server.app)
        self.addCleanup(new_user.disconnect)
        self.assertTrue(authenticate(new_user, 'new-user', keys=public_keys('G'))['success'])
        self.assertFalse(any(
            event['name'] == 'user_list'
            for event in visitor.get_received()
        ))

    def test_invalid_and_private_public_key_material_is_rejected(self):
        invalid = server.socketio.test_client(server.app)
        self.addCleanup(invalid.disconnect)
        private_keys = public_keys()
        private_keys['encryption']['d'] = 'private-material'
        result = authenticate(invalid, 'private-key-user', keys=private_keys)
        self.assertFalse(result['success'])

    def test_recipient_binding_and_missing_signatures_are_rejected(self):
        self.sender.emit('send_message', {
            'recipient_sid': self.recipient_sid,
            'recipient_username': 'someone-else',
            'encrypted_message': 'ciphertext',
            'encrypted_key': 'wrapped-key',
            'iv': 'nonce',
            'signature': 'signature',
        })
        result = next(
            event for event in self.sender.get_received()
            if event['name'] == 'message_sent'
        )
        self.assertEqual(result['args'][0]['status'], 'failed')

        self.sender.emit('send_message', {
            'recipient_sid': self.recipient_sid,
            'recipient_username': 'recipient',
            'encrypted_message': 'ciphertext',
            'encrypted_key': 'wrapped-key',
            'iv': 'nonce',
        })
        result = next(
            event for event in self.sender.get_received()
            if event['name'] == 'message_sent'
        )
        self.assertEqual(result['args'][0]['status'], 'failed')

    def test_oversized_file_is_rejected(self):
        self.sender.emit('send_file', {
            'recipient_sid': self.recipient_sid,
            'recipient_username': 'recipient',
            'encrypted_file': 'x' * (server.MAX_ENCRYPTED_FILE_CHARS + 1),
            'encrypted_key': 'wrapped-key',
            'iv': 'nonce',
            'signature': 'signature',
            'filename': 'large.bin',
            'file_type': 'application/octet-stream',
        })
        result = next(
            event for event in self.sender.get_received()
            if event['name'] == 'file_sent'
        )
        self.assertEqual(result['args'][0]['status'], 'failed')

    def test_connection_logs_do_not_include_session_or_user_identifiers(self):
        output = io.StringIO()
        with redirect_stdout(output):
            client = server.socketio.test_client(server.app)
            client.emit('register', {
                'mode': 'create',
                'username': 'private-user',
                'password': 'correct horse battery staple',
                'public_keys': public_keys('F'),
            })
            client.disconnect()

        self.assertNotIn('private-user', output.getvalue())
        self.assertNotIn('correct horse battery staple', output.getvalue())


if __name__ == '__main__':
    unittest.main()
