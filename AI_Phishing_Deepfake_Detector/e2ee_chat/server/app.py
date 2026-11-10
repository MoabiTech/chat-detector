#!/usr/bin/env python3
"""Loopback-only E2EE chat relay with local account and public-key binding."""

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
from contextlib import closing
from datetime import datetime, timedelta, timezone

from flask import Flask, jsonify, render_template, request
from flask_socketio import SocketIO, emit

app = Flask(__name__, template_folder='../templates', static_folder='../static')
app.config['SECRET_KEY'] = os.urandom(24)
app.config['DATABASE'] = os.environ.get(
    'E2EE_CHAT_DATABASE',
    os.path.join(os.path.dirname(__file__), 'chat_users.sqlite3'),
)
socketio = SocketIO(app, async_mode='threading', max_http_buffer_size=16 * 1024 * 1024)

users = {}
MAX_ENCRYPTED_FILE_CHARS = 15 * 1024 * 1024
MAX_ENCRYPTED_MESSAGE_CHARS = 64 * 1024
MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_BYTES = 1024
_USERNAME_PATTERN = re.compile(r'^[A-Za-z0-9_.-]{3,32}$')
_RSA_PRIVATE_FIELDS = {'d', 'p', 'q', 'dp', 'dq', 'qi', 'oth'}


def _database_connection():
    connection = sqlite3.connect(app.config['DATABASE'], timeout=5)
    connection.row_factory = sqlite3.Row
    connection.execute(
        '''
        CREATE TABLE IF NOT EXISTS accounts (
            username TEXT PRIMARY KEY COLLATE NOCASE,
            password_salt BLOB NOT NULL,
            password_hash BLOB NOT NULL,
            public_keys_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        '''
    )
    connection.execute(
        '''
        CREATE TABLE IF NOT EXISTS portal_sessions (
            token_hash TEXT PRIMARY KEY,
            username TEXT NOT NULL COLLATE NOCASE,
            expires_at TEXT NOT NULL,
            revoked INTEGER NOT NULL DEFAULT 0
        )
        '''
    )
    connection.commit()
    return connection


def _decode_jwk_integer(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9_-]+', value):
        return None
    try:
        return int.from_bytes(
            base64.urlsafe_b64decode(value + '=' * (-len(value) % 4)),
            'big',
        )
    except (ValueError, base64.binascii.Error):
        return None


def _valid_public_keys(public_keys):
    if not isinstance(public_keys, dict) or set(public_keys) != {'encryption', 'signing'}:
        return False
    encryption_key = public_keys['encryption']
    signing_key = public_keys['signing']
    if (
        not isinstance(encryption_key, dict)
        or encryption_key.get('kty') != 'RSA'
        or encryption_key.get('alg') != 'RSA-OAEP-256'
        or _RSA_PRIVATE_FIELDS.intersection(encryption_key)
    ):
        return False
    modulus = _decode_jwk_integer(encryption_key.get('n'))
    exponent = _decode_jwk_integer(encryption_key.get('e'))
    if modulus is None or modulus.bit_length() < 2048 or exponent != 65537:
        return False
    return (
        isinstance(signing_key, dict)
        and signing_key.get('kty') == 'EC'
        and signing_key.get('crv') == 'P-256'
        and isinstance(signing_key.get('x'), str)
        and bool(re.fullmatch(r'[A-Za-z0-9_-]{43}', signing_key['x']))
        and isinstance(signing_key.get('y'), str)
        and bool(re.fullmatch(r'[A-Za-z0-9_-]{43}', signing_key['y']))
        and not _RSA_PRIVATE_FIELDS.intersection(signing_key)
    )


def _valid_password(password):
    if not isinstance(password, str):
        return False
    try:
        encoded = password.encode('utf-8')
    except UnicodeEncodeError:
        return False
    return MIN_PASSWORD_LENGTH <= len(password) and len(encoded) <= MAX_PASSWORD_BYTES


def _password_hash(password, salt):
    return hashlib.scrypt(
        password.encode('utf-8'),
        salt=salt,
        n=2**14,
        r=8,
        p=1,
        dklen=32,
    )


def _authenticate_account(mode, username, password, public_keys):
    if (
        mode not in {'create', 'login'}
        or not isinstance(username, str)
        or not _USERNAME_PATTERN.fullmatch(username)
        or not _valid_password(password)
        or not _valid_public_keys(public_keys)
    ):
        return None, 'Enter a valid username, password, and public keys.'

    canonical_keys = json.dumps(public_keys, sort_keys=True, separators=(',', ':'))
    with closing(_database_connection()) as database:
        account = database.execute(
            'SELECT * FROM accounts WHERE username = ?',
            (username,),
        ).fetchone()
        if mode == 'create':
            if account is not None:
                return None, 'That account already exists. Sign in instead.'
            salt = os.urandom(16)
            password_digest = _password_hash(password, salt)
            try:
                database.execute(
                    'INSERT INTO accounts '
                    '(username, password_salt, password_hash, public_keys_json, created_at) '
                    'VALUES (?, ?, ?, ?, ?)',
                    (
                        username,
                        salt,
                        password_digest,
                        canonical_keys,
                        datetime.now(timezone.utc).isoformat(),
                    ),
                )
                database.commit()
            except sqlite3.IntegrityError:
                return None, 'That account already exists. Sign in instead.'
        else:
            if account is None:
                return None, 'Invalid username or password.'
            candidate_hash = _password_hash(password, account['password_salt'])
            if not hmac.compare_digest(candidate_hash, account['password_hash']):
                return None, 'Invalid username or password.'
            if not hmac.compare_digest(
                canonical_keys.encode('utf-8'),
                account['public_keys_json'].encode('utf-8'),
            ):
                return None, (
                    'This browser does not have the account encryption keys. '
                    'Key recovery is not available; do not create a replacement account '
                    'with this username.'
                )
    return username if mode == 'create' else account['username'], None


def _create_portal_session(username):
    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode('utf-8')).hexdigest()
    now = datetime.now(timezone.utc)
    expires_at = (now + timedelta(hours=12)).isoformat()
    with closing(_database_connection()) as database:
        database.execute(
            'DELETE FROM portal_sessions WHERE expires_at <= ?',
            (now.isoformat(),),
        )
        database.execute(
            'INSERT INTO portal_sessions (token_hash, username, expires_at) VALUES (?, ?, ?)',
            (token_hash, username, expires_at),
        )
        database.commit()
    return token


def _portal_session_account(token):
    if not isinstance(token, str) or not 40 <= len(token) <= 128:
        return None
    token_hash = hashlib.sha256(token.encode('utf-8')).hexdigest()
    now = datetime.now(timezone.utc).isoformat()
    with closing(_database_connection()) as database:
        session = database.execute(
            '''
            SELECT username FROM portal_sessions
            WHERE token_hash = ? AND revoked = 0 AND expires_at > ?
            ''',
            (token_hash, now),
        ).fetchone()
    return session['username'] if session else None


@app.route('/')
def index():
    return render_template(
        'chat.html',
        detector_url=os.environ.get('DETECTOR_URL', 'http://127.0.0.1:8502/'),
    )


@app.post('/api/session/validate')
def validate_portal_session():
    data = request.get_json(silent=True)
    username = _portal_session_account(data.get('token') if isinstance(data, dict) else None)
    if username is None:
        return jsonify({'success': False, 'error': 'Session is invalid or expired.'}), 401
    return jsonify({'success': True, 'username': username})


@app.post('/api/session/revoke')
def revoke_portal_session():
    data = request.get_json(silent=True)
    token = data.get('token') if isinstance(data, dict) else None
    if not isinstance(token, str) or not 40 <= len(token) <= 128:
        return jsonify({'success': False, 'error': 'A valid session token is required.'}), 400
    token_hash = hashlib.sha256(token.encode('utf-8')).hexdigest()
    with closing(_database_connection()) as database:
        cursor = database.execute(
            'UPDATE portal_sessions SET revoked = 1 WHERE token_hash = ? AND revoked = 0',
            (token_hash,),
        )
        database.commit()
    if cursor.rowcount != 1:
        return jsonify({'success': False, 'error': 'Session is invalid or already signed out.'}), 401
    return jsonify({'success': True})


@app.route('/api/health')
def health():
    return jsonify({
        'status': 'ok',
        'users_online': len(users),
        'message': 'Local authenticated E2EE chat relay',
    })


@socketio.on('connect')
def handle_connect(auth=None):
    emit('connected', {'sid': request.sid})


@socketio.on('register')
def handle_register(data):
    """Create or authenticate a local account and bind its public keys."""
    if request.sid in users:
        emit('user_registered', {'success': False, 'error': 'This connection is already authenticated.'})
        return
    if not isinstance(data, dict):
        emit('user_registered', {'success': False, 'error': 'Invalid authentication data.'})
        return

    username, error = _authenticate_account(
        data.get('mode'),
        data.get('username'),
        data.get('password'),
        data.get('public_keys'),
    )
    if error:
        emit('user_registered', {'success': False, 'error': error})
        return

    session_token = _create_portal_session(username)
    users[request.sid] = {
        'username': username,
        'display_name': username,
        'public_keys': data['public_keys'],
        'sid': request.sid,
    }
    emit('user_registered', {
        'success': True,
        'username': username,
        'session_token': session_token,
    })
    broadcast_user_list()


@socketio.on('get_users')
def handle_get_users():
    if request.sid not in users:
        emit('user_list', [])
        return
    emit('user_list', get_user_list())


def get_user_list():
    return [
        {
            'sid': user['sid'],
            'username': user['username'],
            'display_name': user['display_name'],
            'public_keys': user['public_keys'],
        }
        for user in users.values()
    ]


def broadcast_user_list():
    user_list = get_user_list()
    for sid in tuple(users):
        socketio.emit('user_list', user_list, to=sid)


@socketio.on('send_message')
def handle_message(data):
    """Relay signed ciphertext only; private keys remain in authenticated clients."""
    if not isinstance(data, dict) or request.sid not in users:
        emit('message_sent', {'status': 'failed', 'error': 'Sign in before sending messages.'})
        return

    sender = users[request.sid]
    allowed_fields = {
        'recipient_sid',
        'recipient_username',
        'encrypted_message',
        'encrypted_key',
        'iv',
        'signature',
        'message_type',
    }
    if set(data) != allowed_fields:
        emit('message_sent', {
            'status': 'failed',
            'error': 'Message must contain only the signed encrypted envelope.',
        })
        return
    recipient_sid = data.get('recipient_sid')
    encrypted_message = data.get('encrypted_message')
    encrypted_key = data.get('encrypted_key')
    iv = data.get('iv')
    signature = data.get('signature')
    message_type = data.get('message_type', 'text')
    if (
        not isinstance(recipient_sid, str)
        or not isinstance(encrypted_message, str)
        or len(encrypted_message) > MAX_ENCRYPTED_MESSAGE_CHARS
        or not isinstance(encrypted_key, str)
        or not isinstance(iv, str)
        or not isinstance(signature, str)
        or len(signature) > 1024
        or message_type != 'text'
    ):
        emit('message_sent', {'status': 'failed', 'error': 'Invalid signed encrypted message.'})
        return

    recipient = users.get(recipient_sid)
    if recipient is None:
        emit('message_sent', {'status': 'failed', 'error': 'User not found.'})
        return
    if data.get('recipient_username') != recipient['username']:
        emit('message_sent', {'status': 'failed', 'error': 'Message recipient does not match.'})
        return

    emit('receive_message', {
        'from_sid': request.sid,
        'from_username': sender['username'],
        'from_user': sender['display_name'],
        'recipient_username': recipient['username'],
        'encrypted_message': encrypted_message,
        'encrypted_key': encrypted_key,
        'iv': iv,
        'signature': signature,
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'message_type': message_type,
    }, room=recipient_sid)
    emit('message_sent', {'status': 'delivered'})


@socketio.on('send_file')
def handle_file(data):
    """Relay a signed, size-limited encrypted file without modifying its bytes."""
    if not isinstance(data, dict) or request.sid not in users:
        emit('file_sent', {'status': 'failed', 'error': 'Sign in before sending files.'})
        return

    sender = users[request.sid]
    allowed_fields = {
        'recipient_sid',
        'recipient_username',
        'encrypted_file',
        'encrypted_key',
        'iv',
        'signature',
        'filename',
        'file_type',
    }
    if set(data) != allowed_fields:
        emit('file_sent', {
            'status': 'failed',
            'error': 'File transfer must contain only the signed encrypted envelope.',
        })
        return
    recipient_sid = data.get('recipient_sid')
    encrypted_file = data.get('encrypted_file')
    encrypted_key = data.get('encrypted_key')
    iv = data.get('iv')
    signature = data.get('signature')
    filename = data.get('filename')
    file_type = data.get('file_type')
    if (
        not isinstance(recipient_sid, str)
        or not isinstance(encrypted_file, str)
        or len(encrypted_file) > MAX_ENCRYPTED_FILE_CHARS
        or not isinstance(encrypted_key, str)
        or not isinstance(iv, str)
        or not isinstance(signature, str)
        or len(signature) > 1024
        or not isinstance(filename, str)
        or not 1 <= len(filename) <= 255
        or not isinstance(file_type, str)
        or len(file_type) > 128
    ):
        emit('file_sent', {'status': 'failed', 'error': 'Invalid or oversized signed encrypted file.'})
        return

    recipient = users.get(recipient_sid)
    if recipient is None:
        emit('file_sent', {'status': 'failed', 'error': 'User not found.'})
        return
    if data.get('recipient_username') != recipient['username']:
        emit('file_sent', {'status': 'failed', 'error': 'File recipient does not match.'})
        return

    emit('receive_file', {
        'from_sid': request.sid,
        'from_username': sender['username'],
        'from_user': sender['display_name'],
        'recipient_username': recipient['username'],
        'encrypted_file': encrypted_file,
        'encrypted_key': encrypted_key,
        'iv': iv,
        'signature': signature,
        'filename': filename,
        'file_type': file_type,
        'timestamp': datetime.now(timezone.utc).isoformat(),
    }, room=recipient_sid)
    emit('file_sent', {'status': 'delivered'})


@socketio.on('disconnect')
def handle_disconnect():
    if users.pop(request.sid, None) is not None:
        broadcast_user_list()


if __name__ == '__main__':
    chat_port = int(os.environ.get('CHAT_PORT', '5001'))
    print(f'Starting local E2EE chat on http://127.0.0.1:{chat_port}')
    print('Accounts and public keys are stored in the configured SQLite database.')
    socketio.run(app, debug=False, host='127.0.0.1', port=chat_port)
