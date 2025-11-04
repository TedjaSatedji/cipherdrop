# Group Messaging Feature - Implementation Guide

## Overview

The Group Messaging feature adds end-to-end encrypted group chat capabilities to CipherDrop. This implementation uses a **symmetric group key** approach where:

1. A group creator generates a random AES-256 group key
2. This key is individually encrypted for each group member using their personal passphrase
3. All group messages are encrypted with the shared group key
4. Only group members who have the correct passphrase can decrypt messages

## Architecture

### Server-Side Changes (server.py)

#### New Database Models

1. **Group Table**
   - `id`: Unique group identifier
   - `name`: Group name
   - `creator_id`: Foreign key to User who created the group
   - `created_at`: Timestamp
   - Relationships: members, messages

2. **GroupMembership Table**
   - `id`: Primary key
   - `group_id`: Foreign key to Group
   - `user_id`: Foreign key to User
   - `encrypted_group_key_b64`: Base64-encoded encrypted group key for this specific user
   - `joined_at`: Timestamp
   - `is_admin`: Boolean (admins can add/remove members)

3. **GroupMessage Table**
   - `id`: Unique message identifier
   - `group_id`: Foreign key to Group
   - `sender_id`: Foreign key to User
   - `encrypted_blob`: Encrypted message content
   - `created_at`: Timestamp

#### New API Endpoints

1. **POST /api/groups/create**
   - Creates a new group
   - Requires: group name, encrypted group key for creator
   - Returns: group ID and name

2. **GET /api/groups**
   - Lists all groups the user is a member of
   - Returns: Array of group info with encrypted keys

3. **GET /api/groups/{group_id}/members**
   - Lists all members of a specific group
   - Returns: Array of member info (username, admin status, join date)

4. **POST /api/groups/{group_id}/members**
   - Adds a new member to the group (admin only)
   - Requires: username, encrypted group key for that user
   - Returns: Success status

5. **DELETE /api/groups/{group_id}/members/{username}**
   - Removes a member (admins can remove anyone, users can remove themselves)
   - Returns: Success status

6. **POST /api/groups/{group_id}/messages**
   - Sends an encrypted message to the group
   - Requires: encrypted message blob (base64)
   - Returns: message ID and timestamp

7. **GET /api/groups/{group_id}/messages**
   - Retrieves encrypted messages from a group
   - Query param: limit (default 50)
   - Returns: Array of encrypted messages

8. **DELETE /api/groups/{group_id}**
   - Deletes a group (creator only)
   - Returns: Success status

### Client-Side Changes (cipherapp.py)

#### New Cryptographic Functions

1. **`generate_group_key()`**
   - Generates a random 32-byte AES-256 key

2. **`encrypt_group_key_for_user(group_key, user_passphrase)`**
   - Encrypts the group key using a user's passphrase
   - Uses existing `super_encrypt_text` with Argon2 KDF
   - Returns base64-encoded encrypted envelope

3. **`decrypt_group_key_for_user(encrypted_group_key_b64, user_passphrase)`**
   - Decrypts the group key using a user's passphrase
   - Returns the raw group key bytes

4. **`encrypt_group_message(message, group_key)`**
   - Encrypts a message with AES-GCM using the group key
   - Returns base64-encoded encrypted blob (nonce + ciphertext)

5. **`decrypt_group_message(encrypted_blob_b64, group_key)`**
   - Decrypts a message using the group key
   - Returns plain text message

#### New API Client Functions

All API endpoint wrappers following the pattern:
- `api_create_group()`
- `api_list_groups()`
- `api_get_group_members()`
- `api_add_group_member()`
- `api_remove_group_member()`
- `api_send_group_message()`
- `api_get_group_messages()`
- `api_delete_group()`

#### New UI Components

**Groups Tab** with three sub-tabs:

1. **My Groups**
   - List of all groups user is a member of
   - Actions: View members, Delete group (if creator), Leave group

2. **Create Group**
   - Form to create a new group with name and passphrase
   - Section to add members (requires their username and passphrase)
   - Info about group key encryption

3. **Group Chat**
   - Dropdown to select a group
   - Passphrase field to unlock the chat
   - Messages display area (decrypted in real-time)
   - Message input and send button
   - Auto-refresh functionality

#### State Management

New state variables in `MainWindow.__init__`:
- `self.groups_list`: List of group dictionaries
- `self.current_group_id`: Currently selected group ID
- `self.group_keys_cache`: Dictionary mapping group_id to decrypted group key

## Security Considerations

### Strengths

1. **End-to-End Encryption**: Messages are encrypted with a group key that never leaves client devices unencrypted
2. **Per-User Key Encryption**: Each member's copy of the group key is encrypted with their own passphrase
3. **No Key Storage**: Group keys are only cached in memory and must be unlocked with passphrase each session
4. **Argon2 KDF**: Strong key derivation prevents brute force attacks on passphrases
5. **AES-GCM**: Authenticated encryption ensures message integrity and authenticity

### Considerations

1. **Passphrase Sharing**: The current implementation requires sharing passphrases to add members. In a production system, this could be replaced with:
   - Public key infrastructure (encrypt group key with recipient's public key)
   - Pre-shared keys
   - Key exchange protocols

2. **Forward Secrecy**: Messages encrypted with the same group key forever. Consider:
   - Periodic key rotation
   - Implementing ratcheting mechanisms (like Signal's Double Ratchet)

3. **Member Removal**: Removed members can still decrypt old messages. Best practices:
   - Rotate group key when members are removed
   - Re-encrypt key for remaining members

4. **Server Trust**: Server sees group membership and message metadata (timestamps, senders)
   - Consider mixing networks or onion routing for metadata protection

## Usage Flow

### Creating a Group

1. User navigates to Groups → Create Group
2. Enters group name and their passphrase
3. Client generates random group key
4. Client encrypts group key with user's passphrase
5. Client sends create request to server
6. Server creates group and adds creator as admin member

### Adding Members

1. Admin selects a group from "My Groups"
2. Goes to "Create Group" tab
3. Enters new member's username and their passphrase
4. Client retrieves group key from cache
5. Client encrypts group key with new member's passphrase
6. Client sends add member request to server
7. Server adds membership with encrypted key

### Sending Messages

1. User selects group in Group Chat tab
2. Enters their passphrase and clicks "Unlock Chat"
3. Client decrypts group key and caches it
4. Client loads and decrypts existing messages
5. User types message and clicks Send
6. Client encrypts message with group key
7. Client sends encrypted blob to server
8. Server stores encrypted message

### Reading Messages

1. All group members retrieve encrypted messages from server
2. Each member unlocks the group with their passphrase
3. Client decrypts their copy of the group key
4. Client uses group key to decrypt all messages
5. Messages displayed in chat interface

## Testing Checklist

- [ ] Create a group with valid name and passphrase
- [ ] List groups and see newly created group
- [ ] Add a second user to the group
- [ ] Both users can unlock the group chat
- [ ] Send messages from both users
- [ ] Both users can decrypt and read all messages
- [ ] View group members
- [ ] Leave a group
- [ ] Delete a group (as creator)
- [ ] Test error cases (wrong passphrase, permission denied, etc.)
- [ ] Verify encrypted blobs in database are unreadable
- [ ] Test with multiple groups

## Future Enhancements

1. **Rich Media**: Support for images, files in group chat
2. **Typing Indicators**: Real-time presence information
3. **Read Receipts**: Track who has read messages
4. **Group Avatars**: Visual customization
5. **Message Search**: Search within decrypted messages
6. **Key Rotation**: Automatic periodic key updates
7. **Public Key Crypto**: Replace passphrase sharing with PKI
8. **Voice/Video**: Real-time encrypted communications
9. **Message Reactions**: Emoji reactions to messages
10. **Thread Replies**: Organized conversations

## Dependencies

All existing dependencies are sufficient:
- **cryptography**: For AES-GCM encryption
- **PySide6**: For UI components
- **requests**: For API calls
- **secrets**: For random key generation

## Database Migration

When deploying to an existing server, the new tables will be automatically created by SQLAlchemy's `Base.metadata.create_all(engine)` call. No manual migration needed for SQLite.

For production databases (PostgreSQL, MySQL), consider using Alembic for proper migrations.

## API Documentation

All new endpoints follow the existing FastAPI documentation format. Access at:
```
http://your-server/docs
```

The Swagger UI will show all group-related endpoints with request/response schemas.

---

**Implementation Date**: November 4, 2025  
**Version**: 1.0  
**Status**: ✅ Complete and Ready for Testing
