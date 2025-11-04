# Group Messaging - Quick Start Guide

## For Users

### Creating Your First Group

1. **Login** to CipherDrop
2. Go to **Groups** tab → **Create Group**
3. Enter:
   - **Group Name**: e.g., "Project Team"
   - **Your Passphrase**: The passphrase you'll use to unlock this group
4. Click **Create Group**
5. ✅ Group created! The app generates a secure group key for you.

### Adding Members

1. Select your group from **My Groups**
2. Go back to **Create Group** tab
3. In "Add Members to New Group" section:
   - **Username**: The person you want to add
   - **Their Passphrase**: Their personal passphrase (they need to share this with you securely)
4. Click **Add Member**

> **Note**: In practice, members should share passphrases via a secure channel (Signal, in-person, etc.)

### Chatting in Groups

1. Go to **Groups** → **Group Chat**
2. Select your group from dropdown
3. Enter your passphrase
4. Click **Unlock Chat**
5. Type messages and press Enter or click Send
6. Click **Refresh** to see new messages from others

### Managing Groups

- **View Members**: Select group → Click "View Members"
- **Leave Group**: Select group → Click "Leave Group"
- **Delete Group**: (Creator only) Select group → Click "Delete Group"

## For Developers

### Key Files Modified

1. **server.py**: Database models + API endpoints
2. **cipherapp.py**: Client UI + crypto functions

### Testing the Feature

```powershell
# Start the server
python server.py

# In another terminal, run the client
python cipherapp.py
```

### API Testing with curl

```bash
# Login
curl -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"test","password":"test123"}'

# Create Group (save token from login)
curl -X POST http://localhost:8000/api/groups/create \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"Test Group","encrypted_group_key_b64":"base64_here"}'

# List Groups
curl http://localhost:8000/api/groups \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### Quick Debugging

**Check Database**:
```bash
sqlite3 dropbox.db
> SELECT * FROM groups;
> SELECT * FROM group_memberships;
> SELECT * FROM group_messages;
```

**Common Issues**:

1. **"Group key not available"**: Unlock the group first in Group Chat tab
2. **"Decryption failed"**: Wrong passphrase or corrupted data
3. **"Only admins can add members"**: You're not an admin of that group
4. **Import errors**: Missing dependencies (see requirements.txt)

### Code Structure

```
Group Key Flow:
1. generate_group_key() → 32 random bytes
2. encrypt_group_key_for_user(key, passphrase) → base64 envelope
3. Store in GroupMembership.encrypted_group_key_b64
4. Retrieve and decrypt_group_key_for_user() → original key
5. Use key for encrypt_group_message() / decrypt_group_message()
```

### Adding New Group Features

To add a new group action:

1. Add API endpoint in `server.py`:
```python
@app.post("/api/groups/{group_id}/your_action")
def your_action(group_id: str, me: User = Depends(bearer(None))):
    # Your logic here
    return {"ok": True}
```

2. Add client function in `cipherapp.py`:
```python
def api_your_action(sess: Session, group_id: str):
    r = requests.post(f"{sess.api}/api/groups/{group_id}/your_action", 
                      headers=sess.headers)
    r.raise_for_status()
    return r.json()
```

3. Add UI button and connect to handler:
```python
self.your_action_button = QPushButton("Your Action")
self.your_action_button.clicked.connect(self.do_your_action)
```

4. Implement worker pattern:
```python
@Slot()
def do_your_action(self):
    worker = Worker(api_your_action, self.session, self.current_group_id)
    worker.signals.success.connect(self.on_your_action_success)
    worker.signals.error.connect(self.on_your_action_error)
    self.threadpool.start(worker)
```

## Security Notes

### What's Encrypted

✅ Group messages (with group key)  
✅ Group keys (with each member's passphrase)  
✅ Member passphrases (never sent to server)

### What's NOT Encrypted

❌ Group names  
❌ Member usernames  
❌ Message timestamps  
❌ Group membership lists

The server can see who is in which group and when messages are sent, but **cannot read the content**.

## Troubleshooting

### UI Issues

**Groups tab not showing**:
- Make sure you're logged in
- Check console for errors

**Can't unlock chat**:
- Verify you're using the same passphrase used when creating/joining
- Try refreshing the groups list

### Server Errors

**404 Not Found**:
- Endpoint might not exist
- Check server.py has all new routes

**403 Forbidden**:
- Not a member of the group
- Not an admin (for admin-only actions)

**500 Internal Server Error**:
- Check server logs
- Database might be corrupted
- Try deleting `dropbox.db` and restarting

### Database Issues

**Foreign key errors**:
- Make sure users exist before creating groups
- Check relationships are properly defined

**Reset database**:
```powershell
rm dropbox.db
python server.py  # Will recreate tables
```

## Performance Tips

1. **Limit message history**: Use the `limit` parameter (default 50)
2. **Cache group keys**: App caches decrypted keys in memory
3. **Batch operations**: Refresh groups once, not per action
4. **Background workers**: All network/crypto ops run in background threads

## Next Steps

1. ✅ Test basic group creation and messaging
2. ✅ Test with 2+ users
3. ✅ Test admin permissions
4. ✅ Test error cases
5. Consider adding features from Future Enhancements list

---

**Need Help?**  
Check `GROUP_MESSAGING_FEATURE.md` for detailed technical documentation.
