# AES-CBC Padding Oracle Challenge

This is an AES-CBC padding oracle challenge server. The server uses AES-256-CBC encryption with PKCS7 padding and exposes a padding oracle vulnerability through its error responses.

## API Endpoints

### GET /challenge

Returns an encrypted flag with a randomly generated IV and ciphertext.

**Response:**
```json
{
  "iv": "base64-encoded-iv",
  "ciphertext": "base64-encoded-ciphertext"
}
```

The flag is generated once at server startup and encrypted using AES-256-CBC, but encrypted with a new IV for each request.

### POST /decrypt

Attempts to decrypt the provided ciphertext, with the IV provided and the server key.

**Request Body:**
```json
{
  "iv": "base64-encoded-iv",
  "ciphertext": "base64-encoded-ciphertext"
}
```

**Responses:**
- `200 OK` - Decryption successful (no response body)
- `400 Bad Request` - Decryption error (invalid ciphertext structure or other decryption failure)
  ```json
  {"error": "Decryption error"}
  ```
- `500 Internal Server Error` - Padding error (invalid PKCS7 padding detected)
  ```json
  {"error": "Padding error"}
  ```

The server differentiates between padding errors and general decryption errors, which creates a padding oracle that can be exploited to decrypt the flag without knowing the encryption key.

### POST /verify

This endpoint can be used to verify the decrypted flag matches the plaintext on the server.

**Request Body:**
```json
{
  "flag": "flag-string"
}
```

**Responses:**
- `200 OK` - Congratulations, the flag matches, you have successfully decrypted the ciphertext
- `403 Forbidden` - Your provided plaintext does not match the value on the server


## Exploitation
Here is a screencap of my test software using the padding oracle to decrypt the flag
![screencapture](screencap.gif)
