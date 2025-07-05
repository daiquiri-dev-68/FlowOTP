# FlowOTP

A minimalist Cloudflare Worker for generating TOTP (Time-based One-Time Password) tokens via HTTP.

## Usage

- **Endpoint:**  
  `/tools/flowotp/[secret]`

Send a GET request with your Base32-encoded TOTP secret.  
Returns the current TOTP token as JSON.

**Example:**
```http
GET https://daiquiri.dev/tools/flowotp/ABCDEF1234567890
```
**Response:**
```json
{ "token": "123456" }
```

## Security

- The `secret` must be at least 16 characters.
- All logic runs within the Cloudflare Worker environment; secrets are never stored.

## Directory Structure

```
[secret].js
flowotp.js
README.md
```

## License

MIT
