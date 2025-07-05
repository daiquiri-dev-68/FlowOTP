export async function onRequestGet(context) {
  const { secret } = context.params;

  if (!secret || secret.length < 16) {
    return new Response(JSON.stringify({ error: "Invalid secret." }), {
      status: 400,
      headers: { "Content-Type": "application/json" }
    });
  }

  function base32toHex(base32) {
    const base32chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let bits = "", hex = "";
    for (let i = 0; i < base32.length; i++) {
      const val = base32chars.indexOf(base32.charAt(i).toUpperCase());
      bits += val.toString(2).padStart(5, '0');
    }
    for (let i = 0; i + 4 <= bits.length; i += 4) {
      hex += parseInt(bits.substr(i, 4), 2).toString(16);
    }
    return hex;
  }

  async function generateTOTP(secret) {
    const key = base32toHex(secret);
    const epoch = Math.floor(Date.now() / 1000);
    const time = Math.floor(epoch / 30).toString(16).padStart(16, '0');
    const timeBytes = Uint8Array.from(time.match(/.{1,2}/g).map(b => parseInt(b, 16)));
    const keyBytes = Uint8Array.from(key.match(/.{1,2}/g).map(b => parseInt(b, 16)));

    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      keyBytes,
      { name: 'HMAC', hash: 'SHA-1' },
      false,
      ['sign']
    );

    const hmac = await crypto.subtle.sign('HMAC', cryptoKey, timeBytes);
    const hmacBytes = new Uint8Array(hmac);

    const offset = hmacBytes[hmacBytes.length - 1] & 0xf;
    const binary = (
      ((hmacBytes[offset] & 0x7f) << 24) |
      ((hmacBytes[offset + 1] & 0xff) << 16) |
      ((hmacBytes[offset + 2] & 0xff) << 8) |
      (hmacBytes[offset + 3] & 0xff)
    );

    const otp = (binary % 1000000).toString().padStart(6, '0');
    return otp;
  }

  const token = await generateTOTP(secret);
  return new Response(JSON.stringify({ token }), {
    headers: { "Content-Type": "application/json" }
  });
}
