// Serverless API for Ayush Admin Panel (/toxic) Authentication
// This runs exclusively on Vercel server-side - clients CANNOT view this source code!

const crypto = require('crypto');

function hashWithSalt(str, salt = "ayush_sec_99x#") {
  return crypto.createHash('sha256').update(salt + str).digest('hex');
}

const VALID_USER_HASHES = [
  "58a1eb2c9c4e1c343c8a23f6d0a18bd9da233543daf50646e4e784ae5aa56ca1", // 'ayush'
  "9ef1a61d6045b7343bb2871aba6d5e04e776401d981fe9b5eda2c18d83a424ad"  // 'toxic'
];

const MASTER_PASS_HASH = "38c9e9cda53fb283bbbd889029d63b723a0db1f0c2786775dd19bd73bf36d2f9";

module.exports = async (req, res) => {
  // CORS & Security headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    let data = req.body;
    if (typeof data === 'string') {
      try { data = JSON.parse(data); } catch (_) {}
    }
    const { user, pass } = data || {};
    if (!user || !pass) {
      return res.status(400).json({ error: 'Username and password required' });
    }

    const inputUserHash = hashWithSalt(String(user).trim().toLowerCase());
    const inputPassHash = hashWithSalt(String(pass));

    const userValid = VALID_USER_HASHES.includes(inputUserHash);
    const passValid = (inputPassHash === MASTER_PASS_HASH);

    if (userValid && passValid) {
      const sessionToken = "tok_" + crypto.randomBytes(24).toString('hex');
      return res.status(200).json({
        success: true,
        token: sessionToken,
        user: String(user).trim().toLowerCase(),
        timestamp: Date.now()
      });
    } else {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
  } catch (err) {
    return res.status(500).json({ error: 'Server authentication error' });
  }
};
