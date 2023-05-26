const express = require('express');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { Client } = require('@elastic/elasticsearch');

const app = express();
const elasticClient = new Client({ node: 'http://localhost:9200' });
const indexName = 'keys';
const jwtSecret = 'your-secret-key'; // Replace with your own secret key

// Create index for storing the keys
async function createIndex() {
  await elasticClient.indices.create({
    index: indexName,
    body: {
      mappings: {
        properties: {
          publicKey: { type: 'keyword' },
          privateKey: { type: 'text' },
        },
      },
    },
  });
}

// Check if the index exists, and create it if it doesn't
async function ensureIndexExists() {
  const { body } = await elasticClient.indices.exists({ index: indexName });
  if (!body) {
    await createIndex();
  }
}

ensureIndexExists().catch(console.error);

// Generate a token for authentication
const generateToken = (payload) => {
  const token = jwt.sign(payload, jwtSecret);
  return token;
};

// Token API to generate a new token and store the key pair
app.get('/generate-token', async (req, res) => {
  // Generate key pair
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem',
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem',
    },
  });

  // Store the public/private key pair in Elasticsearch
  await elasticClient.index({
    index: indexName,
    body: {
      publicKey: publicKey.toString(),
      privateKey: privateKey.toString(),
    },
    refresh: true,
  });

  // Generate and send the JWT token with the public key as the payload
  const token = generateToken({ publicKey: publicKey.toString() });
  res.send(token);
});

// "Hello" API with JWT-based authorization
app.get('/hello', async (req, res) => {
  const token = req.headers.authorization;

  try {
    // Verify and decode the JWT token
    const decoded = jwt.verify(token, jwtSecret);
    const publicKey = decoded.publicKey;

    // Retrieve the private key from Elasticsearch based on the public key
    const { body } = await elasticClient.search({
      index: indexName,
      body: {
        query: {
          match: {
            publicKey: publicKey,
          },
        },
      },
    });

 
    if (body.hits.total.value === 1) {
      const privateKey = body.hits.hits[0]._source.privateKey;

      // Sign the public key using the private key
      const sign = crypto.createSign('RSA-SHA256');
      sign.update(publicKey);
      const signature = sign.sign(privateKey, 'base64');

      // Verify the signature using the public key
      const verify = crypto.createVerify('RSA-SHA256');
      verify.update(publicKey);
      const isPublicKeyValid = verify.verify(publicKey, signature, 'base64');

      if (isPublicKeyValid) {
        // Public key is valid, proceed with the API logic
        res.send('Hello, user!');
      } else {
        res.sendStatus(401);
      }
    } else {
      res.sendStatus(401);
    }
  } catch (error) {
    res.sendStatus(401);
  }
});

// Start the server
app.listen(3000, () => {
  console.log('Server is listening on port 3000');
});
