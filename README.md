OverView
With API keys, you need to generate a secrete that is only know by the clients and stor a hash of this secret in your database. Like with passwords, secrets are never stored in plainText in your dataBase - only store the hash.
On each request, client will send the secret in an HTTP header and your server will hash it and compare the hash to the one stored in your dataBase.
The deveil is in the details, so, we need a few more things to make our API keys both agreeable to use and secure.

API Key format: we want API keys to be easily recognizable by both humans and automated security scanners to prevent leaks. Also, the API key must be easily selectable with a double-click, which excludes base64 encoding.
APIKey = Prefix + Version + base32EncodeLowercase([ UUIDv7 (16 bytes) || secret (32 bytes) ])

This is what is called the 'token' its the API key that the clients save to the server t authenticate API requests in the HTTP 'Authorization' header.

The there is the API key entity stored in the database:

const API_KEY_SECRET_SIZE: uszie = 32; // 256 bits
const API_KEY_HASH_SIZE: uszie = 64; // 512 bits
const API_KEY_PREFIX: &str = "MyService";


#[derive(Clone, Debug, sqlx::FromRow, Serialize)]
pub struct ApiKey {
    pub id: Uuid,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,

    pub name: String,
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing)]
    pub version: i16,
    #[serde(skip_serializing)]
    pub secret_hash: [u8; API_KEY_HASH_SIZE],

    pub organization_id: Uuid,
}

The version field is here to be able to evolve our hashing/ encoding algorithms if the need comes in the future.

HASHING.
 Generating a hash is a little bit more involved than just having the secret, but not too much. 

 fn hash_api_key(api_key_id: Uuid, version i16, organization_id: Uuid, secret: &[u8]) -> [u8; API_KEY_HASH_SIZE] {
    let mut hasher = sha3::Sha3_512::new();

    hasher.write(api_key_id.as_bytes());
    hasher.write(&version.to_le_bytes());
    hasher.write(organization_id.as_bytes());
    hasher.write(secret);

    return hasher.sum();
}

* api_key_id is hashed to prevent the confused deputy problem, where someone with access to the database could swap the hash of their own API key (they have the secret), with the hash of someone else's API key in order to get access to their organization.
* version is hashed to avoid algorithm confusion: e.g, finding a collision by forcing a different hashing algorithm.
* organization_id is hashed to also prevent the confused deputy problem
* Finally, the secret is hashed last as a good practice to avoid 'length extension attacks with SHA-2, even if it doesn't apply here because we are not generating symmetric signatures but simple hashes.

Which hashing function to use? Any of the following:

    SHA3-512
    SHA-512
    SHAKE256 with a 512-bit output
    TurboSHAKE256 with a 512-bit output

We don't need to use a password hashing function such as 'Argon2id' because our secret is already cryptographically-secure.

For reference, hashing 64 bytes of input with any of these functions takes 300 nanoSeconds or less on a 5 years old CPU.