#[derive(Clone, Debug, Deserialize)]

pub struct CreateApiKeyInput {
    pub organization_id: Uuid,
    pub name: String,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug,Serialize)]

pub struct ApiKeyWithToken {
    pub api_key: ApiKey,
    pub token: String,
}

impl AuthService {
    pub async fn create_api_key(
        &self,
        ctx: RequestContext,
        input: CreateApiKeyInput,        
    ) -> Result<ApiKeyWithToken, Error> {
        // ..check auth

        let name = input.name.trim().to_string();
        validate_api_key_name(&name)?;

        if let Some(expires_at) = input.expires_at {
            validate_api_key_expires_at(expires_at)?;
        }

        // token is then sent to the client. It's the API key to be sent into the Authorization HTTP header

        let api_key_with_token = generate_api_key_v1(input.organization_id, name, input.expires_at);
        self.repo.create_api_key(&self.db, &api_key_with_token.api_key).await?;

        return Ok(api_key_with_token);
    }
}

fn generate_api_key_v1(
    organization_id: Uuid,
    name: String,
    expires_at: Option<DateTime<Utc>>,    
) -> ApiKeyWithToken {
    // It's okay to use UUIDv7 (low entropy) because we don't rely on the security of the api_key_id
    // but on the security of the secret instead

    let api_key_id = Uuid::new_v7();

    // token_data = [api_key_id(16 bytes) || secret (32 bytes) ]

    let mut token_data = [0u8; 16 + API_KEY_SECRET_SIZE];
    token_data[..16].copy_from_slice(api_key_id.as_bytes());
    rand::thread_rng().fill_bytes(&mut token_data[16..]);

    let hash = hash_api_key(api_key_id, organization_id, &token_data[16..]);

    // token = API_KEY_PREFIX || "V1" || base32(api_key_id || secret)
    let mut token = base32::encode_lowercase(&token_data);
    token.insert_str(0, "V1");
    token.insert_str(0, API_KEY_PREFIX);

    token_data.zeroize();

    let now = Utc::now();
    let api_key = ApiKey {
        id: api_key_id,
        created_at: now,
        updated_at: now,
        name: name,
        secret_hash: hash,
        expires_at,
        organization_id,
    };

    return ApiKeyWithToken {api_key, token };
}
