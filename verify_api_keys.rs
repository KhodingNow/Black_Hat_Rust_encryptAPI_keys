struct ParsedApiKey {
    pub id: Uuid,
    pub version: i16,
    pub secret: [u8; API_KEY_SECRET_SIZE],
}

impl AuthService {
    pub async fn verify_api_key(&self, api_key: &str) -> Result<ApiKey, Error> {
        let parsed_api_key = match parsed_api_key(api_key) {
            Ok(parsed_api_key) => parsed_api_key,
            Err(err) => {
                sleep_on_failure().await;
                return Err(err);
            } 
        };

        let api_key = match self.repo.find_api_key_by_id(&self.db, parsed_api_key.id).await {
            Ok(api_key) => api_key,
            Err(err) => {
                sleep_on_failure().await;
                return Err(Error::ApiKeyIsNotValid);
            }
        };

        if let Some(expires_at) = api_key.expires_at {
            if expires_at <= Utc::now() {
                sleep_on_failure().await;
                return Err(Error::ApiKeyIsNotValid);
            }
        }

        let hash = hash_api_key(parsed_api_key.id, parsed_api_key.version, organization_id, &parsed_api_key.secret);

        // everything is ok, remove sensitive secrets from memory

        parsed_api_key.secret.zeroize();

        return Ok(api_key);
    }
}

fn parsed_api_key(api_key_str: &str) -> Result<ParsedApiKey, Error> {
    //..
}

async fn sleep_on_failure() {
    let sleep_for_ms = rand::thread_rng().gen_range(500..800);
    tokio::time::sleep(Duration::from_millis(sleep_for_ms)),await;
}