pub async fn auth_middleware(
    State(state): State<Arc<ServerState>>,
    cookies: CookieJar,
    mut request: Request,
    next: Next,    
) -> Result<Response, Error> {
    let mut authorization_header = request
    .header()
    .get(header::AUTHORIZATION)
    .map(|header| header.to_str().unwrap_or_default())
    .unwrap_or_default()
    .trim()
    .to_str();

    let ctx = request.extensions_mut().get_mut::<RequestContext>()
    .ok_or(Error::Internal("middlewares.auth: RequestContext is missing"))?;

    let api_key_str: &str = decode_autorization_header(&authorization_header)?;
    let api_key: ApiKey = state.auth_service.verify_api_key(api_key_str).await?;

    ctx.auth = Some(RequestContextAuth::ApiKey(api_key));

    authorization_header.zeroize();

    return Ok(next.run(request).await);

    // BLACK HAT RUST //
}
