pub mod providers;

use conrad_core::auth::Authenticator;
use cookie::CookieJar;
use url::Url;

pub struct OAuthConfig {
    client_id: &'static str,
    client_secret: &'static str,
    scope: Vec<&'static str>,
}

impl OAuthConfig {
    pub fn new(
        client_id: &'static str,
        client_secret: &'static str,
        scope: Vec<&'static str>,
    ) -> Self {
        Self {
            client_id,
            client_secret,
            scope,
        }
    }
}

pub trait OAuthProvider {
    type Config;

    fn new<D>(auth: Authenticator<D>, config: Self::Config) -> Self
    where
        D: Clone;
    fn get_authorization_url(&self, cookies: &mut CookieJar) -> Url;
}

#[doc(hidden)]
pub trait IntoProvider {
    fn to_provider<P>(&self, config: P::Config) -> P
    where
        P: OAuthProvider;
}

impl<D> IntoProvider for Authenticator<D>
where
    D: Clone,
{
    fn to_provider<P>(&self, config: P::Config) -> P
    where
        P: OAuthProvider,
    {
        P::new(self.clone(), config)
    }
}
