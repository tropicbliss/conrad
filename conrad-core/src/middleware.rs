use cookie::CookieJar;
use http::{HeaderMap, Method};
use url::Url;

pub trait IntoRequest {
    fn get_cookies(&self) -> &mut CookieJar;
    fn get_method(&self) -> &Method;
    fn get_headers(&self) -> &HeaderMap;
    fn get_origin_url(&self) -> &Url;
}
