use std::time::SystemTime;

pub struct Cookie {
    pub same_site: &'static str,
    pub path: &'static str,
    pub http_only: bool,
    pub expires: SystemTime,
    pub secure: bool,
}
