use super::utils;
use crate::{
    errors::OAuthError, AuthInfo, OAuthConfig, OAuthProvider, RedirectInfo, Tokens,
    ValidationResult,
};
use async_trait::async_trait;
use oauth2::{
    basic::BasicClient, reqwest::async_http_client, AuthType, AuthUrl, AuthorizationCode, ClientId,
    ClientSecret, CsrfToken, RedirectUrl, Scope, TokenResponse, TokenUrl,
};
use reqwest::Client;
use serde::Deserialize;
use serde_json::Value;
use std::time::Duration;

const PROVIDER_ID: &str = "reddit";

#[derive(Clone)]
pub struct RedditConfig {
    base: OAuthConfig,
    redirect_uri: String,
}

impl RedditConfig {
    pub fn new(
        client_id: String,
        client_secret: String,
        scope: Vec<String>,
        redirect_uri: String,
    ) -> Self {
        let base = OAuthConfig {
            client_id,
            client_secret,
            scope,
        };
        Self { base, redirect_uri }
    }
}

#[derive(Clone)]
pub struct RedditProvider {
    client: BasicClient,
    scope: Vec<String>,
    web_client: Client,
}

#[async_trait]
impl OAuthProvider for RedditProvider {
    type Config = RedditConfig;
    type UserInfo = Box<RedditUser>;

    fn get_authorization_url(&self) -> RedirectInfo {
        let mut req = self
            .client
            .authorize_url(CsrfToken::new_random)
            .add_extra_param("duration", "permanent");
        for scope in &self.scope {
            req = req.add_scope(Scope::new(scope.to_string()));
        }
        let info = req.url();
        RedirectInfo {
            url: info.0,
            csrf_token: info.1.secret().to_string(),
        }
    }

    fn new(config: Self::Config) -> Self {
        let client = BasicClient::new(
            ClientId::new(config.base.client_id),
            Some(ClientSecret::new(config.base.client_secret)),
            AuthUrl::new("https://www.reddit.com/api/v1/authorize".to_string()).unwrap(),
            Some(TokenUrl::new("https://www.reddit.com/api/v1/access_token".to_string()).unwrap()),
        )
        .set_redirect_uri(RedirectUrl::new(config.redirect_uri).unwrap())
        .set_auth_type(AuthType::BasicAuth);
        let web_client = Client::builder()
            .timeout(Duration::from_secs(15))
            .user_agent("conrad")
            .build()
            .unwrap();
        Self {
            client,
            scope: config.base.scope,
            web_client,
        }
    }

    async fn validate_callback(
        &self,
        code: String,
    ) -> Result<ValidationResult<Self::UserInfo>, OAuthError> {
        let tokens = self.get_tokens(code).await?;
        let provider_user = utils::get_provider_user::<Box<RedditUser>>(
            &self.web_client,
            &tokens.access_token,
            "https://oauth.reddit.com/api/v1/me",
        )
        .await?;
        let provider_user_id = provider_user.id.clone();
        Ok(ValidationResult {
            tokens,
            provider_user,
            auth_info: AuthInfo {
                provider_id: PROVIDER_ID,
                provider_user_id,
            },
        })
    }
}

impl RedditProvider {
    async fn get_tokens(&self, code: String) -> Result<Tokens, OAuthError> {
        let token_result = self
            .client
            .exchange_code(AuthorizationCode::new(code))
            .request_async(async_http_client)
            .await
            .map_err(|err| OAuthError::RequestError(Box::new(err)))?;
        let access_token = token_result.access_token().secret().to_string();
        Ok(Tokens {
            access_token,
            expiration_info: None,
            scope: None,
        })
    }
}

#[derive(Deserialize, Debug, Clone)]
pub struct RedditUser {
    pub is_employee: bool,
    pub seen_layout_switch: bool,
    pub has_visited_new_profile: bool,
    pub pref_no_profanity: bool,
    pub has_external_account: bool,
    pub pref_geopopular: String,
    pub seen_redesign_modal: bool,
    pub pref_show_trending: bool,
    pub subreddit: Subreddit,
    pub pref_show_presence: bool,
    pub snoovatar_img: String,
    pub snoovatar_size: (i64, i64),
    pub gold_expiration: Value,
    pub has_gold_subscription: bool,
    pub is_sponsor: bool,
    pub num_friends: i64,
    pub features: Features,
    pub can_edit_name: bool,
    pub verified: bool,
    pub pref_autoplay: bool,
    pub coins: i64,
    pub has_paypal_subscription: bool,
    pub has_subscribed_to_premium: bool,
    pub id: String,
    pub has_stripe_subscription: bool,
    pub oauth_client_id: String,
    pub can_create_subreddit: bool,
    pub over_18: bool,
    pub is_gold: bool,
    pub is_mod: bool,
    pub awarder_karma: i64,
    pub suspension_expiration_utc: Value,
    pub has_verified_email: bool,
    pub is_suspended: bool,
    pub pref_video_autoplay: bool,
    pub has_android_subscription: bool,
    pub in_redesign_beta: bool,
    pub icon_img: String,
    pub pref_nightmode: bool,
    pub awardee_karma: i64,
    pub hide_from_robots: bool,
    pub password_set: bool,
    pub link_karma: i64,
    pub force_password_reset: bool,
    pub total_karma: i64,
    pub seen_give_award_tooltip: bool,
    pub inbox_count: i64,
    pub seen_premium_adblock_modal: bool,
    pub pref_top_karma_subreddits: bool,
    pub pref_show_snoovatar: bool,
    pub name: String,
    pub pref_clickgadget: i64,
    pub created: i64,
    pub gold_creddits: i64,
    pub created_utc: i64,
    pub has_ios_subscription: bool,
    pub pref_show_twitter: bool,
    pub in_beta: bool,
    pub comment_karma: i64,
    pub accept_followers: bool,
    pub has_subscribed: bool,
    pub linked_identities: Vec<Value>,
    pub seen_subreddit_chat_ftux: bool,
}

#[derive(Deserialize, Debug, Clone)]
pub struct Subreddit {
    pub default_set: bool,
    pub user_is_contributor: bool,
    pub banner_img: String,
    pub restrict_posting: bool,
    pub user_is_banned: bool,
    pub free_form_reports: bool,
    pub community_icon: String,
    pub show_media: bool,
    pub icon_color: String,
    pub user_is_muted: bool,
    pub display_name: String,
    pub header_img: String,
    pub title: String,
    pub coins: i64,
    pub previous_names: Vec<String>,
    pub over_18: bool,
    pub icon_size: (i64, i64),
    pub primary_color: String,
    pub icon_img: String,
    pub description: String,
    pub allowed_media_in_comments: Vec<Value>,
    pub submit_link_label: String,
    pub header_size: Value,
    pub restrict_commenting: bool,
    pub subscribers: i64,
    pub submit_text_label: String,
    pub is_default_icon: bool,
    pub link_flair_position: String,
    pub display_name_prefixed: String,
    pub key_color: String,
    pub name: String,
    pub is_default_banner: bool,
    pub url: String,
    pub quarantine: bool,
    pub banner_size: (i64, i64),
    pub user_is_moderator: bool,
    pub accept_followers: bool,
    pub public_description: String,
    pub link_flair_enabled: bool,
    pub disable_contributor_requests: bool,
    pub subreddit_type: String,
    pub user_is_subscriber: bool,
}

#[derive(Deserialize, Debug, Clone)]
pub struct Features {
    pub mod_service_mute_writes: bool,
    pub promoted_trend_blanks: bool,
    pub show_amp_link: bool,
    pub chat: bool,
    pub is_email_permission_required: bool,
    pub mod_awards: bool,
    pub expensive_coins_package: bool,
    pub mweb_xpromo_revamp_v2: Mweb,
    pub awards_on_streams: bool,
    pub mweb_xpromo_modal_listing_click_daily_dismissible_ios: bool,
    pub chat_subreddit: bool,
    pub cookie_consent_banner: bool,
    pub modlog_copyright_removal: bool,
    pub do_not_track: bool,
    pub images_in_comments: bool,
    pub mod_service_mute_reads: bool,
    pub chat_user_settings: bool,
    pub use_pref_account_deployment: bool,
    pub mweb_xpromo_interstitial_comments_ios: bool,
    pub mweb_xpromo_modal_listing_click_daily_dismissible_android: bool,
    pub premium_subscriptions_table: bool,
    pub mweb_xpromo_interstitial_comments_android: bool,
    pub crowd_control_for_post: bool,
    pub mweb_nsfw_xpromo: Mweb,
    pub noreferrer_to_noopener: bool,
    pub chat_group_rollout: bool,
    pub resized_styles_images: bool,
    pub spez_modal: bool,
    pub mweb_sharing_clipboard: Mweb,
}

#[derive(Deserialize, Debug, Clone)]
pub struct Mweb {
    pub owner: String,
    pub variant: String,
    pub experiment_id: i64,
}
