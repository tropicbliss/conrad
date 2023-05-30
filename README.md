# conrad-auth

An authentication framework with an API heavily inspired by [Lucia](https://lucia-auth.com/?). It has support for OAuth and token-based authentication.

## Caveats
- This currently has support for database adapters, but no adapters has been written for it yet. Perhaps there will be one in the future when I am less burned out.
- It also does not have a support crate to translate request types from web frameworks such as Axum to Conrad's `Request` type. Like I said, I don't feel like working on this project at the moment.
- Documentation is non-existent, but you should be able to get around by referencing Lucia's docs instead.
