
# OIDC forwardauth for traefik V2

derived from thomseddon traefik-forward-auth focused on Azure B2C


## Acknowledgements

 - [Thom Seddon's traefik-forward-auth](https://github.com/thomseddon/traefik-forward-auth)

  
## Env variables Reference


| Variable name | Type     | Description                | Default   |
| :-------- | :------- | :------------------------- | :------- |
| `PORT` | `int` | Port the forward auth listens to. | 4181 |
| `INSECURE_COOKIE` | `bool` | Use insecure cookies. | false |
| `LOG_LEVEL` | `string` | Log level. trace \| debug \| info \| error \| fatal \| panic  | error |
| `LOG_FORMAT` | `string` | Log format. pretty\|json\|text  | text |
| `SCOPE` | `string` | space separated list of scopes. | openid profile |
| `PROVIDERS_OIDC_ISSUER_URL` | `string` | **Required**. Issuer URL | |
| `PROVIDERS_OIDC_CLIENT_ID` | `string` | **Required**. Client ID | |
| `PROVIDERS_OIDC_CLIENT_SECRET` | `string` | **Required**. Client Secret | |
| `SECRET` | `string` | **Required**. Secret used for signing | |
| `COOKIE_NAME` | `string` | Cookie name | _forward_auth |
| `CSRF_COOKIE_NAME` | `string` | CSRF Cookie name | _forward_auth_csrf |
| `URL_PATH` | `string` | Callback path | /_oauth |
| `LIFETIME` | `int` | Cookie lifetime | 43200 |
| `AUTH_HOST` | `string` | Authentication host | empty |
| `LOGOUT_REDIRECT` | `string` | Logout redirect url | empty |
| `COOKIE_DOMAIN` | `string` | List of cookie domains | empty |

  
## Appendix

Any additional information goes here

  
## Authors

- [@pnocera](https://www.github.com/pnocera)

  snyk container test scratch --file=Dockerfile