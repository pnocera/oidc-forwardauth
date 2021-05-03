
# OIDC forwardauth for traefik V2

derived from thomseddon traefik-forward-auth focused on Azure B2C


## Acknowledgements

 - [Thom Seddon's traefik-forward-auth](https://github.com/thomseddon/traefik-forward-auth)

  
## Env variables Reference


| Variable name | Type     | Description                |
| :-------- | :------- | :------------------------- |
| `PORT` | `string` | Port the forward auth listens to. default 4181 |
| `INSECURE_COOKIE` | `bool` | Use insecure cookies |
| `LOG_LEVEL` | `string` | Log level |
| `SCOPE` | `string` | comma separated list of scopes |
| `PROVIDERS_OIDC_ISSUER_URL` | `string` | **Required**. Issuer URL |
| `PROVIDERS_OIDC_CLIENT_ID` | `string` | **Required**. Client ID |
| `PROVIDERS_OIDC_CLIENT_SECRET` | `string` | **Required**. Client Secret |
| `SECRET` | `string` | **Required**. Secret used for signing |


  
## Appendix

Any additional information goes here

  
## Authors

- [@pnocera](https://www.github.com/pnocera)

  