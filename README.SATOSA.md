# SATOSA backend setup

To install the OpenID4VP SATOSA backend you just need to:

1. install this package and the extra dependencies: `pip install pyeudiw[satosa]`
2. copy and customize [example/satosa/pyeudiw_backend.yaml](example/satosa/pyeudiw_backend.yaml)
3. copy and customize the content of the folders [static](example/satosa/static) and [templates](example/satosa/templates) to your satosa deployment.
4. include the backend configuration in your satosa configuration
5. customize the file `internal_attributes.yaml` used in your deployment, enabling the `openid4vp` protocol. See [example/satosa/internal_attributes.yaml](example/satosa/internal_attributes.yaml) as example. 
6. start Satosa.

## Backend configuration

1. Customize [example/satosa/pyeudiw_backend.yaml](example/satosa/pyeudiw_backend.yaml), then copy it in your satosa `plugins/backend` project folder. Example `plugins/backends/pyeudiw_backend.yaml`;
2. Add `  - "plugins/backends/pyeudiw_backend.yaml"` in your SATOSA `proxy_conf.yaml` file, within the section `BACKEND_MODULES`;
3. Add `  - "plugins/microservices/disco_to_target_issuer.yaml"` and `  - "plugins/microservices/target_based_routing.yaml"` in your SATOSA `proxy_conf.yaml` file, within the section `MICRO_SERVICES`;
4. In `plugins/microservices/target_based_routing.yaml` please add `    "https://eudi.wallet.gov.it": "OpenID4VP"`
5. Customize [example/satosa/static/disco.html](example/satosa/static/disco.html), then copy it in satosa static file folder. Example `example/static/static/disco.html`
6. Customize [example/satosa/templates/*.html](example/satosa/templates/*.html), then copy it in satosa templates file folder (the path your have configured in your `pyeudiw_backend.yaml` file).
7. Customize [example/satosa/internal_attributes.yaml](example/satosa/internal_attributes.yaml), then copy it the path your have configured in your `proxy_conf.yaml` file).

### Backend Configuration Parameters

#### Top-Level

| Parameter | Description                                        | Example value                           |
|-----------|----------------------------------------------------|-----------------------------------------|
| module    | The name of the module that implements the backend | pyeudiw.satosa.backend.OpenID4VPBackend |
| name      | The name of the backend                            | OpenID4VP                               |

#### Config

##### UI

| Parameter                    | Description                                   | Example value                     |
|------------------------------|-----------------------------------------------|-----------------------------------|
| config.ui.static_storage_url | The URL of the static storage for the UI      | https://localhost/static          |
| config.ui.template_folder    | The folder where the UI templates are located | templates                         |
| config.ui.qrcode_template    | The name of the template for the QR code      | qr_code.html                      |
| config.ui.error_template     | The name of the template for the error page   | error.html                        |
| config.ui.error_url          | The URL of the error page                     | https://localhost/error_page.html |

##### Endpoints

| Parameter                             | Description                                       | Example value                  |
|---------------------------------------|---------------------------------------------------|--------------------------------|
| config.endpoints.pre_request          | The endpoint for the pre-request                  | /pre-request                   |
| config.endpoints.response             | The endpoint for the response                     | /response-uri                  |
| config.endpoints.request              | The endpoint for the request                      | /request-uri                   |
| config.endpoints.entity_configuration | The endpoint to retrieve the entity configuration | /.well-known/openid-federation |
| config.endpoints.status               | The endpoint for the status                       | /status                        |
| config.endpoints.get_response         | The endpoint for the get response                 | /get-response                  |

##### QR Code

| Parameter                     | Description                                        | Example value |
|-------------------------------|----------------------------------------------------|---------------|
| config.qrcode.size            | The size of the QR code in pixels                  | 100           |
| config.qrcode.color           | The color of the QR code in hexadecimal            | #2B4375       |
| config.qrcode.expiration_time | The expiration time of the QR code in seconds      | 120           |
| config.qrcode.logo_path       | The path of the logo to be embedded in the QR code |               |
| config.qrcode.use_zlib        | Whether to use zlib compression for the QR code    | false         |

##### JWT

| Parameter                      | Description                                             | Example value                                                                     |
|--------------------------------|---------------------------------------------------------|-----------------------------------------------------------------------------------|
| config.jwt.default_sig_alg     | The default signature algorithm for the JWT             | ES256                                                                             |
| config.jwt.default_enc_alg     | The default encryption algorithm for the JWT            | RSA-OAEP                                                                          |
| config.jwt.default_enc_enc     | The default encryption encoding for the JWT             | A256CBC-HS512                                                                     |
| config.jwt.default_exp         | The default expiration time for the JWT in minutes      | 6                                                                                 |
| config.jwt.enc_alg_supported   | The list of supported encryption algorithms for the JWT | [RSA-OAEP, RSA-OAEP-256, ECDH-ES, ECDH-ES+A128KW, ECDH-ES+A192KW, ECDH-ES+A256KW] |
| config.jwt.enc_enc_supported   | The list of supported encryption encodings for the JWT  | [A128CBC-HS256, A192CBC-HS384, A256CBC-HS512, A128GCM, A192GCM, A256GCM]          |
| config.jwt.sig_alg_supported   | The list of supported signature algorithms for the JWT  | [RS256, RS384, RS512, ES256, ES384, ES512]                                        |

##### Authorization

| Parameter                                      | Description                                                                    | Example value                                 |
|------------------------------------------------|--------------------------------------------------------------------------------|-----------------------------------------------|
| config.authorization.url_scheme                | The URL scheme for the authorization                                           | eudiw                                         |
| config.authorization.scopes                    | The list of scopes for the authorization                                       | [pid-sd-jwt:unique_id+given_name+family_name] |
| config.authorization.default_acr_value         | The default authentication context class reference value for the authorization | https://www.spid.gov.it/SpidL2                |

##### User Attributes

| Parameter                                      | Description                                                                    | Example value            |
|------------------------------------------------|--------------------------------------------------------------------------------|--------------------------|
| config.user_attributes.unique_identifiers      | The list of unique identifiers for the user attributes                         | [tax_id_code, unique_id] |
| config.user_attributes.subject_id_random_value | A random value to be used in hashing                                           | CHANGE_ME!               |

##### Network

| Parameter                                   | Description                                                     | Example Value |
|---------------------------------------------|-----------------------------------------------------------------|---------------|
| config.network.httpc_params.connection.ssl  | The flag to indicate whether to use SSL for the HTTP connection | true          |
| config.network.httpc_params.session.timeout | The timeout value for the HTTP session                          | 6             |

##### Federation

| Parameter                                                      | Description                                               | Example Value                                                            |
|----------------------------------------------------------------|-----------------------------------------------------------|--------------------------------------------------------------------------|
| config.federation.metadata_type                                | The type of metadata to use for the federation            | wallet_relying_party                                                     |
| config.federation.authority_hints                              | The list of authority hints to use for the federation     | [http://127.0.0.1:10000]                                                 |
| config.federation.trust_anchors                                | The list of trust anchors to use for the federation       | [http://127.0.0.1:10000]                                                 |
| config.federation.default_sig_alg                              | The default signature algorithm to use for the federation | RS256                                                                    |
| config.federation.federation_entity_metadata.organization_name | The organization name                                     | Developers Italia SATOSA OpenID4VP backend policy_uri, tos_uri, logo_uri |
| config.federation.federation_entity_metadata.homepage_uri      | The URI of the homepage                                   | https://developers.italia.it                                             |
| config.federation.federation_entity_metadata.policy_uri        | The URI of the policy                                     | https://developers.italia.it/policy.html                                 |
| config.federation.federation_entity_metadata.tos_uri           | The URI of the TOS                                        | https://developers.italia.it/tos.html                                    |
| config.federation.federation_entity_metadata.logo_uri          | The URI of the logo                                       | https://developers.italia.it/assets/icons/logo-it.svg                    |
| config.federation.federation_jwks                              | The list of (private) JSON Web Keys for the federation    |                                                                          |

##### Metadata jwks

| Parameter            | Description                                          | Example Value |
|----------------------|------------------------------------------------------|---------------|
| config.metadata_jwks | The list of (private) JSON Web Keys for the metadata |               |


##### Storage

| Parameter                                                                         | Description                                            | Example Value                 |
|-----------------------------------------------------------------------------------|--------------------------------------------------------|-------------------------------|
| config.storage.mongo_db.cache.module                                              | The module name for the MongoDB cache                  | pyeudiw.storage.mongo_cache   |
| config.storage.mongo_db.cache.class                                               | The class name for the MongoDB cache                   | MongoCache                    |
| config.storage.mongo_db.cache.init_params.url                                     | The URL for the MongoDB connection                     | mongodb://satosa-mongo:27017  |
| config.storage.mongo_db.cache.init_params.conf.db_name                            | The database name for the MongoDB cache                | eudiw                         |
| config.storage.mongo_db.cache.connection_params.username                          | The username for authentication to the database        | satosa                        |
| config.storage.mongo_db.cache.connection_params.password                          | The password for authentication to the database        | thatpassword                  |
| config.storage.mongo_db.storage.module                                            | The python module that implements the storage class    | pyeudiw.storage.mongo_storage |
| config.storage.mongo_db.storage.class                                             | The name of the storage class                          | MongoStorage                  |
| config.storage.mongo_db.storage.init_params.url                                   | The URL of the mongodb server                          | mongodb://satosa-mongo:27017  |
| config.storage.mongo_db.storage.init_params.conf.db_name                          | The name of the database to use for storage            | eudiw                         |
| config.storage.mongo_db.storage.init_params.conf.db_sessions_collection           | The name of the collection to store sessions           | sessions                      |
| config.storage.mongo_db.storage.init_params.conf.db_trust_attestations_collection | The name of the collection to store trust attestations | trust_attestations            |
| config.storage.mongo_db.storage.init_params.conf.db_trust_anchors_collection      | The name of the collection to store trust anchors      | trust_anchors                 |
| config.storage.mongo_db.storage.connection_params.username                        | The username for authentication to the database        | satosa                        |
| config.storage.mongo_db.storage.connection_params.password                        | The password for authentication to the database        | thatpassword                  |

##### Metadata

| Parameter                                              | Description                                                                              | Example value                                                    |
|--------------------------------------------------------|------------------------------------------------------------------------------------------|------------------------------------------------------------------|
| config.metadata.application_type                       | The type of application that uses the OpenID Connect protocol                            | web                                                              |
| config.metadata.authorization_encrypted_response_alg   | The algorithm used to encrypt the authorization response                                 | `<jwt.enc_alg_supported>`                                        |
| config.metadata.authorization_encrypted_response_enc   | The encryption method used to encrypt the authorization response                         | `<jwt.enc_enc_supported>`                                        |
| config.metadata.authorization_signed_response_alg      | The algorithm used to sign the authorization response                                    | `<jwt.sig_alg_supported>`                                        |
| config.metadata.client_id                              | The unique identifier of the client                                                      | https://example.org/verifier                                     |
| config.metadata.client_name                            | The human-readable name of the client                                                    | Name of an example organization                                  |
| config.metadata.contacts                               | The list of email addresses of the client's contacts                                     | [ops@verifier.example.org]                                       |
| config.metadata.default_acr_values                     | The list of default authentication context class references that the client requests     | [https://www.spid.gov.it/SpidL2, https://www.spid.gov.it/SpidL3] |
| config.metadata.default_max_age                        | The default maximum amount of time that the authentication session is valid              | 1111                                                             |
| config.metadata.id_token_encrypted_response_alg        | The algorithm used to encrypt the ID token response                                      | `<jwt.enc_alg_supported>`                                        |
| config.metadata.id_token_encrypted_response_enc        | The encryption method used to encrypt the ID token response                              | `<jwt.enc_enc_supported>`                                        |
| config.metadata.id_token_signed_response_alg           | The algorithm used to sign the ID token response                                         | `<jwt.sig_alg_supported>`                                        |
| config.metadata.presentation_definition                | The object that defines the presentation request                                         | [Presentation definition](#presentation-definition)              |
| config.metadata.redirect_uris                          | The list of URIs that the client can use to receive the authorization response           | https://example.org/verifier/redirect-uri                        |
| config.metadata.request_uris                           | The list of URIs that the client can use to request the authorization                    | https://example.org/verifier/request-uri                         |
| config.metadata.require_auth_time                      | The boolean value that indicates whether the auth_time claim is required in the ID token | true                                                             |
| config.metadata.subject_type                           | The subject identifier type that the client requests                                     | pairwise                                                         |
| config.metadata.vp_formats.vc+sd-jwt.sd-jwt_alg_values | VP formats specification algorithms for SD-JWT                                           | [ES256, ES384]                                                   |
| config.metadata.vp_formats.vc+sd-jwt.kb-jwt_alg_values | VP formats specification algorithms for Key Binding JWT                                  | [ES256, ES384]                                                   |

###### Presentation definition

| Parameter                                                            | Description                                                                                           | Example value                                  |
|----------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------|------------------------------------------------|
| config.metadata.presentation_definition.id                           | The unique identifier of the presentation definition                                                  | d76c51b7-ea90-49bb-8368-6b3d194fc131           |
| config.metadata.presentation_definition.input_descriptors            | The list of input descriptors that specify the verifiable credentials that the client requests        | See below                                      |
| config.metadata.presentation_definition.id                           | The unique identifier of the input descriptor                                                         | IdentityCredential                             |
| config.metadata.presentation_definition.format                       | The object that defines the verifiable credential format that the client requests                     | vc+sd-jwt: {}                                  |
| config.metadata.presentation_definition.constraints                  | The object that defines the constraints on the verifiable credential                                  | See below                                      |
| config.metadata.presentation_definition.constraints.limit_disclosure | The string that indicates whether the client requests minimal disclosure of the verifiable credential | required                                       |
| config.metadata.presentation_definition.constraints.fields           | The list of objects that define the fields that the client requests in the verifiable credential      | See below                                      |
| config.metadata.presentation_definition.constraints.fields.path      | The list of strings that define the JSON path to the field in the verifiable credential               | ["$.vct"], ["$.family_name"], ["$.given_name"] |
| config.metadata.presentation_definition.constraints.fields.filter    | The object that defines the filter criteria for the field in the verifiable credential                | type: string, const: IdentityCredential        |


## NginX

Configure an httpd fronted such NginX, an example is available within the `uwsgi_setup` folder of [Satosa-Saml2Spid](https://github.com/italia/Satosa-Saml2Spid/tree/master/example/uwsgi_setup) 
remember to customize and add any additional parameter to your preferred httpd configuration.


