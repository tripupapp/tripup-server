# TripUp Server
![GitHub](https://img.shields.io/github/license/tripupapp/tripup-server)
![Neo4j 3.3.2](https://img.shields.io/badge/Neo4j-3.3.2-blue.svg)
![Go 1.11.5](https://img.shields.io/badge/Go-1.11.5-blue.svg)

Server code for [TripUp](https://tripup.app), an open source, photo storage and sharing app made for privacy conscious users.

## Questions and Support
Please use the following channels for any questions or support:
- [GitHub Discussions](https://github.com/tripupapp/tripup-server/discussions)
- [Reddit](https://reddit.com/r/tripup)
- [Discord Channel](https://discord.gg/5xCF7Eb)

❗ Please **DO NOT** use the GitHub issue tracker for support queries. ❗️

## Build Instructions

### Dependencies
- Go 1.11.5
- Neo4j 3.3.2
- Firebase, for authentication.
- AWS, for data storage.
- OneSignal, for notifications.

*Note: where possible, analytics are disabled for the above services.*

### Steps
1. Build the server binary by running the following commands:
    ```bash
    > go version
    go version go1.11.5 darwin/amd64
    > cd /path/to/server-code && go get -u
    > cd /path/to/server-code && env GO111MODULE=on go build
    ```
2. Set the environment variables as appropriate for your shell. Example for `bash`:
    ```bash
    #!/bin/sh
    > export TRIPUP_NEO_USER="NEO4J_USERNAME"                         # "neo4j"
    > export TRIPUP_NEO_PASS="NEO4J_PASSWORD"                         # "neo4j"
    > export TRIPUP_NEO_HOST="NEO4J_INSTANCE_HOSTNAME"                # "localhost"
    > export TRIPUP_NEO_PORT="NEO4J_INSTANCE_BOLT_PORT"               # "7687"
    > export TRIPUP_SERVER_PORT="SERVER_INCOMING_PORT"                # "8080"
    > export TRIPUP_SERVER_TIMEOUT="SECONDS_TO_CONNECTION_TIMEOUT"    # "10s"
    > export TRIPUP_SERVER_MAX_REQ="MAX_NUMBER_OF_REQUESTS"           # "10"
    > export AWS_REGION="AWS_BUCKET_REGION"                           # "eu-west-2"
    > export AWS_ACCESS_KEY_ID="AWS_ACCESS_KEY_ID"
    > export AWS_SECRET_ACCESS_KEY="AWS_SECRET_ACCESS_KEY"
    > export GOOGLE_APPLICATION_CREDENTIALS="/path/to/google-service-account-key.json"
    > export ONESIGNAL_APPID="ONESIGNAL_APPID"
    > export ONESIGNAL_APIKEY="ONESIGNAL_APIKEY"
    ```
    See https://firebase.google.com/docs/admin/setup#initialize-sdk for instructions on how to obtain your Google Service Account JSON key.

3. With the environment variables set, run the binary in the same session:
    ```bash
    > ./appserver
    [INFO] ServerLog: 2021/05/26 21:12:27 server initialised successfully, listening on port 8080
    ```

## Usage instructions
- This server follows REST style.
- All end points are protected and require a valid JWT token. Therefore, authorisation via the auth provider (currently Firebase) is required in order to obtain a valid Authorization Bearer token.
- All user data is end-to-end encrypted, so even after authorisation, data returned will be in PGP encrypted format. The users private key(s) will be required to derive the actual data.

### API endpoints
⚠️ API is subject to change and there are no guarantees regarding backward compatibility for the moment.

TODO: improve documentation
```
    /ping
        GET     /               ping tripup server

    /users
        POST    /               create user
        POST    /public         get a user from contact info
        GET     /self           get caller UUID
        PUT     /self/contact   update caller contact info
        GET     /{userID}       get a user from userID

    /assets
        GET     /                   get callers assets
        POST    /                   create asset for caller
        PATCH   /                   modify callers assets
        PATCH   /original           modify callers assets original path
        PUT     /{assetID}/original replace original path for assetID

    /groups
        GET     /                   get callers groups
        POST    /                   create group for caller
        GET     /album              get assets for all groups of caller
        PUT     /{groupID}          caller joins group
        DELETE  /{groupID}          caller leaves group
        GET     /{groupID}/users        get list of users in group
        PATCH   /{groupID}/users        modify users in group
        PATCH   /{groupID}/album        modify group asset list
        PATCH   /{groupID}/album/shared modify groups shared asset list

    /info
        POST    /validids   validate UUIDs

    /schema
        GET     /0          gets any schema 0 data for caller
        PATCH   /0          patch schema 0 data for caller to schema 1
```

## Contributing
There are many ways to contribute to TripUp!

### Bug reports
We use the [GitHub issue tracker](https://github.com/tripupapp/tripup-server/issues) for bug reports. Please search existing issues and create a new one if your bug report has not been raised, providing as much detail as possible.

🛑 **Please DO NOT bump an issue with +1 posts that do not add to the discussion. Use the emoji reactions instead to show that an issue affects you too; we will prioritise issues that have the most reactions.** 🛑

### Code
We welcome developers (new and experienced) to contribute. We use [GitHub projects](https://github.com/tripupapp/tripup-server/projects) for coordinating our work. If you require help with a code change, feel free to open a pull request.

### Feature suggestions
Please use [GitHub Discussions](https://github.com/tripupapp/tripup-server/discussions) to suggest new features.

## License
This project is licensed under the AGPLv3. Please see the LICENSE file for the full license terms.

Please note that whilst the code is licensed under the AGPLv3, all assets, logos and branding, including the name, are subject to relevant trademark laws and explicit permission is required before using these for any commercial purposes.
