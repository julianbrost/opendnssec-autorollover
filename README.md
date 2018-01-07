# opendnssec-autorollover

A tool for automating DNSSEC key updates in parent zones.

**Warning** opendnssec-autorollover is still in early development, so use it at
your own risk.

opendnssec-autorollover can be run periodically (like from cron) and will
invoke `ods-enforcer` to check for any pending updates for parent zones. It
then invokes a callback for each domain with these changes, which is supposed
to automatically update the DNSKEY/DS records using some API. Finally, it
automatically retrieves all DS records present in the parent zone and issues
`ds-seen`/`ds-gone` commands to OpenDNSSEC accordingly.

## Getting started

You can run opendnssec-autorollover as any user that is allowed to interact
with ods-enforcer. To get started, just do the following:

    git clone https://github.com/julianbrost/opendnssec-autorollover.git
    cd opendnssec-autorollover
    install -m600 config.example.ini config.ini  # use restrictive permissions here, contains API keys
    $EDITOR config.ini  # adapt to your needs, see below for supported registrars and config snippets
    ./opendnssec-autorollover  # and pray... like I said, use at your own risk

## Supported registrars

### Hosting.de

[Create an API key](https://secure.hosting.de/profile/api-keys/create) in their control panel
with at least these permissions:

 * `DOM_DOMAINS_EDIT`
 * `DOM_DOMAINS_EDIT_DNSSEC_DATA`
 * `DOM_DOMAINS_LIST`

Add a snippet like this to `config.ini`:

    [example.com.]
    handler = hosting.de
    auth_token = YOUR_API_KEY_HERE

### Gandi.net

[Create an API key](https://v4.gandi.net/admin/api_key) in the old v4 control
panel. The new control panel doesn't seem to support that feature. Also, as far
as I know, there is no way to restrict this key to specific actions, so it has
full access to your account. Then add a snippet like this to `config.ini`:

    [example.org.]
    handler = gandi.net
    api_key = YOUR_API_KEY_HERE
