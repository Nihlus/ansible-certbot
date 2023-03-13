#!/usr/bin/env python3

from __future__ import (absolute_import, division, print_function, annotations)
__metaclass__ = type

import subprocess

DOCUMENTATION = r'''
---
module: certbot_certificate
short_description: Manages certificates handled by certbot
version_added: "1.0.0"
description:  This module is used to manage certificates handled by certbot, creating or renewing them as appropriate.

options:
    state:
        description: 
            - The state of the certificate(s) after the module has run.
            - "present" indicates that certificates that do not exist should be issued and certificates due for renewal should be renewed.
            - "absent" indicates that certificates should be deleted from the filesystem.
            - "revoked" indicates that certificates should be revoked and optionally retained on the filesystem.
            - "renewed" indicates that certificates should be forcibly renewed regardless of their expiry dates.
        required: false
        type: str
        choices:
            - present
            - absent
            - revoked
            - renewed
        default: present
    install:
        description: Whether to install the certificates in the current web server.
        required: false
        type: bool
        default: true
    cert_name: 
        description: The name of the certificate.
        required: false
        type: str
        aliases:
            - name
    domains:
        description: The domains of the certificates to operate on.
        required: false
        type: list
        elements: str
    eab_kid:
        description: Key Identifier for External Account Binding.
        required: false
        type: str
    eab_hmac_key:
        description: HMAC Key for External Account Binding
        required: false
        type: str
    keep_until_expiring:
        description: If the requested certificate matches an existing certificate, always keep the existing one until it is due for renewal.
        required: false
        type: bool
    preferred_chain:
        description: If the CA offers multiple certificate chains, prefer the chain whose topmost certificate was issued from this Subject Common Name. If no match, the default offered chain will be used.
        required: false
        type: str
    test_cert:
        description: Use the staging server to obtain or revoke test (invalid) certificates; equivalent to --server https://acme-staging-v02.api.letsencrypt.org/director
        required: false
        type: bool
    allow_subset_of_names:
        description: When performing domain validation, do not consider it a failure if authorizations can not be obtained for a strict subset of the requested domains.
        required: false
        type: bool
    preferred_challenges:
        description: A sorted list of the preferred challenge to use during authorization with the most preferred challenge listed first.
        required: false
        type: list
        elements: str
    csr:
        description: Path to a Certificate Signing Request (CSR) in DER or PEM format.
        required: false
        type: path
    cert_path:
        description: Path to where certificate is saved (with auth --csr), installed from, or revoked.
        required: false
        type: path
    pre_hook:
        description: Command to be run in a shell before obtaining any certificates. Intended primarily for renewal, where it can be used to temporarily shut down a webserver that might conflict with the standalone plugin. This will only be called if a certificate is actually to be obtained/renewed. When renewing several certificates that have identical pre-hooks, only the first will be executed.
        required: false
        type: path
    post_hook:
        description: Command to be run in a shell after attempting to obtain/renew certificates. Can be used to deploy renewed certificates, or to restart any servers that were stopped by --pre-hook. This is only run if an attempt was made to obtain/renew a certificate. If multiple renewed certificates have identical post-hooks, only one will be run.
        required: false
        type: path
    deploy_hook:
        description: Command to be run in a shell once for each successfully issued certificate. For this command, the shell variable $RENEWED_LINEAGE will point to the config live subdirectory (for example, "/etc/letsencrypt/live/example.com") containing the new certificates and keys; the shell variable $RENEWED_DOMAINS will contain a space-delimited list of renewed certificate domains (for example, "example.com www.example.com").
        required: false
        type: path
    disable_hook_validation
        description: Ordinarily the commands specified for --pre-hook/--post-hook/--deploy-hook will be checked for validity, to see if the programs being run are in the $PATH, so that mistakes can be caught early, even when the hooks aren't being run just yet. The validation is rather simplistic and fails if you use more advanced shell constructs, so you can use this switch to disable it.
        required: false
        type: bool
    no_directory_hooks:
        description: Disable running executables found in Certbot's hook directories during renewal.
        required: false
        type: bool
    disable_renew_updates
        description: Disable automatic updates to your server configuration that would otherwise be done by the selected installer plugin, and triggered when the user executes "certbot renew", regardless of if the certificate is renewed. This setting does not apply to important TLS configuration updates. 
        required: false
        type: bool
    no_autorenew
        description: Disable auto renewal of certificates.
        required: false
        type: bool
    reason:
        description: Specify the reason for revoking certificate.
        required: false
        type: str
        choices:
            - unspecified
            - keycompromise
            - affiliationchange
            - superseded
            - cessationofoperation
    delete_after_revoke:
        description: Delete certificates after revoking them, along with all previous and later versions of those certificates.
        required: false
        type: bool
    no_delete_after_revoke:
        description: Do not delete certificates after revoking them. This option should be used with caution because the 'renew' subcommand will attempt to renew undeleted revoked certificates. 
        required: false
        type: bool 
    key_path:
        description: Path to private key for certificate installation or revocation (if account key is missing).
        required: false
        type: path
    authentication:
        description: The authentication method to use when creating or renewing certificates
        required: false
        type: str
        choices:
            - apache
            - standalone
            - nginx
            - webroot
            - dns-cloudflare
            - dns-cloudxns
            - dns-digitalocean
            - dns-dnsimple
            - dns-dnsmadeeasy
            - dns-gehirn
            - dns-google
            - dns-linode
            - dns-nsone
            - dns-ovh
            - dns-rfc2136
            - dns-route53
            - dns-sakuracloud
    break_my_certs:
        description: 
            - Whether to allow replacement of seemingly valid certificates with invalid test certificates. 
            - USE WITH CAUTION.
        required: false
        type: bool
        default: false
author:
    - Jarl Gullberg <jarl.gullberg@gmail.com>
'''

EXAMPLES = r'''
# Issue or renew named certificate and install it into your current webserver (run)
- name: ensure certificate is present, valid, and installed
  certbot_certificate:
    cert_name: example.com
    state: present

# Use a different authentication scheme
- name: ensure certificate is present, valid, and installed
  certbot_certificate:
    cert_name: example.com
    authentication: apache
    state: present

# Issue or renew named certificate without installing it (certonly)
- name: ensure certificate is present, valid, and installed
  certbot_certificate:
    cert_name: example.com
    install: false
    state: present
    
# Forcibly renew certificates
- name: renew certificate (renew)
  certbot_certificate:
    cert_name: example.com
    state: renewed
    
# Revoke and delete certificate
- name: revoke certificate (revoke)
  certbot_certificate:
    cert_name: example.com
    state: revoked
    
# Revoke and keep certificate
- name: revoke certificate (revoke)
  certbot_certificate:
    cert_name: example.com
    no_delete_after_revoke: true
    state: revoked

# Delete certificate from filesystem
- name: delete certificate (delete)
  certbot_certificate:
    cert_name: example.com
    state: absent
'''

RETURN = r'''
actions_taken:
    - cert_name: example.com
      action: renew
      changed: true
certbot_stdout: ...
certbot_stderr: ...
'''

from pathlib import Path
from typing import Callable, Any
from ansible.module_utils.basic import AnsibleModule

try:
    from ansible.module_utils.certbot_cli import Certbot
    from ansible.module_utils.certbot_cli import CertbotResult
    from ansible.module_utils.certbot_commands import CertbotAuthentication
    from ansible.module_utils.certbot_commands import CertbotRevocationReason
    from ansible.module_utils.certbot_info import CertbotCertificateActionInformation
except ModuleNotFoundError:
    from module_utils.certbot_cli import Certbot
    from module_utils.certbot_cli import CertbotResult
    from module_utils.certbot_commands import CertbotAuthentication
    from module_utils.certbot_commands import CertbotRevocationReason
    from module_utils.certbot_info import CertbotCertificateActionInformation


def get_param_or_none(params: dict, param_name: str, map_function: Callable[[Any], Any] | None = None):
    value = params.get(param_name)
    if not value:
        return None

    if map_function is not None:
        return map_function(value)
    else:
        return value


def run_module():
    module_args = dict(
        state=dict(type='str', required=False, choices=['present', 'absent', 'revoked', 'renewed'], default='present'),
        install=dict(type='bool', required=False, default=True),
        cert_name=dict(type='str', required=False, aliases=['name']),
        domains=dict(type='list', required=False, elements='str'),
        eab_kid=dict(type='str', required=False),
        eab_hmac_key=dict(type='str', required=False),
        keep_until_expiring=dict(type='bool', required=False),
        preferred_chain=dict(type='str', required=False),
        test_cert=dict(type='bool', required=False),
        allow_subset_of_names=dict(type='bool', required=False),
        preferred_challenges=dict(type='list', required=False, elements='str'),
        csr=dict(type='path', required=False),
        cert_path=dict(type='path', required=False),
        pre_hook=dict(type='path', required=False),
        post_hook=dict(type='path', required=False),
        deploy_hook=dict(type='path', required=False),
        disable_hook_validation=dict(type='bool', required=False),
        no_directory_hooks=dict(type='bool', required=False),
        disable_renew_updates=dict(type='bool', required=False),
        no_autorenew=dict(type='bool', required=False),
        reason=dict(
            type='str',
            required=False,
            choices=['unspecified', 'keycompromise', 'affiliationchange', 'superseded', 'cessationofoperation']
        ),
        delete_after_revoke=dict(type='bool', required=False),
        no_delete_after_revoke=dict(type='bool', required=False),
        key_path=dict(type='path', required=False),
        authentication=dict(
            type='str',
            required=False,
            choices=[
                'apache',
                'standalone',
                'nginx',
                'webroot',
                'dns-cloudflare',
                'dns-cloudnxs',
                'dns-digitalocean',
                'dns-dnsimple',
                'dns-dnsmadeeasy',
                'dns-gehirn',
                'dns-google',
                'dns-linode',
                'dns-nsone',
                'dns-ovh',
                'dns-rfc2136',
                'dns-route53',
                'dns-sakuracloud'
            ]
        ),
        break_my_certs=dict(type='bool', required=False)
    )

    result = dict(
        actions_taken=list(dict()),
        changed=False
    )

    module = AnsibleModule(
        argument_spec=module_args,
        required_if=[
            ('state', 'present', ('authentication',)),
            ('state', 'renewed', ('authentication',)),
            ('state', 'revoked', ('authentication', 'reason'))
        ],
        mutually_exclusive=[
            ('delete_after_revoke', 'no_delete_after_revoke')
        ]
    )

    state = module.params['state']

    certbot = Certbot(module.run_command)

    try:
        certbot_result: CertbotResult
        if state == 'present':
            if module.params['install']:
                certbot_result = certbot.run(
                    get_param_or_none(module.params, 'domains'),
                    get_param_or_none(module.params, 'eab_kid'),
                    get_param_or_none(module.params, 'eab_hmac_key'),
                    get_param_or_none(module.params, 'cert_name'),
                    get_param_or_none(module.params, 'keep_until_expiring'),
                    get_param_or_none(module.params, 'preferred_chain'),
                    get_param_or_none(module.params, 'authentication', lambda val: CertbotAuthentication[val]),
                    get_param_or_none(module.params, 'test_cert')
                )
            else:
                certbot_result = certbot.certonly(
                    get_param_or_none(module.params, 'domains'),
                    get_param_or_none(module.params, 'eab_kid'),
                    get_param_or_none(module.params, 'eab_hmac_key'),
                    get_param_or_none(module.params, 'cert_name'),
                    get_param_or_none(module.params, 'keep_until_expiring'),
                    get_param_or_none(module.params, 'preferred_chain'),
                    get_param_or_none(module.params, 'authentication', lambda val: CertbotAuthentication[val]),
                    get_param_or_none(module.params, 'allow_subset_of_names'),
                    get_param_or_none(module.params, 'preferred_challenges'),
                    get_param_or_none(module.params, 'csr', lambda val: Path(val)),
                    get_param_or_none(module.params, 'cert_path', lambda val: Path(val)),
                    get_param_or_none(module.params, 'test_cert')
                )
        elif state == 'absent':
            certbot_result = certbot.delete(get_param_or_none(module.params, 'cert_name'))
        elif state == 'revoked':
            certbot_result = certbot.revoke(
                get_param_or_none(module.params, 'test_cert'),
                get_param_or_none(module.params, 'reason', lambda val: CertbotRevocationReason[val]),
                get_param_or_none(module.params, 'delete_after_revoke'),
                get_param_or_none(module.params, 'no_delete_after_revoke'),
                get_param_or_none(module.params, 'cert_name'),
                get_param_or_none(module.params, 'cert_path', lambda val: Path(val)),
                get_param_or_none(module.params, 'key_path', lambda val: Path(val))
            )
        elif state == 'renewed':
            certbot_result = certbot.renew(
                get_param_or_none(module.params, 'cert_name'),
                True,
                get_param_or_none(module.params, 'allow_subset_of_names'),
                get_param_or_none(module.params, 'preferred_chain'),
                get_param_or_none(module.params, 'preferred_challenges'),
                get_param_or_none(module.params, 'pre_hook', lambda val: Path(val)),
                get_param_or_none(module.params, 'post_hook', lambda val: Path(val)),
                get_param_or_none(module.params, 'deploy_hook', lambda val: Path(val)),
                get_param_or_none(module.params, 'disable_hook_validation'),
                get_param_or_none(module.params, 'no_directory_hooks'),
                get_param_or_none(module.params, 'disable_renew_updates'),
                get_param_or_none(module.params, 'no_autorenew'),
                get_param_or_none(module.params, 'break_my_certs'),
            )
        else:
            raise RuntimeError('Unknown state')

        if certbot_result.actions_taken:
            result['actions_taken'] = list(
                map(lambda a: a.__dict__ | {"action": a.action_name}, certbot_result.actions_taken)
            )

            for action in certbot_result.actions_taken:
                if action.changed:
                    result['changed'] = True
                    break

        module.exit_json(
            certbot_stdout=certbot_result.completed_process.stdout,
            certbot_stderr=certbot_result.completed_process.stderr,
            **result
        )
    except subprocess.CalledProcessError as cpe:
        module.fail_json(msg='certbot command failed', stdout=cpe.stdout, stderr=cpe.stderr, **result)


def main():
    run_module()


if __name__ == '__main__':
    main()
