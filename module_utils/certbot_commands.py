#!/usr/bin/env python3

from __future__ import annotations
from enum import Enum
from pathlib import Path


class CertbotAuthentication(Enum):
    """
    Enumerates available authentication methods for certbot certificate issuance.
    """
    apache: str = 'apache'
    nginx: str = 'nginx'
    standalone: str = 'standalone'
    webroot: str = 'webroot'
    dns_cloudflare: str = 'dns-cloudflare'
    dns_cloudxns: str = 'dns-cloudxns'
    dns_digitalocean: str = 'dns-digitalocean'
    dns_dnsimple: str = 'dns-dnsimple'
    dns_dnsmadeeasy: str = 'dns-dnsmadeeasy'
    dns_gehirn: str = 'dns-gehirn'
    dns_google: str = 'dns-google'
    dns_linode: str = 'dns-linode'
    dns_nsone: str = 'dns-nsone'
    dns_ovh: str = 'dns-ovh'
    dns_rfc2136: str = 'dns-rfc2136'
    dns_route53: str = 'dns-route53'
    dns_sakuracloud: str = 'dns-sakuracloud'


class CertbotRevocationReason(Enum):
    """
    Enumerates various reasons for revoking a certificate.
    """
    unspecified: str = 'unspecified'
    keycompromise: str = 'keycompromise'
    affiliationchange: str = 'affiliationchange'
    superseded: str = 'superseded'
    cessationofoperation: str = 'cessationofoperation'


class __CertbotSubcommand:
    """
    Represents an abstract certbot subcommand.
    """

    subcommand: str
    """
    The name of the subcommand.
    """

    def __init__(self, subcommand: str):
        self.subcommand: str = subcommand

    def build_args(self) -> list[str]:
        """
        Builds appropriate command-line arguments for the subcommand.
        :return: A list of arguments.
        """
        return [self.subcommand, '-n']


class __CertbotCertificateAction(__CertbotSubcommand):
    """
    Represents an abstract certbot action on a certificate.
    """

    domains: list[str] | None
    """
    Domain names to apply. The first domain provided will be the subject CN of the certificate, and all domains will be 
    Subject Alternative Names on the certificate. The first domain will also be used in some software user interfaces 
    and as the file paths for the certificate and related material unless otherwise specified or you already have a 
    certificate with the same name. In the case of a name collision it will append a number like 0001 to the file path 
    name.
    """

    eab_kid: str | None
    """
    Key Identifier for External Account Binding.
    """

    eab_hmac_key: str | None
    """
    HMAC key for External Account Binding.
    """

    cert_name: str | None
    """
    Certificate name to apply. This name is used by Certbot for housekeeping and in file paths; it doesn't affect the 
    content of the certificate itself.
    """

    keep_until_expiring: bool | None
    """
    If the requested certificate matches an existing certificate, always keep the existing one until it is due for 
    renewal.
    """

    preferred_chain: str | None
    """
    If the CA offers multiple certificate chains, prefer the chain whose topmost certificate was issued from this 
    Subject Common Name. If no match, the default offered chain will be used.
    """

    authentication: CertbotAuthentication | None
    """
    The authentication scheme to use when issuing or renewing certificates.
    """

    def __init__(
            self,
            subcommand: str,

            domains: list[str] | None = None,
            eab_kid: str | None = None,
            eab_hmac_key: str | None = None,
            cert_name: str | None = None,
            keep_until_expiring: bool | None = None,
            preferred_chain: str | None = None,
            authentication: CertbotAuthentication | None = None
    ):
        super().__init__(subcommand)

        self.domains = domains
        self.eab_kid = eab_kid
        self.eab_hmac_key = eab_hmac_key
        self.cert_name = cert_name
        self.keep_until_expiring = keep_until_expiring
        self.preferred_chain = preferred_chain
        self.authentication = authentication

    def build_args(self) -> list[str]:
        args: list[str] = super().build_args()

        if self.domains:
            for domain in self.domains:
                args.append('-d')
                args.append(domain)

        if self.eab_kid:
            args.append('--eab-kid')
            args.append(self.eab_kid)

        if self.eab_hmac_key:
            args.append('--eab-hmac-key')
            args.append(self.eab_hmac_key)

        if self.cert_name:
            args.append('--cert-name')
            args.append(self.cert_name)

        if self.keep_until_expiring:
            args.append('--keep-until-expiring')

        if self.preferred_chain:
            args.append('--preferred-chain')
            args.append(self.preferred_chain)

        if self.authentication:
            args.append('--' + self.authentication.value)

        return args


class CertbotCertificatesSubCommand(__CertbotSubcommand):
    """
    Runs certbot in information mode, printing out information about available certificates.
    """

    domains: list[str] | None
    """
    Domain names to apply. The first domain provided will be the subject CN of the certificate, and all domains will be
    Subject Alternative Names on the certificate. The first domain will also be used in some software user interfaces 
    and as the file paths for the certificate and related material unless otherwise specified or you already have a 
    certificate with the same name. In the case of a name collision it will append a number like 0001 to the file path
    name.
    """

    cert_name: str | None
    """
    Certificate name to apply. This name is used by Certbot for housekeeping and in file paths; it doesn't affect the 
    content of the certificate itself. To see certificate names, run 'certbot certificates'. When creating a new 
    certificate, specifies the new certificate's name.
    """

    def __init__(self, domains: list[str] | None = None, cert_name: str | None = None):
        super().__init__('certificates')

        self.domains = domains
        self.cert_name = cert_name

    def build_args(self) -> list[str]:
        args: list[str] = super().build_args()

        if self.cert_name:
            args.append('--cert-name')
            args.append(self.cert_name)

        if self.domains:
            for domain in self.domains:
                args.append('-d')
                args.append(domain)

        return args


class CertbotRunSubcommand(__CertbotCertificateAction):
    """
    Runs certbot in automatic mode, obtaining or renewing and installing certificates in the current webserver.
    """

    test_cert: bool | None
    """
    Use the staging server to obtain or revoke test (invalid) certificates; equivalent to --server 
    https://acme-staging-v02.api.letsencrypt.org/director
    """

    def __init__(
            self,
            domains: list[str] | None = None,
            eab_kid: str | None = None,
            eab_hmac_key: str | None = None,
            cert_name: str | None = None,
            keep_until_expiring: bool | None = None,
            preferred_chain: str | None = None,
            authentication: CertbotAuthentication | None = None,

            test_cert: bool | None = None
    ):
        super().__init__(
            'run',
            domains,
            eab_kid,
            eab_hmac_key,
            cert_name,
            keep_until_expiring,
            preferred_chain,
            authentication
        )

        self.test_cert = test_cert

        if self.authentication != CertbotAuthentication.apache or self.authentication != CertbotAuthentication.nginx:
            raise RuntimeError("The 'run' subcommand only supports apache or nginx authentication")

    def build_args(self) -> list[str]:
        args: list[str] = super().build_args()

        if self.test_cert:
            args.append('--test-cert')

        return args


class CertbotCertOnlySubcommand(__CertbotCertificateAction):
    """
    Runs certbot in certificate-only mode, obtaining or renewing certificates without installing them.
    """

    allow_subset_of_names: bool | None
    """
    When performing domain validation, do not consider it a failure if authorizations can not be obtained for a strict 
    subset of the requested domains.
    """

    preferred_challenges: list[str] | None
    """
    A sorted list of the preferred challenge to use during authorization with the most preferred challenge listed first.
    """

    csr: Path | None
    """
    Path to a Certificate Signing Request (CSR) in DER or PEM format.
    """

    cert_path: Path | None
    """
    Path to where certificate is saved (with auth --csr), installed from, or revoked.
    """

    test_cert: bool | None
    """
    Use the staging server to obtain or revoke test (invalid) certificates; equivalent to --server 
    https://acme-staging-v02.api.letsencrypt.org/director
    """

    def __init__(
            self,
            domains: list[str] | None = None,
            eab_kid: str | None = None,
            eab_hmac_key: str | None = None,
            cert_name: str | None = None,
            keep_until_expiring: bool | None = None,
            preferred_chain: str | None = None,
            authentication: CertbotAuthentication | None = None,

            allow_subset_of_names: bool | None = None,
            preferred_challenges: list[str] | None = None,
            csr: Path | None = None,
            cert_path: Path | None = None,
            test_cert: bool | None = None
    ):
        super().__init__(
            'certonly',
            domains,
            eab_kid,
            eab_hmac_key,
            cert_name,
            keep_until_expiring,
            preferred_chain,
            authentication
        )

        self.allow_subset_of_names = allow_subset_of_names
        self.preferred_challenges = preferred_challenges
        self.csr = csr
        self.cert_path = cert_path
        self.test_cert = test_cert

    def build_args(self) -> list[str]:
        args: list[str] = super().build_args()

        if self.allow_subset_of_names:
            args.append('--allow-subset-of-names')

        if self.preferred_challenges:
            args.append('--preferred-challenges')
            args.append(','.join(self.preferred_challenges))

        if self.csr:
            args.append('--csr')
            args.append(str(self.csr.absolute()))

        if self.cert_path:
            args.append('--cert-path')
            args.append(str(self.cert_path.absolute()))

        if self.test_cert:
            args.append('--test-cert')

        return args


class CertbotRenewSubCommand(__CertbotSubcommand):
    """
    Runs certbot in renew mode, attempting to renew all certificates you have previously obtained if they are close to
    expiry.
    """

    cert_name: str | None
    """
    Certificate name to apply. This name is used by Certbot for housekeeping and in file paths; it doesn't affect the 
    content of the certificate itself. To see certificate names, run 'certbot certificates'. When creating a new 
    certificate, specifies the new certificate's name.
    """

    force_renewal: bool | None
    """
    If a certificate already exists for the requested domains, renew it now, regardless of whether it is near expiry.
    """

    allow_subset_of_names: bool | None
    """
    When performing domain validation, do not consider it a failure if authorizations can not be obtained for a strict 
    subset of the requested domains. This may be useful for allowing renewals for multiple domains to succeed even if 
    some domains no longer point at this system. 
    """

    preferred_chain: str | None
    """
    If the CA offers multiple certificate chains, prefer the chain whose topmost certificate was issued from this 
    Subject Common Name. If no match, the default offered chain will be used.
    """

    preferred_challenges: list[str] | None
    """
    A sorted list of the preferred challenge to use during authorization with the most preferred challenge listed first.
    """

    pre_hook: Path | None
    """
    Command to be run in a shell before obtaining any certificates. Intended primarily for renewal, where it can be used 
    to temporarily shut down a webserver that might conflict with the standalone plugin. This will only be called if a 
    certificate is actually to be obtained/renewed. When renewing several certificates that have identical pre-hooks, 
    only the first will be executed.
    """

    post_hook: Path | None
    """
    Command to be run in a shell after attempting to obtain/renew certificates. Can be used to deploy renewed 
    certificates, or to restart any servers that were stopped by --pre-hook. This is only run if an attempt was made to 
    obtain/renew a certificate. If multiple renewed certificates have identical post-hooks, only one will be run.
    """

    deploy_hook: Path | None
    """
    Command to be run in a shell once for each successfully issued certificate. For this command, the shell variable 
    $RENEWED_LINEAGE will point to the config live subdirectory (for example, "/etc/letsencrypt/live/example.com") 
    containing the new certificates and keys; the shell variable $RENEWED_DOMAINS will contain a space-delimited list of 
    renewed certificate domains (for example, "example.com www.example.com").
    """

    disable_hook_validation: bool | None
    """
    Ordinarily the commands specified for --pre-hook/--post-hook/--deploy-hook will be checked for validity, to see if 
    the programs being run are in the $PATH, so that mistakes can be caught early, even when the hooks aren't being run 
    just yet. The validation is rather simplistic and fails if you use more advanced shell constructs, so you can use 
    this switch to disable it.
    """

    no_directory_hooks: bool | None
    """
    Disable running executables found in Certbot's hook directories during renewal.
    """

    disable_renew_updates: bool | None
    """
    Disable automatic updates to your server configuration that would otherwise be done by the selected installer 
    plugin, and triggered when the user executes "certbot renew", regardless of if the certificate is renewed. This 
    setting does not apply to important TLS configuration updates. 
    """

    no_autorenew: bool | None
    """
    Disable auto renewal of certificates.
    """

    break_my_certs: bool | None
    """
    Whether to allow replacement of seemingly valid certificates with invalid test certificates. USE WITH CAUTION.
    """

    def __init__(
            self,
            cert_name: str | None = None,
            force_renewal: bool | None = None,
            allow_subset_of_names: bool | None = None,
            preferred_chain: str | None = None,
            preferred_challenges: list[str] | None = None,
            pre_hook: Path | None = None,
            post_hook: Path | None = None,
            deploy_hook: Path | None = None,
            disable_hook_validation: bool | None = None,
            no_directory_hooks: bool | None = None,
            disable_renew_updates: bool | None = None,
            no_autorenew: bool | None = None,
            break_my_certs: bool | None = None
    ):
        super().__init__('renew')

        self.cert_name = cert_name
        self.force_renewal = force_renewal
        self.allow_subset_of_names = allow_subset_of_names
        self.preferred_chain = preferred_chain
        self.preferred_challenges = preferred_challenges
        self.pre_hook = pre_hook
        self.post_hook = post_hook
        self.deploy_hook = deploy_hook
        self.disable_hook_validation = disable_hook_validation
        self.no_directory_hooks = no_directory_hooks
        self.disable_renew_updates = disable_renew_updates
        self.no_autorenew = no_autorenew
        self.break_my_certs = break_my_certs

    def build_args(self) -> list[str]:
        args: list[str] = super().build_args()

        if self.cert_name:
            args.append('--cert-name')
            args.append(self.cert_name)

        if self.force_renewal:
            args.append('--force-renewal')

        if self.allow_subset_of_names:
            args.append('--allow-subset-of-names')

        if self.preferred_chain:
            args.append('--preferred-chain')
            args.append(self.preferred_chain)

        if self.preferred_challenges:
            args.append('--preferred-challenges')
            args.append(','.join(self.preferred_challenges))

        if self.pre_hook:
            args.append('--pre-hook')
            args.append(str(self.pre_hook.absolute()))

        if self.post_hook:
            args.append('--post-hook')
            args.append(str(self.post_hook.absolute()))

        if self.deploy_hook:
            args.append('--deploy-hook')
            args.append(str(self.deploy_hook.absolute()))

        if self.disable_hook_validation:
            args.append('--disable-hook-validation')

        if self.no_directory_hooks:
            args.append('--no-directory-hooks')

        if self.disable_renew_updates:
            args.append('--disable-renew-updates')

        if self.no_autorenew:
            args.append('--no-autorenew')

        if self.break_my_certs:
            args.append('--break-my-certs')

        return args


class CertbotRevokeSubCommand(__CertbotSubcommand):
    """
    Runs certbot in revoke mode, revoking and deleting specified certificates.
    """

    test_cert: bool | None
    """
    Use the staging server to obtain or revoke test (invalid) certificates; equivalent to --server 
    https://acme-staging-v02.api.letsencrypt.org/director
    """

    reason: CertbotRevocationReason | None
    """
    Specify the reason for revoking certificate.
    """

    delete_after_revoke: bool | None
    """
    Delete certificates after revoking them, along with all previous and later versions of those certificates.
    """

    no_delete_after_revoke: bool | None
    """
    Do not delete certificates after revoking them. This option should be used with caution because the 'renew' 
    subcommand will attempt to renew undeleted revoked certificates. 
    """

    cert_name: str | None
    """
    Certificate name to apply. This name is used by Certbot for housekeeping and in file paths; it doesn't affect the 
    content of the certificate itself. To see certificate names, run 'certbot certificates'. When creating a new 
    certificate, specifies the new certificate's name.
    """

    cert_path: Path | None
    """
    Path to where certificate is saved (with auth --csr), installed from, or revoked.
    """

    key_path: Path | None
    """
    Path to private key for certificate installation or revocation (if account key is missing).
    """

    def __init__(
            self,

            test_cert: bool | None = None,
            reason: str | None = None,
            delete_after_revoke: bool | None = None,
            no_delete_after_revoke: bool | None = None,
            cert_name: str | None = None,
            cert_path: Path | None = None,
            key_path: Path | None = None
    ):
        super().__init__('revoke')

        self.test_cert = test_cert
        self.reason = reason
        self.delete_after_revoke = delete_after_revoke
        self.no_delete_after_revoke = no_delete_after_revoke
        self.cert_name = cert_name
        self.cert_path = cert_path
        self.key_path = key_path

        if not self.cert_name and not self.cert_path:
            raise RuntimeError("One of cert_name and cert_path must be specified")

        if self.cert_name and self.cert_path:
            raise RuntimeError('cert_name and cert_path are mutually exclusive')

        if self.delete_after_revoke and self.no_delete_after_revoke:
            raise RuntimeError('delete_after_revoke and no_delete_after_revoke are mutually exclusive')

    def build_args(self) -> list[str]:
        args: list[str] = super().build_args()

        if self.test_cert:
            args.append('--test-cert')

        if self.reason:
            args.append('--reason')
            args.append(self.reason.value)

        if self.delete_after_revoke:
            args.append('--delete-after-revoke')

        if self.no_delete_after_revoke:
            args.append('--no-delete-after-revoke')

        if self.cert_name:
            args.append('--cert-name')
            args.append(self.cert_name)

        if self.cert_path:
            args.append('--cert-path')
            args.append(str(self.cert_path.absolute()))

        if self.key_path:
            args.append('--key-path')
            args.append(str(self.key_path.absolute()))

        return args


class CertbotDeleteSubCommand(__CertbotSubcommand):
    """
    Runs certbot in delete mode, removing the specified certificate from the filesystem.
    """

    cert_name: str
    """
    Certificate name to apply. This name is used by Certbot for housekeeping and in file paths; it doesn't affect the 
    content of the certificate itself. To see certificate names, run 'certbot certificates'. When creating a new 
    certificate, specifies the new certificate's name.
    """

    def __init__(self, cert_name: str):
        super().__init__('delete')

        self.cert_name = cert_name

    def build_args(self) -> list[str]:
        args: list[str] = super().build_args()

        args.append('--cert-name')
        args.append(self.cert_name)

        return args