#!/usr/bin/env python3

from __future__ import annotations
from pathlib import Path
from typing import Callable

import subprocess

from .certbot_info import CertbotCertificateInformation
from .certbot_info import CertbotCertificateActionInformation
from .certbot_info import determine_actions_taken

from .certbot_commands import CertbotAuthentication
from .certbot_commands import __CertbotSubcommand
from .certbot_commands import CertbotRunSubcommand
from .certbot_commands import CertbotCertOnlySubcommand
from .certbot_commands import CertbotRenewSubCommand
from .certbot_commands import CertbotRevokeSubCommand
from .certbot_commands import CertbotDeleteSubCommand
from .certbot_commands import CertbotCertificatesSubCommand


class CertbotResult:
    actions_taken: list[CertbotCertificateActionInformation] | None
    completed_process: subprocess.CompletedProcess
    certificates: list[CertbotCertificateInformation] | None

    def __init__(
            self,
            completed_process: subprocess.CompletedProcess,
            actions_taken: list[CertbotCertificateActionInformation] | None = None,
            certificates: list[CertbotCertificateInformation] | None = None
    ):
        self.completed_process = completed_process
        self.actions_taken = actions_taken
        self.certificates = certificates


class Certbot:
    """
    Wraps the certbot executable, allowing control of certificate issuance, renewal, revocation and information
    gathering via a Python interface.
    """

    command_runner: Callable[[list[str]], tuple[int, str, str]]
    """
    The callable to use when running the certbot command.
    """

    def __init__(self, command_runner: Callable[[list[str]], tuple[int, str, str]] | None = None):
        if command_runner:
            self.command_runner = command_runner
        else:
            self.command_runner = self.__default_command_runner

    def run(
            self,
            domains: list[str] | None = None,
            eab_kid: str | None = None,
            eab_hmac_key: str | None = None,
            cert_name: str | None = None,
            keep_until_expiring: bool | None = None,
            preferred_chain: str | None = None,
            authentication: CertbotAuthentication | None = None,
            test_cert: bool | None = None
    ) -> CertbotResult:
        """
        Runs certbot in automatic mode, issuing, renewing and/or installing certificates as required.
        :param domains: The domains of the issued or renewed certificate.
        :param eab_kid: The key identifier for the external account binding.
        :param eab_hmac_key: The HMAC key for the external account binding.
        :param cert_name: The name of the certificate to issue or renew.
        :param keep_until_expiring: Whether to keep existing certificates as-is until they are due for renewal.
        :param preferred_chain: The Common Name of the root certificate to use when multiple chains are available.
        :param authentication: The authentication scheme to use when issuing or renewing certificates.
        :param test_cert: Whether to use the staging server to issue or renew (invalid) certificates.
        :return:
        """
        subcommand = CertbotRunSubcommand(
            domains,
            eab_kid,
            eab_hmac_key,
            cert_name,
            keep_until_expiring,
            preferred_chain,
            authentication,
            test_cert
        )

        result = self.__run(subcommand)
        return CertbotResult(result, determine_actions_taken(result, subcommand))

    def certonly(
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
    ) -> CertbotResult:
        """
        Runs certbot in certificate-only mode, issuing or renewing certificates as required.
        :param domains: The domains of the issued or renewed certificate.
        :param eab_kid: The key identifier for the external account binding.
        :param eab_hmac_key: The HMAC key for the external account binding.
        :param cert_name: The name of the certificate to issue or renew.
        :param keep_until_expiring: Whether to keep existing certificates as-is until they are due for renewal.
        :param preferred_chain: The Common Name of the root certificate to use when multiple chains are available.
        :param authentication: The authentication scheme to use when issuing or renewing certificates.
        :param allow_subset_of_names: Do not consider failure to obtain authorization for some subset of the domains as
        an error.
        :param preferred_challenges: A sorted list of the preferred challenges to use for authorization.
        :param csr: The path to a Certificate Signing Request in DER or PEM format.
        :param cert_path: The path where the issued or renewed certificates should be created or already exists.
        :param test_cert: Whether to use the staging server to issue or renew (invalid) certificates.
        :return:
        """
        subcommand = CertbotCertOnlySubcommand(
            domains,
            eab_kid,
            eab_hmac_key,
            cert_name,
            keep_until_expiring,
            preferred_chain,
            authentication,
            allow_subset_of_names,
            preferred_challenges,
            csr,
            cert_path,
            test_cert)

        result = self.__run(subcommand)
        return CertbotResult(result, determine_actions_taken(result, subcommand))

    def renew(
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
    ) -> CertbotResult:
        """
        Runs certbot in renewal mode, renewing certificates as required.
        :param cert_name: The name of the certificate to renew.
        :param force_renewal: Whether to force renewal even if the certificate is not due.
        :param allow_subset_of_names: Do not consider failure to obtain authorization for some subset of the domains as
        an error.
        :param preferred_chain: The Common Name of the root certificate to use when multiple chains are available.
        :param preferred_challenges: A sorted list of the preferred challenges to use for authorization.
        :param pre_hook: The path to a script that runs before obtaining any certificates.
        :param post_hook: The past to a script that runs after attempting to obtain or renew certificates.
        :param deploy_hook: The path to a script that runs once for each successfully issued certificate.
        :param disable_hook_validation: Whether to disable validation of the hook scripts.
        :param no_directory_hooks: Whether to disable running executables found in certbot's hook directories during
        renewal.
        :param disable_renew_updates: Whether to disable automatic updates to the server configuration.
        :param no_autorenew: Whether to disable auto-renewal of certificates.
        :param break_my_certs: Whether to allow replacement of seemingly valid certificates with invalid test
        certificates. USE WITH CAUTION.
        :return:
        """
        subcommand = CertbotRenewSubCommand(
            cert_name,
            force_renewal,
            allow_subset_of_names,
            preferred_chain,
            preferred_challenges,
            pre_hook,
            post_hook,
            deploy_hook,
            disable_hook_validation,
            no_directory_hooks,
            disable_renew_updates,
            no_autorenew,
            break_my_certs
        )

        result = self.__run(subcommand)
        return CertbotResult(result, determine_actions_taken(result, subcommand))

    def certificates(
            self,
            domains: list[str] | None = None,
            cert_name: str | None = None
    ) -> CertbotResult:
        """
        Runs certbot in certificate mode, all available certificates.
        :param domains: The domains of the certificates to list.
        :param cert_name: The name of the certificate to list.
        :return:
        """
        subcommand = CertbotCertificatesSubCommand(domains, cert_name)
        result = self.__run(subcommand)

        # Doesn't support any failure modes
        result.check_returncode()

        certificates: list[CertbotCertificateInformation] = []

        in_information_block = False
        line_block: list[str] = []
        for line in result.stdout.splitlines():
            if 'Certificate Name' in line:
                if in_information_block:
                    certificates.append(CertbotCertificateInformation.parse(line_block))
                    line_block.clear()

                in_information_block = True

            if in_information_block:
                line_block.append(line)

        if in_information_block:
            certificates.append(CertbotCertificateInformation.parse(line_block))
            line_block.clear()

        return CertbotResult(result, certificates=certificates)

    def revoke(
            self,
            test_cert: bool | None = None,
            reason: str | None = None,
            delete_after_revoke: bool | None = None,
            no_delete_after_revoke: bool | None = None,
            cert_name: str | None = None,
            cert_path: Path | None = None,
            key_path: Path | None = None
    ) -> CertbotResult:
        """
        Runs certbot in revocation mode, revoking the named certificate.
        :param test_cert: Whether to use the staging server to issue or renew (invalid) certificates.
        :param reason: The reason for revoking the certificate.
        :param delete_after_revoke: Whether the certificate should be deleted after revocation.
        :param no_delete_after_revoke: Whether the certificate should be retained after revocation.
        :param cert_name: The name of the certificate to revoke.
        :param cert_path: The path to the certificate to revoke.
        :param key_path: The path to the private key of the certificate to revoke.
        :return:
        """
        subcommand = CertbotRevokeSubCommand(
            test_cert,
            reason,
            delete_after_revoke,
            no_delete_after_revoke,
            cert_name,
            cert_path,
            key_path
        )

        result = self.__run(subcommand)
        return CertbotResult(result, determine_actions_taken(result, subcommand))

    def delete(self, cert_name: str) -> CertbotResult:
        """
        Runs certbot in deletion mode, erasing the named certficate from the filesystem.
        :param cert_name: The name of the certificate to delete.
        :return:
        """
        subcommand = CertbotDeleteSubCommand(cert_name)

        result = self.__run(subcommand)
        return CertbotResult(result, determine_actions_taken(result, subcommand))

    def __run(self, subcommand: __CertbotSubcommand) -> subprocess.CompletedProcess:
        args = subcommand.build_args()
        result = self.command_runner(['certbot'] + args)

        return subprocess.CompletedProcess(
            args,
            returncode=result[0],
            stdout=result[1],
            stderr=result[2]
        )

    @staticmethod
    def __default_command_runner(args: list[str]) -> tuple[int, str, str]:
        result = subprocess.run(args, capture_output=True, text=True)
        return result.returncode, result.stdout, result.stderr
