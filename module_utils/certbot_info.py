#!/usr/bin/env python3

from __future__ import annotations

import re
from subprocess import CompletedProcess
from datetime import datetime
from pathlib import Path

from .certbot_commands import __CertbotSubcommand
from .certbot_commands import CertbotRunSubcommand
from .certbot_commands import CertbotCertOnlySubcommand
from .certbot_commands import CertbotRenewSubCommand
from .certbot_commands import CertbotRevokeSubCommand
from .certbot_commands import CertbotDeleteSubCommand


class CertbotCertificateActionInformation:
    """
    Represents some type of taken action related to a certificate.
    """

    cert_name: str
    """
    The name of the certificate.
    """

    changed: bool
    """
    Whether the action produced a change to the certificate. 
    """

    action_name: str
    """
    The name of the action.
    """

    def __init__(self, cert_name: str, changed: bool, action_name: str):
        self.cert_name = cert_name
        self.changed = changed
        self.action_name = action_name


class CertbotCertificateIssuanceInformation(CertbotCertificateActionInformation):
    """
    Represents the issuance of a new certificate.
    """
    def __init__(self, cert_name: str):
        super().__init__(cert_name, True, 'issue')


class CertbotCertificateRenewalInformation(CertbotCertificateActionInformation):
    """
    Represents the renewal of a certificate.
    """
    def __init__(self, cert_name: str, renewed: bool):
        super().__init__(cert_name, renewed, 'renew')


class CertbotCertificateRevocationInformation(CertbotCertificateActionInformation):
    """
    Represents the revocation of a certificate.
    """
    def __init__(self, cert_name: str, revoked: bool):
        super().__init__(cert_name, revoked, 'revoke')


class CertbotCertificateDeletionInformation(CertbotCertificateActionInformation):
    """
    Represents the deletion of a certificate.
    """
    def __init__(self, cert_name: str, deleted: bool):
        super().__init__(cert_name, deleted, 'delete')


class CertbotCertificateInformation:
    """
    Represents information about an issued certificate.
    """

    name: str
    """
    The name of the certificate.
    """

    serial_number: str
    """
    The serial number of the certificate.
    """

    key_type: str
    """
    The type of private key used by the certificate.
    """

    domains: list[str]
    """
    The domains listed on the certificate.
    """

    expiry_date: datetime
    """
    The date at which the certificate expires.
    """

    is_test_cert: bool
    """
    Indicates whether the certificate is an invalid test certificate.
    """

    is_valid: bool
    """
    Indicates whether the certificate is valid.
    """

    certificate_path: str
    """
    The path to the certificate.
    """

    private_key_path: str
    """
    The path to the private key.
    """

    def __init__(
            self,
            name: str,
            serial_number: str,
            key_type: str,
            domains: list[str],
            expiry_date: datetime,
            is_valid: bool,
            is_test_cert: bool,
            certificate_path: str,
            private_key_path: str,
    ):
        self.name = name
        self.serial_number = serial_number
        self.key_type = key_type
        self.domains = domains
        self.expiry_date = expiry_date
        self.is_valid = is_valid
        self.is_test_cert = is_test_cert
        self.certificate_path = certificate_path
        self.private_key_path = private_key_path

    @staticmethod
    def parse(lines: list[str]) -> CertbotCertificateInformation:
        """
        Parses a CertbotCertificateInformation from a set of text lines.
        :param lines: The lines.
        :return: The certificate information.
        """

        name: str | None = None
        serial_number: str | None = None
        key_type: str | None = None
        domains: list[str] | None = None
        expiry_date: datetime | None = None
        is_valid: bool | None = None
        is_test_cert: bool | None = None
        certificate_path: str | None = None
        private_key_path: str | None = None

        for line in lines:
            line_parts = line.strip().split(':', 1)

            if line_parts[0] == 'Certificate Name':
                name = line_parts[1]
            elif line_parts[0] == 'Serial Number':
                serial_number = line_parts[1]
            elif line_parts[0] == 'Key Type':
                key_type = line_parts[1]
            elif line_parts[0] == 'Domains':
                domains = line_parts[1].split()
            elif line_parts[0] == 'Expiry Date':
                combined_expiry = line_parts[1]
                parts: list[str] = combined_expiry.split()
                expiry_date = datetime.strptime(' '.join(parts[0:2]), "%Y-%m-%d %H:%M:%S%z")

                if '(VALID' in parts[2]:
                    is_valid = True
                elif '(INVALID' in parts[2]:
                    is_valid = False

                is_test_cert = 'TEST_CERT)' in parts[2]
            elif line_parts[0] == 'Certificate Path':
                raw_cert_path = line_parts[1]
                certificate_path = str(Path(raw_cert_path).absolute())
            elif line_parts[0] == 'Private Key Path':
                raw_private_key_path = line_parts[1]
                private_key_path = str(Path(raw_private_key_path).absolute())

        if not name:
            raise ValueError("No name available")

        if not serial_number:
            raise ValueError("No serial number available")

        if not key_type:
            raise ValueError("No key type available")

        if not domains:
            raise ValueError("No domains available")

        if not expiry_date:
            raise ValueError("No expiry date available")

        if not is_valid:
            raise ValueError("Could not determine validity of certificate")

        if not is_test_cert:
            raise ValueError("Could not determine whether the certificate was a test certificate")

        if not certificate_path:
            raise ValueError("No certificate path available")

        if not private_key_path:
            raise ValueError("No private key path available")

        return CertbotCertificateInformation(
            name,
            serial_number,
            key_type,
            domains,
            expiry_date,
            is_valid,
            is_test_cert,
            certificate_path,
            private_key_path
        )


def determine_actions_taken(
        process: CompletedProcess,
        subcommand: __CertbotSubcommand
) -> list[CertbotCertificateActionInformation]:
    """
    Determines actions taken by a finished certbot process.
    :param process: The finished process.
    :param subcommand: The subcommand executed.
    :return:
    """
    actions: list[CertbotCertificateActionInformation] = []

    if isinstance(subcommand, CertbotRunSubcommand):
        cert_name_match = re.search(r'\.+/(?P<cert_name>.+)/fullchain\.pem', process.stdout)

        cert_name = subcommand.cert_name
        if cert_name_match:
            cert_name = cert_name_match.group('cert_name')

        if not cert_name:
            raise RuntimeError("Unable to determine certificate name")

        renewed = 'Renewing an existing certificate' in process.stdout
        issued = 'Requesting a certificate' in process.stdout
        no_change = 'Keeping the existing certificate' in process.stdout

        if process.returncode != 0:
            # Could still be a partial success
            if 'we successfully installed your certificate' in process.stdout:
                pass
        else:
            process.check_returncode()

        if renewed:
            return [CertbotCertificateRenewalInformation(cert_name, True)]

        if issued:
            return [CertbotCertificateIssuanceInformation(cert_name)]

        if no_change:
            return [CertbotCertificateRenewalInformation(cert_name, True)]
    elif isinstance(subcommand, CertbotCertOnlySubcommand):
        # Bail out, we don't support any error codes
        process.check_returncode()

        if 'have been saved at' in process.stdout:
            cert_name_match = re.search(r'\.+/(?P<cert_name>.+)/fullchain\.pem', process.stdout)

            cert_name = subcommand.cert_name
            if cert_name_match:
                cert_name = cert_name_match.group('cert_name')

            if not cert_name:
                raise RuntimeError("Unable to determine certificate name")

            if 'Requesting a certificate' in process.stdout:
                return [CertbotCertificateIssuanceInformation(cert_name)]
            elif 'Renewing an existing certificate' in process.stdout:
                return [CertbotCertificateRenewalInformation(cert_name, True)]
            else:
                raise RuntimeError("Unknown certificate action")
        elif 'Certificate not yet due for renewal; no action taken.' in process.stdout:
            if not subcommand.cert_name:
                raise RuntimeError("Unable to determine certificate name")

            return [CertbotCertificateRenewalInformation(subcommand.cert_name, False)]
        else:
            raise RuntimeError("Unknown certificate action")
    elif isinstance(subcommand, CertbotRenewSubCommand):
        # Bail out, we don't support any error codes
        process.check_returncode()

        renewals: list[CertbotCertificateRenewalInformation] = []
        for match in re.finditer(r'\s+/.+/(?P<cert_name>.+)/fullchain\.pem .*\((?P<status>.+)\)', process.stdout):
            cert_name = match.group('cert_name')
            status = match.group('status')

            renewals.append(CertbotCertificateRenewalInformation(cert_name, status == 'success'))

        return renewals
    elif isinstance(subcommand, CertbotRevokeSubCommand):
        if process.returncode == 0:
            return [CertbotCertificateRevocationInformation(subcommand.cert_name, True)]
        elif process.returncode == 1 and "No certificate found" in process.stdout:
            return [CertbotCertificateRevocationInformation(subcommand.cert_name, False)]
        else:
            process.check_returncode()
    elif isinstance(subcommand, CertbotDeleteSubCommand):
        if process.returncode == 0:
            return [CertbotCertificateDeletionInformation(subcommand.cert_name, True)]
        elif process.returncode == 1 and "No certificate found" in process.stdout:
            return [CertbotCertificateDeletionInformation(subcommand.cert_name, False)]
        else:
            process.check_returncode()
    else:
        raise RuntimeError("Unsupported subcommand")

    return actions
