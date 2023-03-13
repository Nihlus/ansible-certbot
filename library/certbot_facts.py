#!/usr/bin/env python3

from __future__ import (absolute_import, division, print_function, annotations)
__metaclass__ = type


DOCUMENTATION = r'''
---
module: certbot_facts
short_description: Gathers facts about certbot certificates
version_added: "1.0.0"
description:  This module is used to gather information about certbot-managed certificates on the host.

options:
    name: 
        description: The name of the certificate to gather facts about.
        required: false
        type: str
    domains:
        description: The domain of the certificate to gather facts about.
        required: false
        type: list
        elements: str

author:
    - Jarl Gullberg <jarl.gullberg@gmail.com>
'''

EXAMPLES = r'''
# Gather facts about all certificates
- name: Gather facts
  certbot_facts:
  
# Gather facts about a specific certificate
- name: Gather facts
  certbot_facts:
    name: example.com
    
# Gather facts about a set of domains
- name: Gather facts
  certbot_facts:
    domains:
      - example.com
      - placeholder.org
'''

RETURN = r'''
certbot_certificates:
    description: The found certificates.
    type: list
    elements: dict
    sample:
        - name: example.com
          serial_number: 09d2af8dd22201dd8d48e5dcfcaed281ff9422c7
          key_type: RSA
          domains:
            - example.com
            - www.example.com
            - domain.example.com
          expiry_date: 2023-05-31 17:45:41+00:00
          valid_days: 80
          certificate_path: /etc/letsencrypt/live/example.com/fullchain.pem
          private_key_path: /etc/letsencrypt/live/example.com/fullchain.pem
'''

from ansible.module_utils.basic import AnsibleModule

try:
    from ansible.module_utils.certbot_cli import Certbot
    from ansible.module_utils.certbot_info import CertbotCertificateInformation
except ModuleNotFoundError:
    from module_utils.certbot_cli import Certbot
    from module_utils.certbot_info import CertbotCertificateInformation


def run_module():
    module_args = dict(
        name=dict(type='str', required=False),
        domains=dict(type='list', required=False, elements='str')
    )

    result = dict(
        changed=False,
        ansible_facts=dict(certbot_certificates=list[dict]())
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )

    domains = module.params['domains'] if 'domains' in module.params else None
    cert_name = module.params['cert_name'] if 'cert_name' in module.params else None

    result['ansible_facts']['certbot_certificates'] = list(
        map(lambda c: c.__dict__, Certbot.certificates(domains, cert_name))
    )

    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()


