Change the password in:
    group_vars/windows/vault.yml
Encrypt vault.yml this way:
    ansible-vault encrypt vault.yml
Run the playbook this way:
    ansible-playbook playbooks/update_cert.yml -i inventory --ask-vault-pass -e certname=domain.tld -e certdomains="domain.tld,*.domain.tld" -e iissite=domain.tld -e iisbindinginfo=1.2.3.4:443:domain.tld
