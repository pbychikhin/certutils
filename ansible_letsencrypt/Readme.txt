Change the password in:
    group_vars/windows/vault.yml
Encrypt vault.yml this way:
    ansible-vault encrypt vault.yml
Run the playbook this way:
    ansible-playbook playbooks/update_cert.yml -i inventory --ask-vault-pass -e certname=domain.tld -e certdomains="domain.tld,*.domain.tld" -e iissite=domain.tld -e iisbindinginfo=1.2.3.4:443:domain.tld -e mode=staging -e target=windows_test
Set mode and target in the command above to production and windows_prod if everything goes fine
You can also set ditry flag. If set, this flag prevents Ansible from removing work dirs on IIS hosts. So you could read logs etc:
    -e dirty=yes