Change the password in:
    group_vars/windows/vault.yml

Encrypt vault.yml this way:
    ansible-vault encrypt vault.yml

Create a YML document with vars. For example, create vars.yml with the content:
    certname: "domain.tld"
    certdomains: "domain.tld,*.domain.tld"
    mode: "staging"
    googlecreds: "/the/path/to/creds.json"
    target: "windows_test"
    dirty: "yes"
    iis:
        - site: "site-a.domain.tld"
          bindinginfo: "1.2.3.4:443:site-a.domain.tld"
        - site: "site-b.domain.tld"
          bindinginfo: "1.2.3.4:443:"
        - site: "site-b.domain.tld"
          bindinginfo: "1.2.3.4:443:site-b.domain.tld"

Run the playbook this way:
    ansible-playbook playbooks/update_cert.yml -i inventory --ask-vault-pass -e @vars.yml

Set mode and target in the YML above to production and windows_prod if everything goes fine.
The ditry flag prevents Ansible from removing work dirs on IIS hosts. So you could read logs etc.
If everything is fine, remove the dirty flag from the vars YML (Don't set "no". This will work as "yes" because only flag's existence matters).
