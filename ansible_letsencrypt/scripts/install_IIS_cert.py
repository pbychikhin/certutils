
import argparse
import sys
import os
import logging
import clr
from pathlib import Path
sys.path.append(os.path.join(os.environ["WINDIR"], "System32", "inetsrv"))
clr.AddReference("Microsoft.Web.Administration")
from System.Security.Cryptography import X509Certificates
from Microsoft.Web.Administration import ServerManager


__CERT_STORE_NAME = "WebHosting"


def get_logger(dsuffix=None):
    """
    Prepares logging facility
    :param dsuffix: a distinguishing suffix
    :return: logger object to be used in the rest of subs
    """
    log_formatter_stream = logging.Formatter(fmt="{asctime} {message}", style="{")
    log_formatter_file = logging.Formatter(fmt="{asctime} [{threadName}] [{levelname}] {message}", style="{")
    log_handler_stream = logging.StreamHandler()
    log_handler_stream.setLevel(logging.INFO)
    log_handler_stream.setFormatter(log_formatter_stream)
    if dsuffix is not None: dsuffix = dsuffix.strip()
    if dsuffix is not None and len(dsuffix) > 0:
        log_handler_file = logging.FileHandler(Path(sys.argv[0]).
                                               with_name(Path(sys.argv[0]).stem + "_" + dsuffix).
                                               with_suffix(".log").as_posix(), mode="a")
    else:
        log_handler_file = logging.FileHandler(Path(sys.argv[0]).with_suffix(".log").as_posix(), mode="a")
    log_handler_file.setLevel(logging.DEBUG)
    log_handler_file.setFormatter(log_formatter_file)
    log_logger = logging.getLogger(Path(sys.argv[0]).name)
    # log_logger.addHandler(log_handler_stream)
    log_logger.addHandler(log_handler_file)
    log_logger.setLevel(logging.DEBUG)
    return log_logger


def compare_bytearrs(arr_1, arr_2):
    """
    Compares elements in two arrays
    This function's name contains bytearrs in its name to point out its purpose
    :param arr_1: arr #1
    :param arr_2: arr #2
    :return: True if arrays are equal, or False if not
    """
    if len(arr_1) == len(arr_2):
        for el1, el2 in zip(arr_1, arr_2):
            if el1 != el2:
                return False
    else:
        return False
    return True


def find_cert_by_thumbprint(store, thumbprint, log):
    """
    Search for a cert with a specific thumbprint in a specific store
    :param store: an opened cert store obj
    :param thumbprint: a cert thumbprint
    :param log: logger obj
    :return: a cert
    """
    log.info("Searching for thubprint {}".format(thumbprint))
    for cert in store.Certificates:
        log.info("Comparing with the cert for {} with thumbprint {}".format(cert.SubjectName.Name, cert.Thumbprint))
        if cert.Thumbprint == thumbprint:
            log.info("Cert found")
            return cert
    log.info("Cert not found")
    return None


def open_stores(pfxpath, chainpath, log):
    """
    Opens cert stores: system and PFX
    :param pfxpath: pfx file path
    :param log: logger obj
    :return: a tuple of (system_store, pfx_store)
    """
    log.info("Open the system store")
    systore = X509Certificates.X509Store(__CERT_STORE_NAME, X509Certificates.StoreLocation.LocalMachine)
    systore.Open(X509Certificates.OpenFlags.ReadWrite | X509Certificates.OpenFlags.OpenExistingOnly)
    log.info("Open the cert's PFX")
    pfxstore = X509Certificates.X509Certificate2Collection()
    pfxstore.Import(pfxpath, None,
                    X509Certificates.X509KeyStorageFlags.PersistKeySet |
                    X509Certificates.X509KeyStorageFlags.MachineKeySet |
                    X509Certificates.X509KeyStorageFlags.Exportable)
    chainstore = None
    if chainpath:
        log.info("Open the chain's PFX")
        chainstore = X509Certificates.X509Certificate2Collection()
        chainstore.Import(chainpath, None, X509Certificates.X509KeyStorageFlags.Exportable)
    return systore, pfxstore, chainstore


def add_cert(store, cert, log):
    """
    Adds a cert to a store if not exists
    :param store: a (system) store obj
    :param cert: cert obj
    :param log: logger obj
    :return: None
    """
    if find_cert_by_thumbprint(store, cert.Thumbprint, log):
        log.info("The cert to be added already exists in the store")
    else:
        log.info("Adding the cert to the store")
        store.Add(cert)


def bind_cert(site_name, cert_store_name, cert_hash, binding_info, log):
    """
    Binds a cert to an IIS site
    :param site_name: IIS site name
    :param cert_store_name: cert store name
    :param cert_hash: cert hash (Bytes array)
    :param binding_info: binding information ("ip:host:port")
    :param host: host name for the binding
    :param ip: ip address for the binding
    :param port: TCP port for the binding
    :param log: logger obj
    :return: s_changed/s_unchanged text. It is used in changed_when Ansible's clause
    """
    manager = ServerManager()
    changed = False
    for site in manager.Sites:
        if site.Name.lower() == site_name.lower():
            log.info("Found site {}".format(site.Name))
            existing_binding = None
            for binding in site.Bindings:
                log.info("Comparing binding {},{} with https,{}".format(binding.Protocol,
                                                                  binding.BindingInformation,
                                                                  binding_info))
                if binding.Protocol.lower() == "https" \
                        and binding.BindingInformation.lower() == binding_info.lower():
                    existing_binding = binding
                    break
            if existing_binding:
                log.info("Found existing binding {}".format(existing_binding.BindingInformation))
                if not compare_bytearrs(existing_binding.CertificateHash, cert_hash):
                    log.info("Existing binding is subject for update - re-creating")
                    site.Bindings.Remove(existing_binding)
                    site.Bindings.Add(binding_info, cert_hash, cert_store_name)
                    changed = True
                else:
                    log.info("Existing binding needs not to be updated")
            else:
                log.info("Existing binding not found - adding a new one {}".format(binding_info))
                site.Bindings.Add(binding_info, cert_hash, cert_store_name)
                changed = True
            break
    if changed:
        manager.CommitChanges()
        return "s_changed"
    else:
        return "s_unchanged"


if __name__ == "__main__":
    cmd = argparse.ArgumentParser(description="Installs a cert from PFX into store and binds it to an IIS site")
    cmd.add_argument("-p", metavar="path", help="path to cert's PFX", required=True)
    cmd.add_argument("-c", metavar="path", help="(optional) path to chain's PFX")
    cmd.add_argument("-s", metavar="name", help="IIS site name", required=True)
    cmd.add_argument("-b", metavar="IP:PORT:HOST", help="IIS site binding's info. Can be specified several times",
                     action="append", required=True)
    cmdargs = cmd.parse_args()
    log = get_logger()
    log.info("--- Opening stores ---")
    systore, pfxstore, chainstore = open_stores(cmdargs.p, cmdargs.c, log)
    log.info("--- Adding a cert to a store ---")
    add_cert(systore, pfxstore[0], log)
    if chainstore:
        log.info("--- Adding a chain to a store ---")
        for cert in chainstore:
            add_cert(systore, cert, log)
    log.info("--- Binding a cert to a site ---")
    num_changed = 0
    for binding_info in cmdargs.b:
        if bind_cert(cmdargs.s, __CERT_STORE_NAME, pfxstore[0].GetCertHash(), binding_info, log) == "s_changed":
            num_changed += 1
    if num_changed:
        print("s_changed", end="")
    else:
        print("s_unchanged", end="")
