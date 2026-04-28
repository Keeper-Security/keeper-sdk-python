import os
from typing import List, Optional, Tuple
from .__version__ import __version__


def value_to_boolean(value):
    value = str(value)
    if value.lower() in ['true', 'yes', 'on', '1']:
        return True
    elif value.lower() in ['false', 'no', 'off', '0']:
        return False
    else:
        return None


def kotlin_bytes(data: bytes):
    return [b if b < 128 else b - 256 for b in data]


def get_connection(**kwargs):

    """
    This method will return the proper connection based on the params passed in.

    If `ksm` and a KDNRM KSM instance, it will connect using keeper secret manager.
    If `params` and a KeeperParam instance, it will connect using Commander.
    If the env var `USE_LOCAL_DAG` is True, it will connect using the Local test DAG engine.

    It returns a child instance of the Connection class.
    """

    if kwargs.get("connection") is not None:
        return kwargs.get("connection")

    vault = kwargs.get("vault")
    logger = kwargs.get("logger")
    if value_to_boolean(os.environ.get("USE_LOCAL_DAG")):
        from ..keeper_dag.connection.local import Connection
        conn = Connection(logger=logger)
    else:
        use_read_protobuf = kwargs.get("use_read_protobuf")
        use_write_protobuf = kwargs.get("use_write_protobuf")

        if vault is not None:
            from ..keeper_dag.connection.commander import Connection
            conn = Connection(vault=vault,
                              logger=logger,
                              use_read_protobuf=use_read_protobuf,
                              use_write_protobuf=use_write_protobuf)
        else:
            raise ValueError("Must pass 'vault' for Keeper SDK. Found neither.")
    return conn


def make_agent(text) -> str:
    return f"{text}/{__version__}"


def split_user_and_domain(user: str) -> Tuple[Optional[str], Optional[str]]:

    if user is None:
        return None, None

    domain = None

    if "\\" in user:
        user_parts = user.split("\\", maxsplit=1)
        user = user_parts[0]
        domain = user_parts[1]
    elif "@" in user:
        user_parts = user.split("@")
        domain = user_parts.pop()
        user = "@".join(user_parts)

    return user, domain


def user_check_list(user: str, name: Optional[str] = None, source: Optional[str] = None) -> List[str]:
    user, domain = split_user_and_domain(user)
    user = user.lower()

    check_list = [user, f".\\{user}"]
    if name is not None:
        name = name.lower()
        check_list += [name, f".\\{name}"]
    if source is not None:
        source = source.lower()
        check_list.append(f"{source[:15]}\\{user}")
        check_list.append(f"{user}@{source}")
        netbios_parts = source.split(".")
        if len(netbios_parts) > 1:
            check_list.append(f"{netbios_parts[0][:15]}\\{user}")
            check_list.append(f"{user}@{netbios_parts[0]}")
    if domain is not None:
        domain = domain.lower()
        check_list.append(f"{domain[:15]}\\{user}")
        check_list.append(f"{user}@{domain}")
        domain_parts = domain.split(".")
        if len(domain_parts) > 1:
            check_list.append(f"{domain_parts[0][:15]}\\{user}")
            check_list.append(f"{user}@{domain_parts[0]}")

    return list(set(check_list))


def user_in_lookup(user: str, lookup: dict, name: Optional[str] = None, source: Optional[str] = None) -> bool:

    for check_user in user_check_list(user, name, source):
        if check_user in lookup:
            return True
    return False
