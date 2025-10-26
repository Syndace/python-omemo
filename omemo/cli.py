from typing import Dict, List, Optional

try:
    import prettytable
except ModuleNotFoundError as e:
    raise ModuleNotFoundError(
        "CLI dependency \"prettytable\" not found. Install python-omemo with CLI dependencies using"
        " \"pip install OMEMO[cli]\""
    ) from e

from .backend import Backend
from .session_manager import SessionManager, UnknownNamespace
from .types import DeviceList


__all__ = [ "debug_encrypt" ]


async def debug_encrypt(
    session_manager: SessionManager,
    bare_jid: str,
    backend_priority_order: Optional[List[str]] = None
) -> None:
    # pylint: disable=protected-access
    # pylint: disable=fixme

    print()
    print("*" * 100)
    print(f"Start of health check for {bare_jid}.")
    print()
    backends: List[Backend] = getattr(session_manager, "_SessionManager__backends")

    # Print the list of available backends and their priorities
    available_namespaces = [ backend.namespace for backend in backends ]

    if backend_priority_order is not None:
        unavailable_namespaces = frozenset(backend_priority_order) - frozenset(available_namespaces)
        if len(unavailable_namespaces) > 0:
            raise UnknownNamespace(
                f"One or more unavailable namespaces were passed in the backend priority order list:"
                f" {unavailable_namespaces}"
            )

    effective_backend_priority_order = \
        available_namespaces if backend_priority_order is None else backend_priority_order

    print("Available backends by priority:")
    for namespace in effective_backend_priority_order:
        print(f"{namespace}")

    for namespace in frozenset(available_namespaces) - frozenset(effective_backend_priority_order):
        print(f"(no priority: {namespace})")

    print()
    print("Device list access check:")

    # Print whether the device list nodes can be accessed
    device_lists: Dict[str, DeviceList] = {}
    for namespace in effective_backend_priority_order:
        try:
            device_list = await session_manager._download_device_list(namespace, bare_jid)
            if len(device_list) == 0:
                print(f"Device list for backend {namespace} doesn't exist or is empty.")
            else:
                print(f"Device list access for backend {namespace} ok.")
                device_lists[namespace] = device_list
        except Exception as e:  # pylint: disable=broad-exception-caught
            print(f"Device list download for backend {namespace} failed: {e}")

    if len(device_lists) == 0:
        print()
        print(f"No devices found for {bare_jid}, health check failed.")
        return

    print()
    print("Gathering device information...")
    table: List[Dict[str, str]] = []
    for namespace, device_list in device_lists.items():
        backend = next(backend for backend in backends if backend.namespace == namespace)

        await session_manager.refresh_device_list(namespace, bare_jid)
        device_information = await session_manager.get_device_information(bare_jid)

        for device_id, _label in device_list.items():
            info = next((info for info in device_information if info.device_id == device_id), None)

            table_row: Dict[str, str] = {}

            table_row["device id"] = str(device_id)
            table_row["namespace"] = namespace
            # TODO: Print whether a label is present per-device and whether there is a valid signature for the
            # label
            # TODO: If a device is listed in both the omemo:1 and omemo:2 device lists, check whether the
            # identity key matches

            # Print whether the bundle node for each device in the device list can be accessed
            try:
                await session_manager._download_bundle(namespace, bare_jid, device_id)
                table_row["bundle download ok?"] = "yes"
            except Exception as e:  # pylint: disable=broad-exception-caught
                table_row["bundle download ok?"] = f"no: {type(e).__name__}"

            # Print whether "full" device information exists, i.e. whether the device is included in
            # get_device_information.
            table_row["full info available?"] = "no" if info is None else "yes"

            # Print whether a session exists
            session = await backend.load_session(bare_jid, device_id)
            table_row["session exists?"] = "no" if session is None else "yes"

            # Print the trust status of each device
            if info is None:
                table_row["trust status"] = "n.a. (full info missing)"
            else:
                trust_level = await session_manager._evaluate_custom_trust_level(info)
                table_row["trust status"] = f"{info.trust_level_name} ({trust_level})"

            table.append(table_row)

    if len(table) > 0:
        print()
        print("Device information:")
        ptable = prettytable.PrettyTable()
        for field_name in table[0].keys():
            ptable.add_column(field_name, [ row[field_name] for row in table ])
        print(ptable)

    print()
    print("Health check complete.")
    print("*" * 100)
