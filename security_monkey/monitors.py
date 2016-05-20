"""
.. module: security_monkey.monitors
    :platform: Unix
    :synopsis: Monitors are a grouping of a watcher and it's associated auditor

.. version:: $$VERSION$$
.. moduleauthor:: Patrick Kelley <pkelley@netflix.com> @monkeysecurity

"""
from security_monkey import app
from security_monkey.auditor import auditor_registry
from security_monkey.watcher import watcher_registry
from security_monkey.account_manager import account_registry, get_account_by_name

class Monitor(object):
    """Collects a watcher with the associated auditors"""
    def __init__(self, watcher_class, account, debug=False):
        self.watcher = watcher_class(accounts=[account.name], debug=debug)
        self.auditors = []
        for auditor_class in auditor_registry[self.watcher.index]:
            au = auditor_class([account.name], debug=debug)
            if au.applies_to_account(account):
                self.auditors.append(au)


def get_watchers(accounts, monitor_names, debug=False):
    """
    Returns a list of monitors in the correct audit order which apply to one or
    more of the accounts.
    """
    watchers = []
    for monitor_name in monitor_names:
        watcher_class = watcher_registry[monitor_name]
        watchers.append(watcher_class(accounts=accounts, debug=debug))

    return watchers

def get_monitors(account_name, monitor_names, debug=False):
    """
    Returns a list of monitors in the correct audit order which apply to one or
    more of the accounts.
    """
    requested_mons = []
    account = get_account_by_name(account_name)
    account_manager = account_registry.get(account.account_type.name)()

    for monitor_name in monitor_names:
        watcher_class = watcher_registry[monitor_name]
        if account_manager.is_compatible_with_account_type(watcher_class.account_type):
            monitor = Monitor(watcher_class, account, debug)
            requested_mons.append(monitor)

    return requested_mons

def all_monitors(account_name, debug=False):
    """
    Returns a list of all monitors in the correct audit order which apply to one
    or more of the accounts.
    """
    monitors = []
    account = get_account_by_name(account_name)
    account_manager = account_registry.get(account.account_type.name)()

    for watcher_class in watcher_registry.itervalues():
        if account_manager.is_compatible_with_account_type(watcher_class.account_type):
          monitor = Monitor(watcher_class, account, debug)
          monitors.append(monitor)

    return monitors
