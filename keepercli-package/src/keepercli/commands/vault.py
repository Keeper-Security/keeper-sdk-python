import argparse
from . import base

class SyncDownCommand(base.ArgparseCommand):
    parser = argparse.ArgumentParser(prog='sync-down', description='Download & decrypt data')
    parser.add_argument('-f', '--force', dest='force', action='store_true', help='full data sync')

    def __init__(self):
        super().__init__(SyncDownCommand.parser)

    def execute(self, context, **kwargs):
        assert context.auth is not None
        force = kwargs.get('force') is True
        context.vault.sync_down(force)

        # TODO pending shares
        # accepted = False
        # if len(params.pending_share_requests) > 0:
        #     for user in params.pending_share_requests:
        #         accepted = False
        #         print('Note: You have pending share request from ' + user)
        #         answer = user_choice('Do you want to accept these request?', 'yn', 'n')
        #         rq = {
        #             'command': 'accept_share' if answer == 'y' else 'cancel_share',
        #             'from_email': user
        #         }
        #         try:
        #             rs = api.communicate(params, rq)
        #             if rs['result'] == 'success':
        #                 accepted = accepted or answer == 'y'
        #         except Exception as e:
        #             logging.debug('Accept share exception: %s', e)
        #
        #     params.pending_share_requests.clear()
        #


