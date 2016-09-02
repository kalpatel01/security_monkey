#     Copyright 2016 Bridgewater Associates
#
#     Licensed under the Apache License, Version 2.0 (the "License");
#     you may not use this file except in compliance with the License.
#     You may obtain a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#     Unless required by applicable law or agreed to in writing, software
#     distributed under the License is distributed on an "AS IS" BASIS,
#     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#     See the License for the specific language governing permissions and
#     limitations under the License.
"""
.. module: security_monkey.accounts.aws_account
    :platform: Unix
    :synopsis: Manages generic AWS account.


.. version:: $$VERSION$$
.. moduleauthor:: Bridgewater OSS <opensource@bwater.com>


"""
from security_monkey.account_manager import AccountManager, CustomFieldConfig
from security_monkey.datastore import Account

class AWSAccountManager(AccountManager):
    account_type = 'AWS'
    identifier_label = 'Number'
    identifier_tool_tip = 'Enter the AWS account number, if you have it. (12 digits)'
    custom_field_configs = [
        CustomFieldConfig('s3_name', 'S3 Name', True,
            'The S3 Name is the way AWS presents the account in an ACL policy.  This is often times the first part of the email address that was used to create the Amazon account.  (myaccount@example.com may be represented as myaccount). If you see S3 issues appear for unknown cross account access, you may need to update the S3 Name.'),
        CustomFieldConfig('role_name', 'Role Name', True,
            "Optional custom role name, otherwise the default 'SecurityMonkey' is used. When deploying roles via CloudFormation, this is the Physical ID of the generated IAM::ROLE.")
    ]

    def __init__(self):
        super(AWSAccountManager, self).__init__()

    def lookup_account_by_identifier(self, identifier):
        """
        Overrides the lookup to also check the number for backwards compatibility
        """
        account = super(AWSAccountManager, self).lookup_account_by_identifier(identifier)
        if account is None:
            query = Account.query.filter(Account.number == identifier)
            if query.count():
                account = query.first()
        return account

    def _populate_account(self, account, account_type, name, active, third_party,
              notes, identifier, custom_fields=None):
        """
        Overrides create and update to also save the number, s3_name and role_name
        for backwards compatibility
        """
        account = super(AWSAccountManager, self)._populate_account(account,
            account_type, name, active, third_party, notes, identifier, custom_fields)

        account.number = identifier;
        account.s3_name = account.getCustom("s3_name")
        account.role_name = account.getCustom("role_name")
        return account
