#!/usr/bin/env python3

"""Active Directory Integration - Sense admin list change

Process:
Take in credentials
Get old list of users in group
Create powershell command to get new group membership
Compare old list with new list
Create separate triggers for any added members and any removed members
"""

import ast
import json

import winrm
from st2reactor.sensor.base import PollingSensor
from winrm.exceptions import AuthenticationError, BasicAuthDisabledError, \
    InvalidCredentialsError, WinRMTransportError


class ADAdminSensor(PollingSensor):
    def __init__(self, sensor_service, config=None, poll_interval=None):

        interval = config.get('poll_interval', 120)
        if interval:
            poll_interval = interval
        super(ADAdminSensor, self).__init__(sensor_service=sensor_service,
                                            config=config,
                                            poll_interval=poll_interval)

        self._logger = self._sensor_service.get_logger(__name__)

        self.groups = config.get('groups')

        hostname = config.get('hostname')
        port = config.get('port', 5986)
        transport = config.get('transport', 'ntlm')

        self.creds_name = config.get('sensor_credential_name')
        creds = config.get('activedirectory').get(self.creds_name)

        username = creds.get('username')
        password = creds.get('password')

        scheme = 'http' if port == 5985 else 'https'

        winrm_url = '{}://{}:{}/wsman'.format(scheme, hostname, port)
        self.session = winrm.Session(winrm_url,
                                     auth=(username, password),
                                     transport=transport,
                                     server_cert_validation='ignore')

        self.members = {}

        for group in self.groups:
            self.members[group] = self._get_members(group)
            if not self.members.get(group):
                self.members[group] = [{'SamAccountName': 'initial'}]

    def setup(self):
        pass

    def poll(self):

        for group in self.groups:

            # Get old group membership
            members = self._get_members(group)
            self._logger.info(group)
            self._logger.info('members')
            self._logger.debug(members)

            # Create query to get new group membership

            output_ps = ("Try\n"
                         "{{\n"
                         "  {0} | ConvertTo-Json\n"
                         "}}\n"
                         "Catch\n"
                         "{{\n"
                         "  $formatted_output = ConvertTo-Json -InputObject $_\n"
                         "  $host.ui.WriteErrorLine($formatted_output)\n"
                         "  exit 1\n"
                         "}}")

            powershell = "$ProgressPreference = 'SilentlyContinue';\n"
            powershell += 'Get-ADGroupMember -Identity "' + group + '"'

            # add output formatters to the powershell code
            powershell = output_ps.format(powershell)

            self._logger.debug(powershell)

            # run powershell command
            try:
                response = self.session.run_ps(powershell)
            except (AuthenticationError, InvalidCredentialsError) as e:
                self.logger.info(e)
                self.logger.info('The specified credentials were rejected by the server.')
                return
            except BasicAuthDisabledError as e:
                self.logger.info(e)
                self.logger.info('Basic auth is not enabled on the target domain controller.')
                return
            except WinRMTransportError as e:
                self.logger.info(e)
                self.logger.info('Transport error - cannot connect to domain controller')
                return

            self._logger.debug(response)

            response_list = json.loads(response.__dict__['std_out'])

            self._logger.debug(response_list)

            removed = []
            added = []

            # Compare old membership list to new membership list

            for new_item in response_list:
                # self._logger.info('new_item')
                # self._logger.info(type(new_item))
                # self._logger.info(new_item)
                # self._logger.info('members')
                # self._logger.info(type(members))
                # self._logger.info(members)
                if new_item not in members:
                    name = new_item.get('SamAccountName')
                    new_person = [name, new_item]
                    added.append(new_person)
            for old_item in members:
                if old_item not in response_list:
                    name = old_item.get('SamAccountName')
                    old_person = [name, old_item]
                    removed.append(old_person)

            # Create trigger for any added member
            if added:
                self._logger.info('New member(s) in AD group ' + group + 'detected.')

                for person in added:
                    payload = {
                        'accountAdded': person[1],
                        'groupName': group,
                        'tenant': self.creds_name,
                        'samAccountName': person[0]
                    }

                    self.sensor_service.dispatch(trigger='activedirectory.watched_'
                                                         'group_member_added',
                                                 payload=payload)

            # Create trigger for any removed member
            if removed:
                self._logger.info('Member removal in AD group ' + group + ' detected.')

                for person in removed:
                    payload = {
                        'accountRemoved': person[1],
                        'groupName': group,
                        'tenant': self.creds_name,
                        'samAccountName': person[0]
                    }

                    self.sensor_service.dispatch(trigger='activedirectory.watched_'
                                                         'group_member_removed',
                                                 payload=payload)

            if not removed and not added:
                self._logger.info('No change in AD group membership detected')

            self._set_members(members=response_list, group=group)

    def cleanup(self):
        pass

    def add_trigger(self, trigger):
        pass

    def update_trigger(self, trigger):
        pass

    def remove_trigger(self, trigger):
        pass

    def _get_members(self, group):
        if not self.members.get(group) and hasattr(self.sensor_service, 'get_value'):
            temp = self.sensor_service.get_value(group + '.members')
            fixed = ast.literal_eval(temp)
            self.members[group] = fixed

        return self.members[group]

    def _set_members(self, members, group):
        self.members[group] = members

        if hasattr(self.sensor_service, 'set_value'):
            self.sensor_service.set_value(name=group + '.members', value=members)
