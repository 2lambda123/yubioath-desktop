# Copyright (c) 2014 Yubico AB
# All rights reserved.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#
# Additional permission under GNU GPL version 3 section 7
#
# If you modify this program, or any covered work, by linking or
# combining it with the OpenSSL project's OpenSSL library (or a
# modified version of that library), containing parts covered by the
# terms of the OpenSSL or SSLeay licenses, We grant you additional
# permission to convey the resulting work. Corresponding Source for a
# non-source form of such a combination shall include the source code
# for the parts of OpenSSL used as well as that of the covered work.


from .ccid import YubiOathCcid
from .exc import CardError


class Controller(object):

    def _prompt_touch(self):
        pass

    def _end_prompt_touch(self):
        pass

    def unlock(self, std):
        raise ValueError('Password required')

    def read_creds(self, ccid_dev, timestamp):
        results = []
        key_found = False

        if ccid_dev:
            try:
                std = YubiOathCcid(ccid_dev)
                key_found = True
                if std.locked:
                    self.unlock(std)
                results.extend(std.calculate_all(timestamp))
            except CardError:
                pass  # No applet?

        if not key_found:
            return None

        return results

    def set_password(self, dev, password):
        if dev.locked:
            self.unlock(dev)
        key = dev.calculate_key(password)
        dev.set_key(key)
        return key

    def add_cred(self, dev, *args, **kwargs):
        if dev.locked:
            self.unlock(dev)
        dev.put(*args, **kwargs)

    def delete_cred(self, dev, name):
        if dev.locked:
            self.unlock(dev)
        dev.delete(name)

    def reset_device(self, dev):
        dev.reset()
