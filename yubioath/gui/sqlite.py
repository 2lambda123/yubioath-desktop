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

from PyQt5 import QtCore

from ..core.sqlite import SQLiteDevice
from .ccid import CardStatus


class SQLiteWatcher(QtCore.QObject):
    status_changed = QtCore.pyqtSignal(int)

    def __init__(self, path, callback, parent=None):
        super(SQLiteWatcher, self).__init__(parent)
        self._status = CardStatus.Present
        self.path = path
        self._callback = callback or (lambda _: _)
        self._device = None
        self.reader = True

    @property
    def status(self):
        return self._status

    @property
    def reader(self):
        return self._reader

    @reader.setter
    def reader(self, value):
        self._reader = value
        self._callback(self, value)

    def open(self):
        if self._device is not None:
            return self._device
        self._device = SQLiteDevice(self.path)
        return self._device

    def passive(self):
        pass

    def active(self):
        pass


def sqlite_watcher(path, callback=None):
    return SQLiteWatcher(path, callback)
