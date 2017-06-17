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

from yubioath.yubicommon import qt
from .. import messages as m
from PyQt5 import QtWidgets


class SettingsDialog(qt.Dialog):

    def __init__(self, parent, settings):
        super(SettingsDialog, self).__init__(parent)
        self.settings = settings

        self.setWindowTitle(m.settings)
        self.accepted.connect(self._save)
        self._build_ui()
        self._reset()

    def _build_ui(self):
        layout = QtWidgets.QFormLayout(self)

        layout.addRow(self.section(m.advanced))

        # Systray
        self._systray = QtWidgets.QCheckBox(m.enable_systray)
        self._systray.setToolTip(m.tt_systray)
        layout.addRow(self._systray)

        # Kill scdaemon
        self._kill_scdaemon = QtWidgets.QCheckBox(m.kill_scdaemon)
        self._kill_scdaemon.setToolTip(m.tt_kill_scdaemon)
        layout.addRow(self._kill_scdaemon)

        layout.addRow(self.section(m.oath_backend))

        # OATH storage backend
        self._backend = QtWidgets.QComboBox()
        self._backend.addItem(m.oath_backend_ccid, 'ccid')
        self._backend.addItem(m.oath_backend_sqlite, 'sqlite')
        layout.addRow(self._backend)

        layout.addRow(self.section(m.oath_backend_ccid))

        # Reader name
        self._reader_name = QtWidgets.QLineEdit()
        self._reader_name.setToolTip(m.tt_reader_name)
        layout.addRow(m.reader_name, self._reader_name)

        btns = QtWidgets.QDialogButtonBox(QtWidgets.QDialogButtonBox.Ok |
                                      QtWidgets.QDialogButtonBox.Cancel)
        btns.accepted.connect(self.accept)
        btns.rejected.connect(self.reject)
        layout.addRow(btns)

    def _reset(self):
        self._systray.setChecked(self.settings.get('systray', False))
        self._kill_scdaemon.setChecked(self.settings.get('kill_scdaemon', False))
        self._backend.setCurrentIndex(self._backend.findData(self.settings.get('backend', 'ccid')))
        self._reader_name.setText(self.settings.get('reader', 'Yubikey'))

    @property
    def systray(self):
        return self._systray.isChecked()

    @property
    def kill_scdaemon(self):
        return self._kill_scdaemon.isChecked()

    @property
    def reader_name(self):
        return self._reader_name.text()

    @property
    def backend(self):
        return self._backend.itemData(self._backend.currentIndex())

    def _save(self):
        self.settings['systray'] = self.systray
        self.settings['kill_scdaemon'] = self.kill_scdaemon
        self.settings['backend'] = self.backend
        self.settings['reader'] = self.reader_name
