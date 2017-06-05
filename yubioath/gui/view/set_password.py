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


class SetPasswordDialog(qt.Dialog):

    def __init__(self, parent):
        super(SetPasswordDialog, self).__init__(parent)

        self.setWindowTitle(m.set_pass)
        self._build_ui()

    def _build_ui(self):
        layout = QtWidgets.QFormLayout(self)

        self._new_pass = QtWidgets.QLineEdit()
        self._new_pass.setEchoMode(QtWidgets.QLineEdit.Password)
        layout.addRow(m.new_pass, self._new_pass)

        self._ver_pass = QtWidgets.QLineEdit()
        self._ver_pass.setEchoMode(QtWidgets.QLineEdit.Password)
        layout.addRow(m.ver_pass, self._ver_pass)

        self._remember = QtWidgets.QCheckBox(m.remember)
        layout.addRow(self._remember)

        btns = QtWidgets.QDialogButtonBox(QtWidgets.QDialogButtonBox.Ok |
                                          QtWidgets.QDialogButtonBox.Cancel)
        btns.accepted.connect(self._save)
        btns.rejected.connect(self.reject)
        layout.addRow(btns)

    def _save(self):
        if not self._new_pass.text() == self._ver_pass.text():
            self._new_pass.setText('')
            self._ver_pass.setText('')
            self._new_pass.setFocus()
            QtWidgets.QMessageBox.warning(self,
                                          m.pass_mismatch,
                                          m.pass_mismatch_desc)
        else:
            self.accept()

    @property
    def password(self):
        return self._new_pass.text()

    @property
    def remember(self):
        return self._remember.isChecked()
