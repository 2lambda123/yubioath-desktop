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
from ...core.standard import ALG_SHA1, ALG_SHA256, TYPE_TOTP, TYPE_HOTP
from ...core.utils import parse_uri
from .. import messages as m
from ..qrparse import parse_qr_codes
from ..qrdecode import decode_qr_data
from PyQt5 import QtCore, QtGui, QtWidgets
from base64 import b32decode
import re

NAME_VALIDATOR = QtGui.QRegExpValidator(QtCore.QRegExp(r'.{3,}'))


class B32Validator(QtGui.QValidator):

    def __init__(self, parent=None):
        super(B32Validator, self).__init__(parent)
        self.partial = re.compile(r'^[ a-z2-7]+$', re.IGNORECASE)

    def fixup(self, value):
        unpadded = value.upper().rstrip('=').replace(' ', '')
        return b32decode(unpadded + '=' * (-len(unpadded) % 8))

    def validate(self, value, pos):
        try:
            self.fixup(value)
            return (QtGui.QValidator.Acceptable, value, pos)
        except:
            if self.partial.match(value):
                return (QtGui.QValidator.Intermediate, value, pos)
        return (QtGui.QValidator.Invalid, value, pos)


class AddCredDialog(qt.Dialog):

    def __init__(self, worker, version, existing_entry_names, parent=None):
        super(AddCredDialog, self).__init__(parent)

        self._worker = worker
        self._version = version
        self.setWindowTitle(m.add_cred)
        self._existing_entry_names = existing_entry_names
        self._build_ui()

    def _build_ui(self):
        layout = QtWidgets.QFormLayout(self)

        self._qr_btn = QtWidgets.QPushButton(QtGui.QIcon(':/qr.png'), m.qr_scan)
        self._qr_btn.clicked.connect(self._scan_qr)
        layout.addRow(self._qr_btn)

        self._cred_name = QtWidgets.QLineEdit()
        self._cred_name.setValidator(NAME_VALIDATOR)
        layout.addRow(m.cred_name, self._cred_name)

        self._cred_key = QtWidgets.QLineEdit()
        self._cred_key.setValidator(B32Validator())
        layout.addRow(m.cred_key, self._cred_key)

        layout.addRow(QtWidgets.QLabel(m.cred_type))
        self._cred_type = QtWidgets.QButtonGroup(self)
        self._cred_totp = QtWidgets.QRadioButton(m.cred_totp)
        self._cred_totp.setProperty('value', TYPE_TOTP)
        self._cred_type.addButton(self._cred_totp)
        layout.addRow(self._cred_totp)
        self._cred_hotp = QtWidgets.QRadioButton(m.cred_hotp)
        self._cred_hotp.setProperty('value', TYPE_HOTP)
        self._cred_type.addButton(self._cred_hotp)
        layout.addRow(self._cred_hotp)
        self._cred_totp.setChecked(True)

        self._n_digits = QtWidgets.QComboBox()
        self._n_digits.addItems(['6', '8'])
        layout.addRow(m.n_digits, self._n_digits)

        self._algorithm = QtWidgets.QComboBox()
        self._algorithm.addItems(['SHA-1', 'SHA-256'])
        layout.addRow(m.algorithm, self._algorithm)

        self._require_touch = QtWidgets.QCheckBox(m.require_touch)
        # Touch-required support not available before 4.2.6
        if self._version >= (4, 2, 6):
            layout.addRow(self._require_touch)

        btns = QtWidgets.QDialogButtonBox(QtWidgets.QDialogButtonBox.Ok |
                                      QtWidgets.QDialogButtonBox.Cancel)
        btns.accepted.connect(self._save)
        btns.rejected.connect(self.reject)
        layout.addRow(btns)

    def _do_scan_qr(self, qimage):
        for qr in parse_qr_codes(qimage):
            try:
                data = decode_qr_data(qr)
                if data.startswith('otpauth://'):
                    return parse_uri(data)
            except:
                pass
        return None

    def _scan_qr(self):
        screen = QtWidgets.QApplication.primaryScreen()
        qimage = screen.grabWindow(0).toImage()
        self._worker.post(m.qr_scanning, (self._do_scan_qr, qimage),
                          self._handle_qr)

    def _handle_qr(self, parsed):
        if parsed:
            otp_type = parsed['type'].lower()
            n_digits = parsed.get('digits', '6')
            algo = parsed.get('algorithm', 'SHA1').upper()

            if otp_type not in ['totp', 'hotp']:
                QtWidgets.QMessageBox.warning(
                    self,
                    m.qr_invalid_type,
                    m.qr_invalid_type_desc)
                return
            if n_digits not in ['6', '8']:
                QtWidgets.QMessageBox.warning(
                    self,
                    m.qr_invalid_digits,
                    m.qr_invalid_digits_desc)
                return
            if algo not in ['SHA1', 'SHA256']:
                # RFC6238 says SHA512 is also supported,
                # but it's not implemented here yet.
                QtWidgets.QMessageBox.warning(
                    self,
                    m.qr_invalid_algo,
                    m.qr_invalid_algo_desc)
                return
            for needed in ['name', 'secret']:
                if needed not in parsed:
                    QtWidgets.QMessageBox.warning(
                        self,
                        m.qr_missing_key,
                        m.qr_missing_key_desc % (needed,))
                    return

            self._cred_name.setText(parsed['name'])
            self._cred_key.setText(parsed['secret'])
            self._n_digits.setCurrentIndex(0 if n_digits == '6' else 1)
            self._algorithm.setCurrentIndex(0 if algo == 'SHA1' else 1)
            if otp_type == 'totp':
                self._cred_totp.setChecked(True)
            else:
                self._cred_hotp.setChecked(True)
        else:
            QtWidgets.QMessageBox.warning(
                self,
                m.qr_not_found,
                m.qr_not_found_desc)

    def _entry_exists(self):
        return self._cred_name.text() in self._existing_entry_names

    def _confirm_overwrite(self):
        return QtWidgets.QMessageBox.question(
            self, m.overwrite_entry, m.overwrite_entry_desc,
            QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.Yes,
            QtWidgets.QMessageBox.No) == QtWidgets.QMessageBox.Yes

    def _save(self):
        if not self._cred_name.hasAcceptableInput():
            QtWidgets.QMessageBox.warning(self, m.invalid_name, m.invalid_name_desc)
            self._cred_name.selectAll()
        elif not self._cred_key.hasAcceptableInput():
            QtWidgets.QMessageBox.warning(self, m.invalid_key, m.invalid_key_desc)
            self._cred_key.selectAll()
        elif self._entry_exists() and not self._confirm_overwrite():
            self._cred_key.selectAll()
        else:
            self.accept()

    @property
    def name(self):
        return self._cred_name.text()

    @property
    def key(self):
        return self._cred_key.validator().fixup(self._cred_key.text())

    @property
    def oath_type(self):
        return self._cred_type.checkedButton().property('value')

    @property
    def n_digits(self):
        return int(self._n_digits.currentText())

    @property
    def algorithm(self):
        return ALG_SHA1 if self._algorithm.currentIndex() == 0 else ALG_SHA256

    @property
    def require_touch(self):
        return self._require_touch.isChecked()
