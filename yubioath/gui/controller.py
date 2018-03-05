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

from ..cli.keystore import CONFIG_HOME
from ..core.ccid import YubiOathCcid
from ..core.sqlite import YubiOathSqlite
from ..core.controller import Controller
from ..core.exc import CardError, DeviceLockedError, NoSpaceError
from ..core.utils import (ALG_SHA1, ALG_SHA256, ALG_SHA512, TYPE_HOTP,
        TYPE_TOTP, Capabilities, kill_scdaemon)
from .ccid import CardStatus, ccid_watcher
from .sqlite import sqlite_watcher
from yubioath.yubicommon.qt.utils import is_minimized
from .view.get_password import GetPasswordDialog
from .keystore import get_keystore
from . import messages as m
from yubioath.core.utils import ccid_supported_but_disabled
from yubioath.yubicommon.qt import get_active_window
from PyQt5 import QtCore, QtWidgets
from base64 import b32decode
from time import time
from collections import namedtuple
from threading import RLock
import os


Code = namedtuple('Code', 'code timestamp ttl')
UNINITIALIZED = Code('', 0, 0)

TIME_PERIOD = 30
INF = float('inf')


class CredEntry(QtCore.QObject):
    changed = QtCore.pyqtSignal()

    def __init__(self, cred, controller):
        super(CredEntry, self).__init__()
        self.cred = cred
        self._controller = controller
        self._code = Code('', 0, 0)

    @property
    def code(self):
        return self._code

    @code.setter
    def code(self, value):
        self._code = value
        self.changed.emit()
        if self.manual:
            self._controller.refreshed.emit()

    @property
    def manual(self):
        return self.cred.touch or \
            self.cred.manual or \
            self.cred.oath_type == TYPE_HOTP

    def calculate(self):
        window = get_active_window()
        dialog = QtWidgets.QMessageBox(window)
        dialog.setWindowTitle(m.touch_title)
        dialog.setStandardButtons(QtWidgets.QMessageBox.NoButton)
        dialog.setIcon(QtWidgets.QMessageBox.Information)
        dialog.setText(m.touch_desc)
        timer = None

        def cb(code):
            if timer:
                timer.stop()
            dialog.accept()
            if isinstance(code, Exception):
                QtWidgets.QMessageBox.warning(window, m.error,
                                          code.message)
            else:
                self.code = code
        self._controller._app.worker.post_bg((self._controller._calculate_cred,
                                              self.cred), cb)
        if self.cred.touch:
            dialog.exec_()
        elif self.cred.oath_type == TYPE_HOTP:
            # HOTP might require touch, we don't know. Assume yes after 500ms.
            timer = QtCore.QTimer(window)
            timer.setSingleShot(True)
            timer.timeout.connect(dialog.exec_)
            timer.start(500)

    def delete(self):
        self._controller.delete_cred(self.cred.name)


def names(creds):
    return set(c.cred.name for c in creds)


class Timer(QtCore.QObject):
    time_changed = QtCore.pyqtSignal(int)

    def __init__(self, interval):
        super(Timer, self).__init__()
        self._interval = interval
        self._enabled = True
        self._running = True
        self._timer_interval = 5000
        self._calc_time()
        self._last_emitted = self._time

        QtCore.QTimer.singleShot(self._wait_time, self._tick)

    def _calc_time(self):
        # First calculate which code timestamp we're at.
        now = time()
        rem = now % self._interval
        self._time = int(now - rem)

        # Now determine how long to wait until the next _tick()
        rem = int((self._interval - rem) * 1000)
        if rem > self._timer_interval + 100:
            self._wait_time = self._timer_interval
        else:
            # Intentionally overshoot by minimal amount of time possible in
            # order to fire the time_changed signal immediately after the
            # deadline.
            self._wait_time = rem + 50

    def _tick(self):
        self._calc_time()
        if self._enabled:
            if self._time != self._last_emitted:
                self.time_changed.emit(self._time)
                self._last_emitted = self._time
        QtCore.QTimer.singleShot(self._wait_time, self._tick)

    def stop(self):
        self._enabled = False

    def start(self):
        self._enabled = True

    @property
    def time(self):
        return self._time


class GuiController(QtCore.QObject, Controller):
    refreshed = QtCore.pyqtSignal()
    changed = QtCore.pyqtSignal()
    ccid_disabled = QtCore.pyqtSignal()

    def __init__(self, app, settings):
        super(GuiController, self).__init__()
        self._app = app
        self._settings = settings
        self._needs_read = False
        self._lock = RLock()
        self._keystore = get_keystore()
        self._current_device_has_ccid_disabled = False
        self.timer = Timer(TIME_PERIOD)

        self._init_backend()

        self.startTimer(3000)
        self.timer.time_changed.connect(self.refresh_codes)

    def _init_backend(self):
        self.watcher = None
        self._reader = None
        self._creds = None

        if self.backend == 'ccid':
            self.Connector = YubiOathCcid
            self.watcher = ccid_watcher(self.reader_name, self._on_reader)
        elif self.backend == 'sqlite':
            self.Connector = YubiOathSqlite
            self.watcher = sqlite_watcher(os.path.join(CONFIG_HOME, "tokens.db"), self._on_reader)

    def settings_changed(self):
        self._init_backend()
        if self.backend == 'ccid':
            if self._settings.get('kill_scdaemon', False):
                kill_scdaemon()

    @property
    def reader_name(self):
        return self._settings.get('reader', 'Yubikey')

    @property
    def backend(self):
        return self._settings.get('backend', 'ccid')

    @property
    def mute_ccid_disabled_warning(self):
        return self._settings.get('mute_ccid_disabled_warning', 0)

    @mute_ccid_disabled_warning.setter
    def mute_ccid_disabled_warning(self, value):
        self._settings['mute_ccid_disabled_warning'] = value

    def unlock(self, conn):
        if conn.locked:
            key = self._keystore.get(conn.id)
            if not key:
                self._app.worker.post_fg((self._init_conn, conn))
                return False
            conn.unlock(key)
        return True

    @property
    def credentials(self):
        return self._creds

    def has_expiring(self, timestamp):
        for c in self._creds or []:
            if c.code.timestamp >= timestamp and c.code.ttl < INF:
                return True
        return False

    def get_capabilities(self):
        with self._lock:
            device = self.watcher.open()

            if device:
                conn = self.Connector(device)
                return conn.capabilities

            return Capabilities(None, [], False)

    def get_entry_names(self):
        return names(self._creds)

    def _on_reader(self, watcher, reader):
        if reader:
            if self._reader is None:
                self._reader = reader
                self._creds = []
                if is_minimized(self._app.window):
                    self._needs_read = True
                else:
                    device = watcher.open()
                    if device:
                        try:
                            conn = self.Connector(device)
                        except CardError:
                            self._reader = None
                            self._creds = None
                            self.changed.emit()
                            return
                        self._app.worker.post_fg((self._init_conn, conn))
                    else:
                        self._needs_read = True
            elif self._needs_read:
                self.refresh_codes(self.timer.time)
        else:
            self._reader = None
            self._creds = None
            self.changed.emit()

    def _init_conn(self, conn):
        with self._lock:
            while conn.locked:
                if self._keystore.get(conn.id) is None:
                    dialog = GetPasswordDialog(get_active_window())
                    if dialog.exec_():
                        self._keystore.put(conn.id,
                                           conn.calculate_key(dialog.password),
                                           dialog.remember)
                    else:
                        return
                try:
                    conn.unlock(self._keystore.get(conn.id))
                except CardError as exc:
                    self._keystore.delete(conn.id)
                    if exc.status == 0x6a80:
                        # wrong syntax (bad password)
                        pass
                    else:
                        # unknown, don't retry
                        return
            self.refresh_codes(self.timer.time, conn)

    def _await(self):
        self._creds = None

    def wrap_credential(self, tup):
        (cred, code) = tup
        entry = CredEntry(cred, self)
        if code and code not in ['INVALID', 'TIMEOUT']:
            entry.code = Code(code, self.timer.time, TIME_PERIOD)

        return entry

    def _set_creds(self, creds):
        if creds:
            creds = [self.wrap_credential(c) for c in creds]
            if self._creds and names(creds) == names(self._creds):
                entry_map = dict((c.cred.name, c) for c in creds)
                for entry in self._creds:
                    cred = entry.cred
                    code = entry_map[cred.name].code
                    if code.code:
                        entry.code = code
                    elif cred.oath_type != entry_map[cred.name].cred.oath_type:
                        break
                self.refreshed.emit()
                return
            elif self._reader and self._needs_read and self._creds:
                return
        self._creds = creds
        self.changed.emit()

    def _calculate_cred(self, cred):
        with self._lock:
            now = time()
            timestamp = self.timer.time
            if timestamp + TIME_PERIOD - now < 10:
                timestamp += TIME_PERIOD
            ttl = TIME_PERIOD
            if cred.oath_type == TYPE_HOTP:
                ttl = INF

            device = self.watcher.open()
            if not device:
                if self.watcher.status != CardStatus.Present:
                    self._set_creds(None)
                return
            conn = self.Connector(device)
            if self.unlock(conn):
                return Code(conn.calculate(cred.name, cred.oath_type, timestamp),
                            timestamp, ttl)

    def _refresh_codes_worker(self, timestamp=None, conn=None):
        with self._lock:
            if not conn:
                device = self.watcher.open()
            else:
                device = conn._device
            self._needs_read = bool(self._reader and device is None)
            timestamp = timestamp or self.timer.time
            try:
                creds = self.read_creds(device, timestamp)
            except DeviceLockedError:
                creds = []
            self._set_creds(creds)

    def refresh_codes(self, timestamp=None, conn=None):
        if not self._reader and self.watcher.reader:
            return self._on_reader(self.watcher, self.watcher.reader)
        elif is_minimized(self._app.window):
            self._needs_read = True
            return
        self._app.worker.post_bg((self._refresh_codes_worker, timestamp, conn))

    def timerEvent(self, event):
        if not is_minimized(self._app.window):
            if self._reader and self._needs_read:
                self.refresh_codes()
            elif self._reader is None and self.backend == 'ccid':
                if ccid_supported_but_disabled():
                    if not self._current_device_has_ccid_disabled:
                        self.ccid_disabled.emit()
                    self._current_device_has_ccid_disabled = True
                    event.accept()
                    return
            self._current_device_has_ccid_disabled = False
        event.accept()

    def add_parsed(self, parsed):
        if 'secret' not in parsed:
            raise ValueError('Missing "secret" parameter')
        if 'type' not in parsed:
            raise ValueError('Missing OATH credential type')

        key = parsed['secret']
        name = parsed.get('name')
        oath_type = parsed.get('type')
        hmac_algorithm = parsed.get('algorithm', 'SHA1').upper()
        digits = int(parsed.get('digits', '6'))
        imf = int(parsed.get('counter', '0'))

        if oath_type not in ['totp', 'hotp']:
            raise ValueError('Invalid OATH credential type')

        if hmac_algorithm == 'SHA1':
            algo = ALG_SHA1
        elif hmac_algorithm == 'SHA256':
            algo = ALG_SHA256
        elif hmac_algorithm == 'SHA512':
            algo = ALG_SHA512
        else:
            raise ValueError('Invalid HMAC algorithm')

        if algo not in self.get_capabilities().algorithms:
            raise NotImplementedError('Selected HMAC algorithm not supported by device')

        if digits == 5 and name.startswith('Steam:'):
            # Steam is a special case where we allow the otpauth
            # URI to contain a 'digits' value of '5'.
            digits = 6

        if digits not in [6, 8]:
            raise ValueError('Invalid number of digits for OTP')

        digits = digits or 6
        unpadded = key.upper()
        key = b32decode(unpadded + '=' * (-len(unpadded) % 8))

        if not name:
            raise ValueError('Credential is missing a name')

        oath_type = TYPE_TOTP if oath_type == 'totp' else TYPE_HOTP
        try:
            self.add_cred(name, key, oath_type, digits=digits, imf=imf,
                    algo=algo)
        except NoSpaceError:
            raise IOError(
                'There is not enough space to add another credential on your'
                ' device. To create free space to add a new '
                'credential, delete those you no longer need.')

    def add_cred(self, *args, **kwargs):
        with self._lock:
            device = self.watcher.open()
            if device:
                conn = self.Connector(device)
                if self.unlock(conn):
                    super(GuiController, self).add_cred(conn, *args, **kwargs)
                    self._creds = None
                    self.refresh_codes()

    def delete_cred(self, name):
        with self._lock:
            device = self.watcher.open()
            if device:
                conn = self.Connector(device)
                if self.unlock(conn):
                    super(GuiController, self).delete_cred(conn, name)
                    self._creds = None
                    self.refresh_codes()

    def set_password(self, password, remember=False):
        with self._lock:
            device = self.watcher.open()
            if device:
                conn = self.Connector(device)
                if self.unlock(conn):
                    key = super(GuiController, self).set_password(conn, password)
                    self._keystore.put(conn.id, key, remember)

    def reset_device(self):
        with self._lock:
            device = self.watcher.open()
            if device:
                conn = self.Connector(device)
                self._keystore.delete(conn.id)
                super(GuiController, self).reset_device(conn)
                self._creds = None
                self.refresh_codes()

    def start(self):
        self.watcher.active()
        self.timer.start()

    def stop(self):
        self.timer.stop()
        self.watcher.passive()

    def forget_passwords(self):
        self._keystore.forget()
        self._set_creds([])
