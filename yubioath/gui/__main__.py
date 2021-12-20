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

from PyQt5 import QtCore, QtGui, QtWidgets

from yubioath import __version__ as version
from yubioath.gui.view.ccid_disabled import CcidDisabledDialog
from yubioath.yubicommon import qt
from ..cli.keystore import CONFIG_HOME

from ..core.utils import kill_scdaemon, parse_uri
from ..core.exc import NoSpaceError
from . import messages as m
from .controller import GuiController
from .ccid import CardStatus
from .view.systray import Systray
from .view.codes import CodesWidget
from .view.settings import SettingsDialog
from .view.add_cred import AddCredDialog
from .view.set_password import SetPasswordDialog
import sys
import os
import signal
import argparse


ABOUT_TEXT = """
<h2>%s</h2>
%s<br>
%s
""" % (m.app_name, m.copyright, m.version_1)


class MainWidget(QtWidgets.QStackedWidget):

    def __init__(self, controller):
        super(MainWidget, self).__init__()

        self._controller = controller

        self._build_ui()
        controller.changed.connect(self._refresh)
        controller.ccid_disabled.connect(self.ccid_disabled)
        controller.watcher.status_changed.connect(self._set_status)
        self._set_status(controller.watcher.status)

    def ccid_disabled(self):
        if not self._controller.mute_ccid_disabled_warning:
            dialog = CcidDisabledDialog()
            dialog.exec_()
            if dialog.do_not_ask_again.isChecked():
                self._controller.mute_ccid_disabled_warning = 1

    def showEvent(self, event):
        event.accept()

    def _build_ui(self):
        self.codes_widget = CodesWidget(self._controller)
        self.no_key_widget = QtWidgets.QLabel(m.no_key)
        self.no_key_widget.setAlignment(QtCore.Qt.AlignCenter)
        self.addWidget(self.no_key_widget)
        self.addWidget(self.codes_widget)

    def _refresh(self):
        if self._controller.credentials is None:
            self.setCurrentIndex(0)
        else:
            self.setCurrentIndex(1)

    def _set_status(self, status):
        if status == CardStatus.NoCard:
            self.no_key_widget.setText(m.no_key)
        elif status == CardStatus.InUse:
            self.no_key_widget.setText(m.key_busy)
        elif status == CardStatus.Present:
            self.no_key_widget.setText(m.key_present)


class YubiOathApplication(qt.Application):

    def __init__(self, args):
        super(YubiOathApplication, self).__init__(m, version)

        QtCore.QCoreApplication.setOrganizationName(m.organization)
        QtCore.QCoreApplication.setOrganizationDomain(m.domain)
        QtCore.QCoreApplication.setApplicationName(m.app_name)

        self.ensure_singleton()

        self._widget = None
        self.settings = qt.Settings.wrap(
            os.path.join(CONFIG_HOME, 'settings.ini'),
            QtCore.QSettings.IniFormat)
        self._settings = self.settings.get_group('settings')

        self._controller = GuiController(self, self._settings)

        self._systray = Systray(self)

        self._init_systray(args.tray or self._settings.get('systray', False))
        self._init_window(not args.tray)

    def _init_systray(self, show=False):
        self._systray.setIcon(QtGui.QIcon(':/yubioath.png'))
        self._systray.setVisible(show)

    def _init_window(self, show=True):
        self.window.setWindowTitle(m.win_title_1 % self.version)
        self.window.setWindowIcon(QtGui.QIcon(':/yubioath.png'))
        self.window.resize(self._settings.get('size', QtCore.QSize(320, 340)))

        self._build_menu_bar()

        self.window.showEvent = self._on_shown
        self.window.closeEvent = self._on_closed
        self.window.hideEvent = self._on_hide

        if show:
            self.window.show()
            self.window.raise_()
        else:
            self._controller.stop()

    def _build_menu_bar(self):
        file_menu = self.window.menuBar().addMenu(m.menu_file)
        self._add_action = QtWidgets.QAction(m.action_add, file_menu)
        self._add_action.triggered.connect(self._add_credential)
        file_menu.addAction(self._add_action)
        self._import_action = QtWidgets.QAction(m.action_import, file_menu)
        self._import_action.triggered.connect(self._import)
        file_menu.addAction(self._import_action)
        self._password_action = QtWidgets.QAction(m.action_password, file_menu)
        self._password_action.triggered.connect(self._change_password)
        self._password_action.setEnabled(False)
        file_menu.addAction(self._password_action)
        file_menu.addSeparator()
        self._reset_action = QtWidgets.QAction(m.action_reset, file_menu)
        self._reset_action.triggered.connect(self._reset)
        self._reset_action.setEnabled(False)
        file_menu.addAction(self._reset_action)
        file_menu.addSeparator()
        settings_action = QtWidgets.QAction(m.action_settings, file_menu)
        settings_action.triggered.connect(self._show_settings)
        file_menu.addAction(settings_action)
        quit_action = QtWidgets.QAction(m.action_quit, file_menu)
        quit_action.triggered.connect(self._systray.quit)
        file_menu.addAction(quit_action)

        if sys.platform == "darwin":
            close_action = QtWidgets.QAction(m.action_close, file_menu)
            close_action.setShortcut(QtGui.QKeySequence.Close)
            close_action.triggered.connect(self.window.hide)
            file_menu.addAction(close_action)

        help_menu = self.window.menuBar().addMenu(m.menu_help)
        about_action = QtWidgets.QAction(m.action_about, help_menu)
        about_action.triggered.connect(self._about)
        help_menu.addAction(about_action)

        self._controller.changed.connect(self._refresh_menu)

    def _refresh_menu(self):
        enabled = bool(self._controller._reader)
        self._password_action.setEnabled(enabled)
        self._reset_action.setEnabled(enabled)

    def _on_shown(self, event):
        if self._controller.backend == 'ccid':
            if self._settings.get('kill_scdaemon', False):
                kill_scdaemon()

        if not self._widget:
            self._widget = MainWidget(self._controller)
            self.window.setCentralWidget(self._widget)
        self._controller.start()
        self._controller.refresh_codes()
        event.accept()

    def _on_hide(self, event):
        if self._widget:
            self._widget.codes_widget.clear_search_filter()
        self._controller.forget_passwords()
        self._controller.stop()
        event.accept()

    def _on_closed(self, event):
        self._settings['size'] = self.window.size()
        if self._systray.isVisible():
            # Unless move is called the position isn't saved!
            self.window.move(self.window.pos())
            self.window.hide()
            event.ignore()
        else:
            event.accept()

    def _about(self):
        QtWidgets.QMessageBox.about(
            self.window,
            m.about_1 % m.app_name,
            ABOUT_TEXT % (self.version,))

    def _reset(self):
        c = self._controller.get_capabilities()
        if c.present:
            res = QtWidgets.QMessageBox.warning(self.window,
                m.reset_title,
                m.reset_warning_desc,
                QtWidgets.QMessageBox.Yes,
                QtWidgets.QMessageBox.No)
            if res == QtWidgets.QMessageBox.Yes:
                self._controller.reset_device()
        else:
            QtWidgets.QMessageBox.critical(self.window, 'No key', 'No key')

    def _import(self):
        c = self._controller.get_capabilities()
        if c.present:
            res = QtWidgets.QFileDialog.getOpenFileName(self.window,
                filter="Text files (*.txt)")
            filepath = res[0]
            if filepath:
                found, imported = 0, 0
                errors = []
                for line in open(filepath, 'rt'):
                    line = line.rstrip()
                    if line.startswith('otpauth://'):
                        found += 1
                        try:
                            parsed = parse_uri(line)
                            self._controller.add_parsed(parsed)
                            imported += 1
                        except Exception as exc:
                            errors.append((line, str(exc)))
                            pass
                msgbox = QtWidgets.QMessageBox.information
                error_desc = ''
                if found != imported:
                    msgbox = QtWidgets.QMessageBox.warning
                    error_desc = '<br><br>Import failures:<br>'
                    for line, error in errors:
                        error_desc += 'Line: %s, Error: %s<br>' % (line, error)
                msgbox(self.window, m.imported, m.imported_desc % (found,
                    imported, error_desc))
        else:
            QtWidgets.QMessageBox.critical(self.window, 'No key', 'No key')

    def _add_credential(self):
        c = self._controller.get_capabilities()
        if c.present:
            dialog = AddCredDialog(
                self.worker,
                c,
                self._controller.get_entry_names(),
                parent=self.window)
            if dialog.exec_():
                if not self._controller._reader:
                    QtWidgets.QMessageBox.critical(
                        self.window, m.key_removed, m.key_removed_desc)
                else:
                    try:
                        self._controller.add_cred(
                            dialog.name,
                            dialog.key,
                            oath_type=dialog.oath_type,
                            digits=dialog.n_digits,
                            algo=dialog.algorithm,
                            require_touch=dialog.require_touch,
                            require_manual_refresh=dialog.require_manual_refresh)
                    except NoSpaceError:
                        QtWidgets.QMessageBox.critical(
                            self.window, m.no_space, m.no_space_desc)
        else:
            QtWidgets.QMessageBox.critical(self.window, 'No key', 'No key')

    def _change_password(self):
        dialog = SetPasswordDialog(self.window)
        if dialog.exec_():
            if not self._controller._reader:
                QtWidgets.QMessageBox.critical(
                    self.window, m.key_removed, m.key_removed_desc)
            else:
                self._controller.set_password(dialog.password, dialog.remember)

    def _show_settings(self):
        if SettingsDialog(self.window, self._settings).exec_():
            self._systray.setVisible(self._settings.get('systray', False))
            self._controller.settings_changed()


def parse_args():
    parser = argparse.ArgumentParser(description='Yubico Authenticator',
                                     add_help=True)
    parser.add_argument('-t', '--tray', action='store_true', help='starts '
                        'the application minimized to the systray')
    return parser.parse_args()


def main():
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    QtWidgets.QApplication.setAttribute(QtCore.Qt.AA_EnableHighDpiScaling, True)
    if hasattr(QtCore.Qt, 'AA_UseHighDpiPixmaps'):
        QtWidgets.QApplication.setAttribute(QtCore.Qt.AA_UseHighDpiPixmaps, True)
    app = YubiOathApplication(parse_args())
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()
