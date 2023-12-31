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
from .. import messages as m
from ...core.utils import TYPE_HOTP
from yubioath.yubicommon.qt.utils import connect_once
from time import time


TIMELEFT_STYLE = """
QProgressBar {
  padding: 1px;
}
QProgressBar::chunk {
  background-color: #2196f3;
  margin: 0px;
  width: 1px;
}
"""


class TimeleftBar(QtWidgets.QProgressBar):
    def __init__(self):
        super(TimeleftBar, self).__init__()

        self.setStyleSheet(TIMELEFT_STYLE)
        self.setMaximumHeight(8)
        self.setInvertedAppearance(True)
        self.setRange(0, 30000)
        self.setValue(0)
        self.setTextVisible(False)

        self._refresh_time = 250
        self._timer = 0
        self._timeleft = 0
        self._target = 0

    def set_target(self, target):
        self._target = target
        self._update()

    def _update(self):
        self._timeleft = (self._target - time()) * 1000
        self._timeleft = max(self._timeleft, 0)
        if self._timeleft >= self.maximum() + 500:
            # System clock jump? We should get a set_target() call to correct
            # it as soon as the credentials get refreshed.
            self._timeleft = 0
        self._timeleft = min(self._timeleft, self.maximum())
        self.setValue(int(self._timeleft))
        if self._timer == 0 and self._timeleft > 0:
            self._timer = self.startTimer(self._refresh_time)
        elif self._timer != 0 and self._timeleft <= 0:
            self.killTimer(self._timer)
            self._timer = 0

    def timerEvent(self, event):
        self._update()
        event.accept()


class SearchBox(QtWidgets.QWidget):

    def __init__(self, codes):
        super(SearchBox, self).__init__()

        self._codeswidget = codes

        layout = QtWidgets.QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        self._model = QtCore.QStringListModel()
        self._completer = QtWidgets.QCompleter()
        self._completer.setModel(self._model)
        self._completer.setCompletionMode(QtWidgets.QCompleter.InlineCompletion)
        self._completer.setCaseSensitivity(QtCore.Qt.CaseInsensitive)

        self._lineedit = QtWidgets.QLineEdit()
        self._lineedit.setPlaceholderText(m.search)
        self._lineedit.setCompleter(self._completer)
        self._lineedit.textChanged.connect(self._text_changed)
        layout.addWidget(self._lineedit)

        self._shortcut_focus = QtWidgets.QShortcut(
            QtGui.QKeySequence.Find,
            self._lineedit, self._set_focus)
        self._shortcut_clear = QtWidgets.QShortcut(
            QtGui.QKeySequence(self.tr("Esc")),
            self._lineedit, self._lineedit.clear)

        self._timer = QtCore.QTimer()
        self._timer.setSingleShot(True)
        self._timer.setInterval(300)
        self._timer.timeout.connect(self._filter_changed)

    def _set_focus(self):
        self._lineedit.setFocus()
        self._lineedit.selectAll()

    def _text_changed(self, query):
        self._timer.stop()
        self._timer.start()

    def _filter_changed(self):
        search_filter = self._lineedit.text()
        self._codeswidget._set_search_filter(search_filter)

    def set_string_list(self, strings):
        self._model.setStringList(strings)

    def clear(self):
        self._lineedit.clear()


class CodeMenu(QtWidgets.QMenu):

    def __init__(self, parent):
        super(CodeMenu, self).__init__(parent)
        self.entry = parent.entry

        self.addAction(m.action_delete).triggered.connect(self._delete)

    def _delete(self):
        res = QtWidgets.QMessageBox.warning(self, m.delete_title,
                                            m.delete_desc_1 % self.entry.cred.name,
                                            QtWidgets.QMessageBox.Ok,
                                            QtWidgets.QMessageBox.Cancel)
        if res == QtWidgets.QMessageBox.Ok:
            self.entry.delete()


class Code(QtWidgets.QWidget):

    def __init__(self, entry, timer):
        super(Code, self).__init__()
        self.entry = entry
        self.issuer, self.name = self._split_issuer_name()
        self.entry.changed.connect(self._draw)
        self.timer = timer
        self.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self._menu)

        self._build_ui()

    def _build_ui(self):
        layout = QtWidgets.QHBoxLayout(self)
        labels = QtWidgets.QVBoxLayout()

        if self.issuer:
            self._issuer_lbl = QtWidgets.QLabel(self.issuer)
            labels.addWidget(self._issuer_lbl)

        self._code_lbl = QtWidgets.QLabel()
        labels.addWidget(self._code_lbl)

        self._name_lbl = QtWidgets.QLabel(self.name)
        labels.addWidget(self._name_lbl)

        layout.addLayout(labels)
        layout.addStretch()

        self._calc_btn = QtWidgets.QPushButton(QtGui.QIcon(':/calc.png'), None)
        self._calc_btn.clicked.connect(self._calc)
        layout.addWidget(self._calc_btn)
        self._calc_btn.setVisible(self.entry.manual)

        self._copy_btn = QtWidgets.QPushButton(QtGui.QIcon(':/copy.png'), None)
        self._copy_btn.clicked.connect(self._copy)
        layout.addWidget(self._copy_btn)

        self.timer.time_changed.connect(self._draw)

        self._draw()

    @property
    def expired(self):
        code = self.entry.code
        if code.timestamp - code.ttl > self.timer.time:
            # System time changed? Code isn't valid yet.
            return True
        if code.timestamp + code.ttl <= self.timer.time:
            # Code is past due
            return True
        return False

    def _draw(self):
        if self.expired:
            name_fmt = '<h2 style="color: gray;">%s</h2>'
        else:
            name_fmt = '<h2>%s</h2>'
        code = self.entry.code
        if self.entry.manual and self.entry.cred.oath_type != TYPE_HOTP:
            self._calc_btn.setEnabled(self.expired)
        self._code_lbl.setText(name_fmt % (code.code))
        self._copy_btn.setEnabled(bool(code.code))

    def _copy(self):
        QtCore.QCoreApplication.instance().clipboard().setText(
            self.entry.code.code)

    def _calc(self):
        if self.entry.manual:
            self._calc_btn.setDisabled(True)
        self.entry.calculate()
        if self.entry.cred.oath_type == TYPE_HOTP:
            QtCore.QTimer.singleShot(
                5000, lambda: self._calc_btn.setEnabled(True))

    def _menu(self, pos):
        CodeMenu(self).popup(self.mapToGlobal(pos))

    def _split_issuer_name(self):
        parts = self.entry.cred.name.split(':', 1)
        if len(parts) == 2:
            return parts
        return None, self.entry.cred.name

    def mouseDoubleClickEvent(self, event):
        if event.button() is QtCore.Qt.LeftButton:
            if (not self.entry.code.code or self.expired) and \
                    self.entry.manual:
                def copy_close():
                    self._copy()
                    self.window().close()
                connect_once(self.entry.changed, copy_close)
                self.entry.calculate()
            else:
                self._copy()  # TODO: Type code out with keyboard?
                self.window().close()
        event.accept()


class CodesList(QtWidgets.QWidget):

    def __init__(self, timer, credentials=[], search_filter=None):
        super(CodesList, self).__init__()

        self._codes = []

        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        for cred in credentials:
            if search_filter is not None and \
               search_filter.lower() not in cred.cred.name.lower():
                continue
            code = Code(cred, timer)
            layout.addWidget(code)
            self._codes.append(code)
            line = QtWidgets.QFrame()
            line.setFrameShape(QtWidgets.QFrame.HLine)
            line.setFrameShadow(QtWidgets.QFrame.Sunken)
            layout.addWidget(line)

        if not credentials:
            no_creds = QtWidgets.QLabel(m.no_creds)
            no_creds.setAlignment(QtCore.Qt.AlignCenter)
            layout.addStretch()
            layout.addWidget(no_creds)
            layout.addStretch()

        layout.addStretch()

    def __del__(self):
        for code in self._codes:
            del code.entry
            del code


class CodesWidget(QtWidgets.QWidget):

    def __init__(self, controller):
        super(CodesWidget, self).__init__()

        self._controller = controller
        controller.changed.connect(self.changed)
        controller.refreshed.connect(self.refresh_timer)

        self._filter = None

        self._build_ui()
        self.changed()

    def _build_ui(self):
        layout = QtWidgets.QVBoxLayout(self)

        self._timeleft = TimeleftBar()
        layout.addWidget(self._timeleft)

        self._scroll_area = QtWidgets.QScrollArea()
        self._scroll_area.setFocusPolicy(QtCore.Qt.NoFocus)
        self._scroll_area.setWidgetResizable(True)
        self._scroll_area.setHorizontalScrollBarPolicy(
            QtCore.Qt.ScrollBarAlwaysOff)
        self._scroll_area.setVerticalScrollBarPolicy(
            QtCore.Qt.ScrollBarAsNeeded)
        self._scroll_area.setWidget(QtWidgets.QWidget())
        layout.addWidget(self._scroll_area)

        self._searchbox = SearchBox(self)
        layout.addWidget(self._searchbox)

    def refresh_timer(self, timestamp=None):
        if timestamp is None:
            timestamp = self._controller.timer.time
        if self._controller.has_expiring(timestamp):
            self._timeleft.set_target(timestamp + 30)
        else:
            self._timeleft.set_target(0)

    def rebuild_completions(self):
        creds = self._controller.credentials
        stringlist = set()
        if not creds:
            return
        for cred in creds:
            cred_name = cred.cred.name
            stringlist |= set(cred_name.split(':', 1))
        self._searchbox.set_string_list(list(stringlist))

    def _set_search_filter(self, search_filter):
        if len(search_filter) < 1:
            search_filter = None
        self._filter = search_filter
        self.changed()

    def clear_search_filter(self):
        self._searchbox.clear()

    def changed(self):
        self._scroll_area.takeWidget().deleteLater()
        creds = self._controller.credentials
        self.rebuild_completions()
        self._scroll_area.setWidget(
            CodesList(
                self._controller.timer,
                creds or [],
                self._filter))
        w = self._scroll_area.widget().minimumSizeHint().width()
        w += self._scroll_area.verticalScrollBar().width()
        self._scroll_area.setMinimumWidth(w)
        self.refresh_timer()
