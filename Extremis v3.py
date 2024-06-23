import sys
import os
import json
import base64
import time
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from PyQt5.QtCore import QUrl, Qt, QSize, QTimer, QDir, QStandardPaths, QSettings
from PyQt5.QtWidgets import (QApplication, QMainWindow, QToolBar, QAction, 
                             QLineEdit, QTabWidget, QMessageBox, QMenu,
                             QInputDialog, QVBoxLayout, QWidget, QListWidget,
                             QDialogButtonBox, QFileDialog, QLabel, QStyle,
                             QDialog, QPushButton, QHBoxLayout, QComboBox,
                             QCheckBox, QProgressBar)
from PyQt5.QtWebEngineWidgets import QWebEngineView, QWebEnginePage, QWebEngineProfile, QWebEngineSettings
from PyQt5.QtGui import QIcon, QFont, QPalette, QColor, QDesktopServices
import random
import string

class SecureDataManager:
    def __init__(self):
        self.key = None
        self.fernet = None
        self.settings = QSettings("SecureBrowser", "UserData")
        self.last_activity = time.time()
        self.lock_timeout = 300  # 5 minutes

    def setup(self):
        if not self.settings.value("salt"):
            salt = os.urandom(16)
            self.settings.setValue("salt", base64.b64encode(salt).decode())
        else:
            salt = base64.b64decode(self.settings.value("salt"))

        if not self.settings.value("password_hash"):
            password = self.set_new_password()
        else:
            password = self.get_password()

        self.derive_key(password, salt)

    def set_new_password(self):
        while True:
            password, ok = QInputDialog.getText(None, "Set Master Password", 
                                                "Enter a strong master password (at least 12 characters with a mix of letters, numbers, and symbols):", 
                                                QLineEdit.Password)
            if not ok:
                raise ValueError("Password not set")
            if self.is_strong_password(password):
                confirm_password, ok = QInputDialog.getText(None, "Confirm Master Password", 
                                                            "Confirm your master password:", 
                                                            QLineEdit.Password)
                if password == confirm_password:
                    salt = base64.b64decode(self.settings.value("salt"))
                    self.set_password(password, salt)
                    return password
                else:
                    QMessageBox.warning(None, "Password Mismatch", "The passwords do not match. Please try again.")
            else:
                QMessageBox.warning(None, "Weak Password", "The password is not strong enough. Please try again.")

    def get_password(self):
        salt = base64.b64decode(self.settings.value("salt"))
        while True:
            password, ok = QInputDialog.getText(None, "Enter Master Password", 
                                                "Enter your master password:", 
                                                QLineEdit.Password)
            if not ok:
                raise ValueError("Password not entered")
            if self.verify_password(password, salt):
                return password
            QMessageBox.warning(None, "Incorrect Password", "The password you entered is incorrect. Please try again.")

    def is_strong_password(self, password):
        return (len(password) >= 12 and 
                any(c.islower() for c in password) and
                any(c.isupper() for c in password) and
                any(c.isdigit() for c in password) and
                any(c in string.punctuation for c in password))

    def set_password(self, password, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        password_hash = base64.b64encode(kdf.derive(password.encode())).decode()
        self.settings.setValue("password_hash", password_hash)

    def verify_password(self, password, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        password_hash = base64.b64encode(kdf.derive(password.encode())).decode()
        return password_hash == self.settings.value("password_hash")

    def derive_key(self, password, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        self.key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        self.fernet = Fernet(self.key)

    def encrypt_data(self, data):
        return self.fernet.encrypt(json.dumps(data).encode()).decode()

    def decrypt_data(self, encrypted_data):
        return json.loads(self.fernet.decrypt(encrypted_data.encode()))

    def save_data(self, key, data):
        self.check_and_handle_inactivity()
        encrypted_data = self.encrypt_data(data)
        self.settings.setValue(key, encrypted_data)

    def load_data(self, key, default=None):
        self.check_and_handle_inactivity()
        encrypted_data = self.settings.value(key)
        if encrypted_data:
            return self.decrypt_data(encrypted_data)
        return default

    def check_and_handle_inactivity(self):
        current_time = time.time()
        if current_time - self.last_activity > self.lock_timeout:
            self.lock()
        self.last_activity = current_time

    def lock(self):
        self.key = None
        self.fernet = None

    def unlock(self):
        if not self.fernet:
            password = self.get_password()
            salt = base64.b64decode(self.settings.value("salt"))
            self.derive_key(password, salt)

class PasswordManager:
    def __init__(self, secure_data_manager):
        self.secure_data_manager = secure_data_manager

    def save_password(self, url, username, password):
        passwords = self.secure_data_manager.load_data("passwords", {})
        passwords[url] = {"username": username, "password": password}
        self.secure_data_manager.save_data("passwords", passwords)

    def get_password(self, url):
        passwords = self.secure_data_manager.load_data("passwords", {})
        return passwords.get(url)

    def prompt_save_password(self, url, username, password):
        reply = QMessageBox.question(None, "Save Password", 
                                     f"Do you want to save the password for {url}?",
                                     QMessageBox.Yes | QMessageBox.No)
        if reply == QMessageBox.Yes:
            self.save_password(url, username, password)

    def generate_password(self, length=16):
        characters = string.ascii_letters + string.digits + string.punctuation
        return ''.join(random.choice(characters) for i in range(length))

class SecureWebPage(QWebEnginePage):
    def __init__(self, profile, parent=None):
        super().__init__(profile, parent)
        self.featurePermissionRequested.connect(self.handlePermissionRequest)
        
        # Enable HSTS
        self.settings().setAttribute(QWebEngineSettings.LocalStorageEnabled, True)
        
        # Set Content Security Policy
        self.setFeaturePermission(QUrl(), QWebEnginePage.Notifications, QWebEnginePage.PermissionDeniedByUser)
        
    def certificateError(self, error):
        return False  # Reject all invalid certificates

    def handlePermissionRequest(self, url, feature):
        if feature in [QWebEnginePage.Geolocation, QWebEnginePage.MediaAudioCapture, 
                       QWebEnginePage.MediaVideoCapture, QWebEnginePage.MediaAudioVideoCapture]:
            reply = QMessageBox.question(None, "Permission Request",
                                         f"Allow {url.host()} to access {feature.name}?",
                                         QMessageBox.Yes | QMessageBox.No)
            if reply == QMessageBox.Yes:
                self.setFeaturePermission(url, feature, QWebEnginePage.PermissionGrantedByUser)
            else:
                self.setFeaturePermission(url, feature, QWebEnginePage.PermissionDeniedByUser)

class SecureBrowser(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Secure Professional Web Browser")
        self.setGeometry(100, 100, 1280, 800)

        self.secure_data_manager = SecureDataManager()
        try:
            self.secure_data_manager.setup()
        except ValueError as e:
            QMessageBox.critical(self, "Error", str(e))
            sys.exit(1)

        self.password_manager = PasswordManager(self.secure_data_manager)

        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)
        self.tabs.setTabsClosable(True)
        self.tabs.tabCloseRequested.connect(self.closeTab)
        self.setCentralWidget(self.tabs)

        self.profile = QWebEngineProfile.defaultProfile()
        self.privateProfile = QWebEngineProfile()

        # Enable HSTS globally
        self.profile.settings().setAttribute(QWebEngineSettings.LocalStorageEnabled, True)
        self.privateProfile.settings().setAttribute(QWebEngineSettings.LocalStorageEnabled, True)

        # Load saved data
        self.bookmarks = self.secure_data_manager.load_data("bookmarks", [])
        self.history = self.secure_data_manager.load_data("history", [])
        self.downloads = self.secure_data_manager.load_data("downloads", [])

        self.setupUI()
        self.isDarkMode = False
        self.applyStyles()

        # Auto-save session every 5 minutes
        self.autoSaveTimer = QTimer(self)
        self.autoSaveTimer.timeout.connect(self.saveSession)
        self.autoSaveTimer.start(300000)

        # Check for inactivity every minute
        self.inactivityTimer = QTimer(self)
        self.inactivityTimer.timeout.connect(self.check_inactivity)
        self.inactivityTimer.start(60000)

    def setupUI(self):
        self.createActions()
        self.createMenuBar()
        self.createToolBar()
        self.addNewTab()

        self.profile.downloadRequested.connect(self.handleDownload)

    def createActions(self):
        style = self.style()
        
        self.newTabAction = QAction(style.standardIcon(QStyle.SP_FileIcon), "New Tab", self)
        self.newTabAction.setShortcut("Ctrl+T")
        self.newTabAction.triggered.connect(self.addNewTab)

        self.newWindowAction = QAction(style.standardIcon(QStyle.SP_TitleBarNormalButton), "New Window", self)
        self.newWindowAction.setShortcut("Ctrl+N")
        self.newWindowAction.triggered.connect(self.newWindow)

        self.privateWindowAction = QAction(style.standardIcon(QStyle.SP_DriveHDIcon), "New Private Window", self)
        self.privateWindowAction.setShortcut("Ctrl+Shift+N")
        self.privateWindowAction.triggered.connect(self.newPrivateWindow)

        self.bookmarkAction = QAction(style.standardIcon(QStyle.SP_ArrowUp), "Bookmark", self)
        self.bookmarkAction.setShortcut("Ctrl+D")
        self.bookmarkAction.triggered.connect(self.addBookmark)

        self.findAction = QAction(style.standardIcon(QStyle.SP_FileDialogContentsView), "Find", self)
        self.findAction.setShortcut("Ctrl+F")
        self.findAction.triggered.connect(self.findInPage)

        self.historyAction = QAction(style.standardIcon(QStyle.SP_BrowserReload), "History", self)
        self.historyAction.triggered.connect(self.showHistory)

        self.downloadsAction = QAction(style.standardIcon(QStyle.SP_ArrowDown), "Downloads", self)
        self.downloadsAction.triggered.connect(self.showDownloads)

        self.darkModeAction = QAction("Dark Mode", self, checkable=True)
        self.darkModeAction.triggered.connect(self.toggleDarkMode)

        self.changePasswordAction = QAction("Change Master Password", self)
        self.changePasswordAction.triggered.connect(self.changeMasterPassword)

        self.generatePasswordAction = QAction("Generate Secure Password", self)
        self.generatePasswordAction.triggered.connect(self.generateSecurePassword)

    def createMenuBar(self):
        menuBar = self.menuBar()

        fileMenu = menuBar.addMenu("&File")
        fileMenu.addAction(self.newTabAction)
        fileMenu.addAction(self.newWindowAction)
        fileMenu.addAction(self.privateWindowAction)
        fileMenu.addSeparator()
        fileMenu.addAction(QAction("Exit", self, triggered=self.close))

        editMenu = menuBar.addMenu("&Edit")
        editMenu.addAction(self.findAction)

        viewMenu = menuBar.addMenu("&View")
        viewMenu.addAction(self.darkModeAction)

        bookmarksMenu = menuBar.addMenu("&Bookmarks")
        bookmarksMenu.addAction(self.bookmarkAction)
        bookmarksMenu.addSeparator()
        bookmarksMenu.addAction(QAction("Show Bookmarks", self, triggered=self.showBookmarks))

        historyMenu = menuBar.addMenu("&History")
        historyMenu.addAction(self.historyAction)

        downloadsMenu = menuBar.addMenu("&Downloads")
        downloadsMenu.addAction(self.downloadsAction)

        securityMenu = menuBar.addMenu("&Security")
        securityMenu.addAction(self.changePasswordAction)
        securityMenu.addAction(self.generatePasswordAction)

    def createToolBar(self):
        style = self.style()
        
        navtb = QToolBar("Navigation")
        navtb.setIconSize(QSize(16,16))
        self.addToolBar(navtb)

        backBtn = QAction(style.standardIcon(QStyle.SP_ArrowBack), "Back", self)
        backBtn.setStatusTip("Back to previous page")
        backBtn.triggered.connect(lambda: self.tabs.currentWidget().back())
        navtb.addAction(backBtn)

        nextBtn = QAction(style.standardIcon(QStyle.SP_ArrowForward), "Forward", self)
        nextBtn.setStatusTip("Forward to next page")
        nextBtn.triggered.connect(lambda: self.tabs.currentWidget().forward())
        navtb.addAction(nextBtn)

        reloadBtn = QAction(style.standardIcon(QStyle.SP_BrowserReload), "Reload", self)
        reloadBtn = QAction(style.standardIcon(QStyle.SP_BrowserReload), "Reload", self)
        reloadBtn.setStatusTip("Reload page")
        reloadBtn.triggered.connect(lambda: self.tabs.currentWidget().reload())
        navtb.addAction(reloadBtn)

        homeBtn = QAction(style.standardIcon(QStyle.SP_DirHomeIcon), "Home", self)
        homeBtn.setStatusTip("Go home")
        homeBtn.triggered.connect(self.navigateHome)
        navtb.addAction(homeBtn)

        navtb.addSeparator()

        self.httpsIcon = QLabel()
        self.httpsIcon.setPixmap(style.standardIcon(QStyle.SP_MessageBoxInformation).pixmap(16,16))
        navtb.addWidget(self.httpsIcon)

        self.urlBar = QLineEdit()
        self.urlBar.returnPressed.connect(self.navigateToUrl)
        navtb.addWidget(self.urlBar)

        stopBtn = QAction(style.standardIcon(QStyle.SP_BrowserStop), "Stop", self)
        stopBtn.setStatusTip("Stop loading current page")
        stopBtn.triggered.connect(lambda: self.tabs.currentWidget().stop())
        navtb.addAction(stopBtn)

    def addNewTab(self, qurl=QUrl("https://www.google.com"), label="New Tab"):
        browser = QWebEngineView()
        page = SecureWebPage(self.profile, browser)
        browser.setPage(page)
        
        # Validate and sanitize URL
        sanitized_url = self.sanitize_url(qurl)
        browser.setUrl(sanitized_url)

        i = self.tabs.addTab(browser, label)
        self.tabs.setCurrentIndex(i)

        browser.urlChanged.connect(lambda qurl, browser=browser:
                                   self.updateUrlBar(qurl, browser))
        browser.loadFinished.connect(lambda _, i=i, browser=browser:
                                     self.tabs.setTabText(i, browser.page().title()))
        browser.loadFinished.connect(self.updateHistory)
        browser.loadFinished.connect(lambda: self.check_for_password(browser))

    def check_for_password(self, browser):
        url = browser.url().toString()
        saved_password = self.password_manager.get_password(url)
        if saved_password:
            username = saved_password['username']
            password = saved_password['password']
            browser.page().runJavaScript(f"""
                (function() {{
                    var usernameField = document.querySelector('input[type="text"], input[type="email"], input[name="username"]');
                    var passwordField = document.querySelector('input[type="password"]');
                    if (usernameField && passwordField) {{
                        usernameField.value = "{username}";
                        passwordField.value = "{password}";
                    }}
                }})();
            """)
        else:
            browser.page().runJavaScript("""
                (function() {
                    var forms = document.getElementsByTagName('form');
                    for (var i = 0; i < forms.length; i++) {
                        forms[i].addEventListener('submit', function(e) {
                            e.preventDefault();
                            var usernameField = this.querySelector('input[type="text"], input[type="email"], input[name="username"]');
                            var passwordField = this.querySelector('input[type="password"]');
                            if (usernameField && passwordField) {
                                window.promptSavePassword = true;
                                window.username = usernameField.value;
                                window.password = passwordField.value;
                            }
                            this.submit();
                        });
                    }
                })();
            """)

    def closeTab(self, i):
        if self.tabs.count() < 2:
            return
        self.tabs.removeTab(i)

    def newWindow(self):
        window = SecureBrowser()
        window.show()

    def newPrivateWindow(self):
        window = SecureBrowser()
        window.profile = window.privateProfile
        window.show()

    def navigateHome(self):
        self.tabs.currentWidget().setUrl(QUrl("https://www.google.com"))

    def sanitize_url(self, url):
        if isinstance(url, str):
            url = QUrl(url)
        if not url.isValid() or url.scheme() == "":
            url.setScheme("https")
        return url

    def navigateToUrl(self):
        q = QUrl(self.urlBar.text())
        if q.scheme() == "":
            q.setScheme("https")
        self.tabs.currentWidget().setUrl(q)

    def updateUrlBar(self, q, browser=None):
        if browser != self.tabs.currentWidget():
            return
        if q.scheme() == 'https':
            self.httpsIcon.setPixmap(self.style().standardIcon(QStyle.SP_MessageBoxInformation).pixmap(16,16))
        else:
            self.httpsIcon.setPixmap(self.style().standardIcon(QStyle.SP_MessageBoxWarning).pixmap(16,16))
        self.urlBar.setText(q.toString())
        self.urlBar.setCursorPosition(0)

    def updateHistory(self):
        url = self.tabs.currentWidget().url().toString()
        title = self.tabs.currentWidget().page().title()
        self.history.append((title, url))
        # Limit history to last 1000 entries
        self.history = self.history[-1000:]
        
        # Check if we should prompt to save password
        self.tabs.currentWidget().page().runJavaScript("""
            (function() {
                if (window.promptSavePassword) {
                    window.promptSavePassword = false;
                    return [true, window.username || '', window.password || ''];
                }
                return [false, '', ''];
            })();
        """, self.handle_save_password_result)

    def handle_save_password_result(self, result):
        if result and isinstance(result, list) and len(result) == 3:
            if result[0] and result[1] and result[2]:
                url = self.tabs.currentWidget().url().toString()
                self.password_manager.prompt_save_password(url, result[1], result[2])

    def addBookmark(self):
        url = self.tabs.currentWidget().url().toString()
        title = self.tabs.currentWidget().page().title()
        bookmark, ok = QInputDialog.getText(self, "Add Bookmark", 
                                            "Enter bookmark name:", 
                                            text=title)
        if ok and bookmark:
            self.bookmarks.append((bookmark, url))
            self.secure_data_manager.save_data("bookmarks", self.bookmarks)

    def showBookmarks(self):
        bookmarksDialog = QDialog(self)
        bookmarksDialog.setWindowTitle("Bookmarks")
        layout = QVBoxLayout()

        bookmarksList = QListWidget()
        for name, url in self.bookmarks:
            bookmarksList.addItem(f"{name} ({url})")

        bookmarksList.itemDoubleClicked.connect(lambda item: self.loadBookmark(item.text()))

        layout.addWidget(bookmarksList)
        bookmarksDialog.setLayout(layout)
        bookmarksDialog.resize(400, 300)
        bookmarksDialog.exec_()

    def loadBookmark(self, bookmark_text):
        url = bookmark_text.split('(')[-1][:-1]  # Extract URL from the bookmark text
        self.addNewTab(QUrl(url))

    def findInPage(self):
        findDialog = QDialog(self)
        findDialog.setWindowTitle("Find in Page")
        layout = QVBoxLayout()

        findInput = QLineEdit()
        findInput.setPlaceholderText("Enter search term")
        layout.addWidget(findInput)

        findNextBtn = QPushButton("Find Next")
        findPrevBtn = QPushButton("Find Previous")
        buttonLayout = QHBoxLayout()
        buttonLayout.addWidget(findNextBtn)
        buttonLayout.addWidget(findPrevBtn)
        layout.addLayout(buttonLayout)

        findNextBtn.clicked.connect(lambda: self.tabs.currentWidget().findText(findInput.text()))
        findPrevBtn.clicked.connect(lambda: self.tabs.currentWidget().findText(findInput.text(), QWebEnginePage.FindBackward))

        findDialog.setLayout(layout)
        findDialog.exec_()

    def showHistory(self):
        historyDialog = QDialog(self)
        historyDialog.setWindowTitle("History")
        layout = QVBoxLayout()

        historyList = QListWidget()
        for title, url in reversed(self.history):  # Show most recent first
            historyList.addItem(f"{title} ({url})")

        historyList.itemDoubleClicked.connect(lambda item: self.loadHistoryItem(item.text()))

        layout.addWidget(historyList)
        
        clearHistoryBtn = QPushButton("Clear History")
        clearHistoryBtn.clicked.connect(self.clearHistory)
        layout.addWidget(clearHistoryBtn)

        historyDialog.setLayout(layout)
        historyDialog.resize(500, 400)
        historyDialog.exec_()

    def loadHistoryItem(self, history_text):
        url = history_text.split('(')[-1][:-1]  # Extract URL from the history text
        self.addNewTab(QUrl(url))

    def clearHistory(self):
        reply = QMessageBox.question(self, 'Clear History',
                                     "Are you sure you want to clear all browsing history?",
                                     QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.Yes:
            self.history.clear()
            self.secure_data_manager.save_data("history", self.history)
            QMessageBox.information(self, "History Cleared", "Your browsing history has been cleared.")

    def handleDownload(self, download):
        defaultPath = os.path.join(QDir.homePath(), download.suggestedFileName())
        path, _ = QFileDialog.getSaveFileName(self, "Save File", defaultPath)
        
        if path:
            # Validate file path
            if os.path.commonprefix([os.path.realpath(path), QDir.homePath()]) != QDir.homePath():
                QMessageBox.warning(self, "Security Warning", "Cannot save files outside the home directory.")
                return
            
            download.setPath(path)
            download.accept()
            self.downloads.append((download.suggestedFileName(), path))
            self.secure_data_manager.save_data("downloads", self.downloads)
            download.finished.connect(self.onDownloadFinished)

    def onDownloadFinished(self):
        QMessageBox.information(self, "Download Complete", "The file has been downloaded successfully.")

    def showDownloads(self):
        downloadsDialog = QDialog(self)
        downloadsDialog.setWindowTitle("Downloads")
        layout = QVBoxLayout()

        downloadsList = QListWidget()
        for filename, path in self.downloads:
            downloadsList.addItem(f"{filename} -> {path}")

        downloadsList.itemDoubleClicked.connect(lambda item: self.openDownloadedFile(item.text()))

        layout.addWidget(downloadsList)

        openFolderBtn = QPushButton("Open Downloads Folder")
        openFolderBtn.clicked.connect(self.openDownloadsFolder)
        layout.addWidget(openFolderBtn)

        downloadsDialog.setLayout(layout)
        downloadsDialog.resize(500, 400)
        downloadsDialog.exec_()

    def openDownloadedFile(self, download_text):
        path = download_text.split(' -> ')[-1]
        QDesktopServices.openUrl(QUrl.fromLocalFile(path))

    def openDownloadsFolder(self):
        downloads_path = QStandardPaths.writableLocation(QStandardPaths.DownloadLocation)
        QDesktopServices.openUrl(QUrl.fromLocalFile(downloads_path))

    def saveSession(self):
        session = []
        for i in range(self.tabs.count()):
            browser = self.tabs.widget(i)
            session.append(browser.url().toString())
        self.secure_data_manager.save_data("session", session)
        self.statusBar().showMessage("Session saved", 2000)

    def loadSession(self):
        session = self.secure_data_manager.load_data("session", [])
        self.bookmarks = self.secure_data_manager.load_data("bookmarks", [])
        self.history = self.secure_data_manager.load_data("history", [])
        self.downloads = self.secure_data_manager.load_data("downloads", [])

        if session:
            for url in session:
                self.addNewTab(QUrl(url))
            self.tabs.removeTab(0)  # Remove the initial blank tab
        else:
            self.addNewTab()

    def toggleDarkMode(self):
        self.isDarkMode = not self.isDarkMode
        self.applyStyles()

    def applyStyles(self):
        if self.isDarkMode:
            self.setStyleSheet("""
                QMainWindow, QWidget {
                    background-color: #2b2b2b;
                    color: #ffffff;
                }
                QTabWidget::pane {
                    border: 1px solid #555555;
                    background: #2b2b2b;
                }
                QTabBar::tab {
                    background: #3b3b3b;
                    border: 1px solid #555555;
                    border-bottom-color: #555555;
                    color: #ffffff;
                }
                QTabBar::tab:selected, QTabBar::tab:hover {
                    background: #4b4b4b;
                }
                QLineEdit {
                    border: 1px solid #555555;
                    background: #3b3b3b;
                    color: #ffffff;
                }
                QToolBar {
                    background: #3b3b3b;
                    border: 1px solid #555555;
                }
                QToolButton {
                    background-color: #3b3b3b;
                    color: #ffffff;
                }
                QToolButton:hover {
                    background-color: #4b4b4b;
                }
                QMenu {
                    background-color: #2b2b2b;
                    border: 1px solid #555555;
                }
                QMenu::item {
                    color: #ffffff;
                }
                QMenu::item:selected {
                    background-color: #4b4b4b;
                }
            """)
        else:
            self.setStyleSheet("""
                QMainWindow {
                    background-color: #f0f0f0;
                }
                QTabWidget::pane {
                    border: 1px solid #cccccc;
                    background: white;
                }
                QTabBar::tab {
                    background: #e0e0e0;
                    border: 1px solid #cccccc;
                    border-bottom-color: #cccccc;
                }
                QTabBar::tab:selected, QTabBar::tab:hover {
                    background: white;
                }
                QLineEdit {
                    border: 1px solid #cccccc;
                    background: white;
                }
                QToolBar {
                    background: white;
                    border: 1px solid #cccccc;
                }
                QToolButton:hover {
                    background-color: #e0e0e0;
                }
                QMenu {
                    background-color: white;
                    border: 1px solid #cccccc;
                }
                QMenu::item:selected {
                    background-color: #e0e0e0;
                }
            """)               
    def changeMasterPassword(self):
        old_password, ok = QInputDialog.getText(self, "Change Master Password", 
                                                "Enter your current master password:", 
                                                QLineEdit.Password)
        if ok:
            salt = base64.b64decode(self.secure_data_manager.settings.value("salt"))
            if self.secure_data_manager.verify_password(old_password, salt):
                new_password = self.secure_data_manager.set_new_password()
                if new_password:
                    self.secure_data_manager.derive_key(new_password, salt)
                    QMessageBox.information(self, "Password Changed", "Your master password has been successfully changed.")
            else:
                QMessageBox.warning(self, "Incorrect Password", "The current password you entered is incorrect.")

    def generateSecurePassword(self):
        length, ok = QInputDialog.getInt(self, "Generate Secure Password", 
                                         "Enter the desired password length:", 16, 12, 32)
        if ok:
            password = self.password_manager.generate_password(length)
            dialog = QDialog(self)
            dialog.setWindowTitle("Generated Password")
            layout = QVBoxLayout()
            
            password_display = QLineEdit(password)
            password_display.setReadOnly(True)
            layout.addWidget(password_display)
            
            copy_button = QPushButton("Copy to Clipboard")
            copy_button.clicked.connect(lambda: QApplication.clipboard().setText(password))
            layout.addWidget(copy_button)
            
            dialog.setLayout(layout)
            dialog.exec_()

    def check_inactivity(self):
        self.secure_data_manager.check_and_handle_inactivity()
        if not self.secure_data_manager.fernet:
            self.lock_browser()

    def lock_browser(self):
        for i in range(self.tabs.count()):
            self.tabs.widget(i).setUrl(QUrl("about:blank"))
        self.urlBar.clear()
        QMessageBox.information(self, "Browser Locked", "The browser has been locked due to inactivity. Please enter your master password to unlock.")
        self.unlock_browser()

    def unlock_browser(self):
        try:
            self.secure_data_manager.unlock()
            self.loadSession()
        except ValueError:
            QMessageBox.critical(self, "Unlock Failed", "Failed to unlock the browser. The application will now close.")
            self.close()

    def closeEvent(self, event):
        self.saveSession()
        self.secure_data_manager.save_data("bookmarks", self.bookmarks)
        self.secure_data_manager.save_data("history", self.history)
        self.secure_data_manager.save_data("downloads", self.downloads)
        self.statusBar().showMessage("All data saved", 2000)
        super().closeEvent(event)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    
    # Set application-wide attributes
    app.setApplicationName("Secure Professional Web Browser")
    app.setApplicationVersion("1.0")
    
    # Create and show the main window
    main_window = SecureBrowser()
    main_window.show()
    
    # Set up an exception hook to handle any uncaught exceptions
    def exception_hook(exctype, value, traceback):
        print(exctype, value, traceback)
        sys.__excepthook__(exctype, value, traceback)
    sys.excepthook = exception_hook
    
    # Start the event loop
    sys.exit(app.exec_())            