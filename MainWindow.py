from PyQt5 import QtCore, QtWidgets

class MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(800, 600)
        MainWindow.setMinimumSize(400, 300)  # Minimum size set to 400x300
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.horizontalLayout_3 = QtWidgets.QHBoxLayout(self.centralwidget)
        self.horizontalLayout_3.setObjectName("horizontalLayout_3")
        self.verticalLayout = QtWidgets.QVBoxLayout()
        self.verticalLayout.setObjectName("verticalLayout")
        self.horizontalLayout_2 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_2.setObjectName("horizontalLayout_2")
        self.start_btn = QtWidgets.QPushButton(self.centralwidget)
        self.start_btn.setObjectName("start_btn")
        self.horizontalLayout_2.addWidget(self.start_btn)
        self.stop_btn = QtWidgets.QPushButton(self.centralwidget)
        self.stop_btn.setObjectName("stop_btn")
        self.horizontalLayout_2.addWidget(self.stop_btn)
        self.verticalLayout.addLayout(self.horizontalLayout_2)
        self.horizontalLayout_4 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_4.setObjectName("horizontalLayout_4")
        self.Filter = QtWidgets.QLabel(self.centralwidget)
        self.Filter.setObjectName("Filter")
        self.horizontalLayout_4.addWidget(self.Filter)
        self.lineEdit = QtWidgets.QLineEdit(self.centralwidget)
        self.lineEdit.setObjectName("lineEdit")
        self.horizontalLayout_4.addWidget(self.lineEdit)
        self.filter_btn = QtWidgets.QPushButton(self.centralwidget)
        self.filter_btn.setObjectName("filter_btn")
        self.horizontalLayout_4.addWidget(self.filter_btn)
        self.verticalLayout.addLayout(self.horizontalLayout_4)
        self.ListView = QtWidgets.QTreeWidget(self.centralwidget)
        self.ListView.setObjectName("ListView")

        # Set header labels with spaces
        header_labels = ["ID", "   Time", "   Source", "   Destination", "   Protocol", "   Length", "   Info"]
        self.ListView.setHeaderLabels(header_labels)

        # Set the size policy to expanding for both horizontal and vertical directions
        size_policy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Expanding)
        self.ListView.setSizePolicy(size_policy)

        # Set section resize mode to adjust based on content
        self.ListView.header().setSectionResizeMode(QtWidgets.QHeaderView.ResizeToContents)

        self.verticalLayout.addWidget(self.ListView)
        self.DetailView = QtWidgets.QTreeWidget(self.centralwidget)
        self.DetailView.setColumnCount(0)
        self.DetailView.setObjectName("DetailView")
        self.verticalLayout.addWidget(self.DetailView)
        self.HexView = QtWidgets.QTextEdit(self.centralwidget)
        self.HexView.setReadOnly(True)
        self.HexView.setObjectName("HexView")
        self.verticalLayout.addWidget(self.HexView)
        self.horizontalLayout_3.addLayout(self.verticalLayout)
        MainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(MainWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 762, 21))
        self.menubar.setObjectName("menubar")
        self.menuFile = QtWidgets.QMenu(self.menubar)
        self.menuFile.setObjectName("menuFile")
        self.menuView = QtWidgets.QMenu(self.menubar)
        self.menuView.setObjectName("menuView")
        MainWindow.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(MainWindow)
        self.statusbar.setObjectName("statusbar")
        MainWindow.setStatusBar(self.statusbar)
        self.toolBar = QtWidgets.QToolBar(MainWindow)
        self.toolBar.setObjectName("toolBar")
        MainWindow.addToolBar(QtCore.Qt.TopToolBarArea, self.toolBar)
        self.actionNew = QtWidgets.QAction(MainWindow)
        self.actionNew.setObjectName("actionNew")
        self.actionExit = QtWidgets.QAction(MainWindow)
        self.actionExit.setObjectName("actionExit")
        self.actionOpen = QtWidgets.QAction(MainWindow)
        self.actionOpen.setObjectName("actionOpen")
        self.actionSave = QtWidgets.QAction(MainWindow)
        self.actionSave.setObjectName("actionSave")
        self.actionToggle_FullScreen = QtWidgets.QAction(MainWindow)
        self.actionToggle_FullScreen.setObjectName("actionToggle_FullScreen")
        self.menuFile.addAction(self.actionNew)
        self.menuFile.addSeparator()
        self.menuFile.addAction(self.actionOpen)
        self.menuFile.addAction(self.actionSave)
        self.menuFile.addSeparator()
        self.menuFile.addAction(self.actionExit)
        self.menuView.addAction(self.actionToggle_FullScreen)
        self.menubar.addAction(self.menuFile.menuAction())
        self.menubar.addAction(self.menuView.menuAction())

        self.retranslateUi(MainWindow)
        self.actionExit.triggered.connect(MainWindow.close)

        # Connect the resize event to the function that adjusts column widths
        MainWindow.resizeEvent = lambda event: self.adjustColumnWidths()

        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "MainWindow"))
        self.start_btn.setText(_translate("MainWindow", "Start"))
        self.stop_btn.setText(_translate("MainWindow", "Stop"))
        self.Filter.setText(_translate("MainWindow", "Filter"))
        self.filter_btn.setText(_translate("MainWindow", "Go"))
        self.ListView.headerItem().setText(0, _translate("MainWindow", "ID"))
        self.ListView.headerItem().setText(1, _translate("MainWindow", "   Time"))
        self.ListView.headerItem().setText(2, _translate("MainWindow", "   Source"))
        self.ListView.headerItem().setText(3, _translate("MainWindow", "   Destination"))
        self.ListView.headerItem().setText(4, _translate("MainWindow", "   Protocol"))
        self.ListView.headerItem().setText(5, _translate("MainWindow", "   Length"))
        self.ListView.headerItem().setText(6, _translate("MainWindow", "   Info"))
        self.menuFile.setTitle(_translate("MainWindow", "File"))
        self.menuView.setTitle(_translate("MainWindow", "View"))
        self.toolBar.setWindowTitle(_translate("MainWindow", "toolBar"))
        self.actionNew.setText(_translate("MainWindow", " New Session"))
        self.actionExit.setText(_translate("MainWindow", "Exit"))
        self.actionOpen.setText(_translate("MainWindow", "Open"))
        self.actionSave.setText(_translate("MainWindow", "Save"))
        self.actionToggle_FullScreen.setText(_translate("MainWindow", "Toggle_FullScreen"))

    def adjustColumnWidths(self):
        # Adjust column widths based on the current window size
        column_count = self.ListView.header().count()
        available_width = self.ListView.width() - 2  # Adjust for borders

        # Distribute the available width equally among columns
        column_width = available_width // column_count

        for i in range(column_count):
            self.ListView.setColumnWidth(i, column_width)


if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QMainWindow()
    ui = MainWindow()
    ui.setupUi(MainWindow)
    MainWindow.show()
    sys.exit(app.exec_())
