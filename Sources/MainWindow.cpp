//
// Created by mohammed on 15/11/2026.
//


#include "Headers/MainWindow.h"
#include "GUI/ui_mainWindow.h"
#include "Headers/AlertPage.h"

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent), ui(new Ui::MainWindow) {
    ui->setupUi(this);

    database.connect("netsentry.db");

    // Sidebar navigation
    connect(ui->home_2, &QPushButton::clicked, this, &MainWindow::showHomePage);
    connect(ui->live_capture, &QPushButton::clicked, this, &MainWindow::showLiveCapturePage);
    connect(ui->file_capture, &QPushButton::clicked, this, &MainWindow::showFileCapturePage);
    connect(ui->alerts, &QPushButton::clicked, this, &MainWindow::showAlertsPage);

    connect(ui->pageAlerts, &AlertsPage::clearAlertsRequested, this, &MainWindow::handleClearDatabase);

    ui->home_2->setChecked(true);
    ui->contenu->setCurrentWidget(ui->pageHome);
}

MainWindow::~MainWindow() {
    delete ui;
}

void MainWindow::showHomePage() {
    ui->contenu->setCurrentWidget(ui->pageHome);
}

void MainWindow::showLiveCapturePage() {
    ui->contenu->setCurrentWidget(ui->pageLive);
}
void MainWindow::setController(Controller *ctrl) {
    ui->pageLive->setController(ctrl);
    ui->pageFile->setController(ctrl);
    ui->pageAlerts->setController(ctrl);
}

void MainWindow::showFileCapturePage() {
    ui->contenu->setCurrentWidget(ui->pageFile);
}

void MainWindow::showAlertsPage() {
    ui->contenu->setCurrentWidget(ui->pageAlerts);
    database.getAlerts(200);
}

void MainWindow::handleClearDatabase() {
    database.clearAlerts();
}