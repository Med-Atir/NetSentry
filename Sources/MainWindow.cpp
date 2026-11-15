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
    ui->contenu->setCurrentIndex(0);
}

MainWindow::~MainWindow() {
    delete ui;
}

void MainWindow::showHomePage() {
    ui->contenu->setCurrentIndex(0);
}

void MainWindow::showLiveCapturePage() {
    ui->contenu->setCurrentIndex(1);
}

void MainWindow::showFileCapturePage() {
    ui->contenu->setCurrentIndex(2);
}

void MainWindow::showAlertsPage() {
    ui->contenu->setCurrentIndex(3);
    database.getAlerts(200);
}

void MainWindow::handleClearDatabase() {
    database.clearAlerts();
}