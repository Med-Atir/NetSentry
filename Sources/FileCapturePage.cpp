//
// Created by mohammed on 15/11/2026.
//
#include "Headers/FileCapturePage.h"
#include "Headers/FileCapturePage.h"
#include "GUI/ui_file_capture.h"

#include <QDateTime>
#include <QFileDialog>
#include <QHeaderView>
#include <QTableWidgetItem>

FileCapturePage::FileCapturePage(QWidget *parent)
    : QWidget(parent), ui(new Ui::FileForm) {
    ui->setupUi(this);

    ui->stopcap->setEnabled(false);
    ui->startcap->setEnabled(false);
    ui->tableAlerts->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);

    connect(ui->browse, &QPushButton::clicked, this, &FileCapturePage::onBrowseClicked);
    connect(ui->startcap, &QPushButton::clicked, this, &FileCapturePage::onStartClicked);
    connect(ui->stopcap, &QPushButton::clicked, this, &FileCapturePage::onStopClicked);
}

FileCapturePage::~FileCapturePage() {
    delete ui;
}

void FileCapturePage::onBrowseClicked() {
    const QString path = QFileDialog::getOpenFileName(
        this,
        tr("Select PCAP File"),
        QString(),
        tr("PCAP Files (*.pcap *.pcapng);;All Files (*)"));

    if (!path.isEmpty()) {
        selectedFilePath = path;
        ui->startcap->setEnabled(true);
    }
}

void FileCapturePage::onStartClicked() {
    if (selectedFilePath.isEmpty()) {
        return;
    }
    ui->tableAlerts->setRowCount(0);
    updateCounters(0, 0, 0);
    setCapturingState(true);
    emit startFileRequested(selectedFilePath);
}

void FileCapturePage::onStopClicked() {
    setCapturingState(false);
    emit stopFileRequested();
}

void FileCapturePage::setCapturingState(bool running) {
    ui->browse->setEnabled(!running);
    ui->startcap->setEnabled(!running && !selectedFilePath.isEmpty());
    ui->stopcap->setEnabled(running);
}

void FileCapturePage::updateCounters(uint64_t packets, uint64_t activeFlows, uint64_t sessionAlerts) {
    ui->packets->setText(QString::number(packets));
    ui->flows->setText(QString::number(activeFlows));
    ui->alerts->setText(QString::number(sessionAlerts));
}

void FileCapturePage::appendAlert(const AlertEvent &alert) {
    const int row = ui->tableAlerts->rowCount();
    ui->tableAlerts->insertRow(row);

    const QString timeStr = QDateTime::fromMSecsSinceEpoch(
        static_cast<qint64>(alert.get_timestamp_us() / 1000))
        .toString("yyyy-MM-dd HH:mm:ss");

    ui->tableAlerts->setItem(row, 0, new QTableWidgetItem(timeStr));
    ui->tableAlerts->setItem(row, 1, new QTableWidgetItem(QString::fromStdString(alert.get_src_ip())));
    ui->tableAlerts->setItem(row, 2, new QTableWidgetItem(QString::fromStdString(alert.get_dst_ip())));
    ui->tableAlerts->setItem(row, 3, new QTableWidgetItem(QString::number(alert.get_src_port())));
    ui->tableAlerts->setItem(row, 4, new QTableWidgetItem(QString::number(alert.get_dst_port())));
    ui->tableAlerts->setItem(row, 5, new QTableWidgetItem(QString::number(alert.get_protocol())));
    ui->tableAlerts->setItem(row, 6, new QTableWidgetItem(QString::fromStdString(alert.get_attack_type())));
    ui->tableAlerts->setItem(row, 7, new QTableWidgetItem(QString::number(alert.get_confidence(), 'f', 2)));
    ui->tableAlerts->setItem(row, 8, new QTableWidgetItem(QString::fromStdString(severity_to_string(alert.get_severity()))));

    ui->tableAlerts->scrollToBottom();
}