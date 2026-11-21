//
// Created by mohammed on 15/11/2026.
//

#include "Headers/AlertPage.h"
#include "GUI/ui_alerts.h"

#include <QDateTime>
#include <QHeaderView>
#include <QTableWidgetItem>

AlertsPage::AlertsPage(QWidget *parent)
    : QWidget(parent), ui(new Ui::AlertForm) {
    ui->setupUi(this);

    ui->tableAlerts->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);

    connect(ui->clear, &QPushButton::clicked, this, &AlertsPage::onClearClicked);
}

AlertsPage::~AlertsPage() {
    delete ui;
}

void AlertsPage::loadAlerts() {
    ui->tableAlerts->setRowCount(0);
    std::vector<AlertEvent> alerts = this->controller->getAlerts();
    for (const auto &alert : alerts) {
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
    }
}

void AlertsPage::onClearClicked() {
    if (!controller) return;
    if (controller->clearAlertsDB()) {
        ui->tableAlerts->setRowCount(0);
    }
}
void AlertsPage::setController(Controller* ctrl) {
    if (!ctrl) return;
    this->controller = ctrl;
    loadAlerts();
}
void AlertsPage::onrefreshClicked() {
    if (!controller) return;
    loadAlerts();
}