//
// Created by mohammed on 15/11/2026.
//

#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include "Headers/DB.h"

namespace Ui {
    class MainWindow;
}

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow() override;

private slots:
    void showHomePage();
    void showLiveCapturePage();
    void showFileCapturePage();
    void showAlertsPage();
    void handleClearDatabase();

private:
    Ui::MainWindow *ui;
    DB database;
};

#endif // MAINWINDOW_H