//
// Created by mohammed on 15/11/2026.
//

#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include "Headers/DB.h"
#include "Headers/Controller.h"

namespace Ui {
    class MainWindow;
}

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow() override;
    void setController(Controller *ctrl);

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