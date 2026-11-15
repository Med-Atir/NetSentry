//
// Created by mohammed on 15/11/2026.
//
#ifndef HOMEPAGE_H
#define HOMEPAGE_H

#include <QWidget>

namespace Ui {
    class HomeForm;
}

class HomePage : public QWidget {
    Q_OBJECT

public:
    explicit HomePage(QWidget *parent = nullptr);
    ~HomePage() override;

private:
    Ui::HomeForm *ui;
};

#endif // HOMEPAGE_H
