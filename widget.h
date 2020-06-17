#ifndef WIDGET_H
#define WIDGET_H

#include <QWidget>
#include <QProcess>

QT_BEGIN_NAMESPACE
namespace Ui { class Widget; }
QT_END_NAMESPACE

class Widget : public QWidget
{
    Q_OBJECT

public:
    Ui::Widget *ui;
    Widget(QWidget *parent = nullptr);
    ~Widget();
    void Sniffer(int num, int ms);
    void startSniffer(int num);
    void stopSniffer();

};

#endif // WIDGET_H
