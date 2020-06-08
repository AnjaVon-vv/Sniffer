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
    Widget(QWidget *parent = nullptr);
    ~Widget();
    static void callback(u_char *arg, const struct pcap_pkthdr *pcapPkt, const u_char *packet);
    int mainSniffer();
    void stopSniffer();
    int print(const char *format,...);

private:
    Ui::Widget *ui;
    QProcess *qp;
};
#endif // WIDGET_H
