package exp.hskeys.test;

import exp.hskeys.Function;
import exp.hskeys.MyMatrix;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

public class onlineEncDemo {
    public static void main(String[] args) {
        Pairing bp = PairingFactory.getPairing("D:\\code\\java\\CloudCrypto-master\\src\\main\\java\\exp\\hskeys\\a.properties");
        Field Zr = bp.getZr();
        Element[][] data = new Element[10][30];
        for (int i = 0; i < 10; i++) {
            for (int j = 0; j < 30; j++) {
                data[i][j] = Zr.newRandomElement().getImmutable();
            }
        }
        Element[][] data1 = new Element[10][1];
        for (int i = 0; i < 10; i++) {
            for (int j = 0; j < 1; j++) {
                data1[i][j] = Zr.newRandomElement().getImmutable();
            }
        }
        Element[][] data2 = new Element[10][1];
        for (int i = 0; i < 10; i++) {
            for (int j = 0; j < 1; j++) {
                data2[i][j] = Zr.newRandomElement().getImmutable();
            }
        }
        MyMatrix mm2 = new MyMatrix(10,30,data2);
        MyMatrix mm = new MyMatrix(10,30,data);
        MyMatrix mm1 = new MyMatrix(10,1,data1);
        Element M = Zr.newRandomElement().getImmutable();;
        Element[] s = new Element[10];
        for(int i = 0; i < 10; i++){
            s[i] = Zr.newRandomElement().getImmutable();
        }
        Element alpha = Zr.newRandomElement().getImmutable();
        Element t = Zr.newRandomElement().getImmutable();
        Element[] element_x = new Element[10];
        for(int i = 0; i < 10; i++){
            element_x[i] = Zr.newRandomElement().getImmutable();
        }

        long startTime=System.currentTimeMillis();   //获取开始时间
        System.out.println(Function.onlineEnc(mm,mm1,mm2,M,s, alpha, t, element_x));
        long endTime=System.currentTimeMillis(); //获取结束时间
        System.out.println("程序运行时间： "+(endTime-startTime)+"ms");
    }
}