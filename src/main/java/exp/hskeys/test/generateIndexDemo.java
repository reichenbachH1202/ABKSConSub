package exp.hskeys.test;

import exp.hskeys.Function;
import exp.hskeys.MyMatrix;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

public class generateIndexDemo {
    public static void main(String[] args) {
        Pairing bp = PairingFactory.getPairing("D:\\code\\java\\CloudCrypto-master\\src\\main\\java\\exp\\hskeys\\a.properties");
        Field Zr = bp.getZr();
        Field G1 = bp.getG1();
        Element alpha = Zr.newRandomElement().getImmutable();
        int keyword_k = 1000;
        Element[] kwHash = new Element[keyword_k];
        for(int i = 0; i < keyword_k; i++){
            kwHash[i] = G1.newRandomElement().getImmutable();
        }


        Element[][] data = new Element[10][30];
        for (int i = 0; i < 10; i++) {
            for (int j = 0; j < 30; j++) {
                data[i][j] = Zr.newRandomElement().getImmutable();
            }
        }
        MyMatrix mm1 = new MyMatrix(10,30,data);

        Element[][] data1 = new Element[10][1];
        for (int i = 0; i < 10; i++) {
            data1[i][0] = Zr.newRandomElement().getImmutable();
        }
        MyMatrix mm2 = new MyMatrix(10,1,data1);

        Element[][] data2 = new Element[10][1];
        for (int i = 0; i < 10; i++) {
            data2[i][0] = Zr.newRandomElement().getImmutable();
        }
        MyMatrix mm3 = new MyMatrix(10,1,data2);

        long startTime=System.currentTimeMillis();   //获取开始时间
        Function.generateIndex(keyword_k, kwHash, mm1, mm2, mm3, alpha);
        long endTime=System.currentTimeMillis(); //获取结束时间
        System.out.println("程序运行时间： "+(endTime-startTime)+"ms");
    }
}
