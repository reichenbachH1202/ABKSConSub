package exp.hskeys.test;

import exp.hskeys.Function;
import exp.hskeys.MyMatrix;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import static exp.hskeys.Function.Search;

public class searchDemo {
    public static void main(String[] args) {
        Pairing bp = PairingFactory.getPairing("D:\\code\\java\\CloudCrypto-master\\src\\main\\java\\exp\\hskeys\\a.properties");
        Field Zr = bp.getZr();
        Field G1 = bp.getG1();
        Element alpha = Zr.newRandomElement().getImmutable();
        Element Idx_0 = G1.newRandomElement().getImmutable();
        Element Idx_1 = G1.newRandomElement().getImmutable();
        Element Idx_2 = G1.newRandomElement().getImmutable();
        Element t1 = G1.newRandomElement().getImmutable();
        Element t2 = G1.newRandomElement().getImmutable();
        int keyword_k = 100;
        int k = 1000;
        Element[] kwHash = new Element[k];
        Element tqKw = G1.newRandomElement().getImmutable();
        for(int i = 0; i < k; i++){
            kwHash[i] = G1.newRandomElement().getImmutable();
        }

        Element[][] data2 = new Element[10][1];
        for (int i = 0; i < 10; i++) {
            data2[i][0] = Zr.newRandomElement().getImmutable();
        }
        MyMatrix mm3 = new MyMatrix(10,1,data2);

        long startTime=System.currentTimeMillis();   //获取开始时间
        Function.Search(k, mm3, tqKw, t1, t2, Idx_0, Idx_1, Idx_2, alpha, kwHash);
        long endTime=System.currentTimeMillis(); //获取结束时间
        System.out.println("程序运行时间： "+(endTime-startTime)+"ms");
    }
}
