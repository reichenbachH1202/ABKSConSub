package exp.hskeys.test;

import exp.hskeys.Function;
import exp.hskeys.MyMatrix;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

public class onlineDecDemo {
    public static void main(String[] args) {
        Pairing bp = PairingFactory.getPairing("D:\\code\\java\\CloudCrypto-master\\src\\main\\java\\exp\\hskeys\\a.properties");
        Field Zr = bp.getZr();
        Field G1 = bp.getG1();
        Element hashValue = Zr.newRandomElement().getImmutable();
        Element c5 = G1.newRandomElement().getImmutable();
        Element c1 = G1.newRandomElement().getImmutable();
        Element m1 = G1.newRandomElement().getImmutable();
        Element q = G1.newRandomElement().getImmutable();
        Element SDK1 = G1.newRandomElement().getImmutable();
        Element SDK2 = G1.newRandomElement().getImmutable();

        long startTime=System.currentTimeMillis();   //获取开始时间
        Function.onlineDec(m1, q, c1, c5, hashValue, SDK1, SDK2);
        long endTime=System.currentTimeMillis(); //获取结束时间
        System.out.println("程序运行时间： "+(endTime-startTime)+"ms");
    }
}
