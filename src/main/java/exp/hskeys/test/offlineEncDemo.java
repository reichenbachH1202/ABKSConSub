package exp.hskeys.test;

import exp.hskeys.Function;
import exp.hskeys.MyMatrix;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.HashMap;

public class offlineEncDemo {
    public static void main(String[] args) throws Exception {

        Pairing bp = PairingFactory.getPairing("D:\\code\\java\\CloudCrypto-master\\src\\main\\java\\exp\\hskeys\\a.properties");
        Field Zr = bp.getZr();
        Element[][] data = new Element[100][300];
        for (int i = 0; i < 100; i++) {
            for (int j = 0; j < 300; j++) {
                data[i][j] = Zr.newRandomElement().getImmutable();
            }
        }
        MyMatrix mm = new MyMatrix(100,300,data);
        Element alpha = Zr.newRandomElement().getImmutable();
        Element u = Zr.newRandomElement().getImmutable();
        Element h = Zr.newRandomElement().getImmutable();
        long startTime=System.currentTimeMillis();   //获取开始时间
        System.out.println(Function.offlineEnc(mm,alpha,u,h));
        long endTime=System.currentTimeMillis(); //获取结束时间
        System.out.println("程序运行时间： "+(endTime-startTime)+"ms");
    }
}