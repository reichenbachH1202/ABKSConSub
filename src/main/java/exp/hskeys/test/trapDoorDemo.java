package exp.hskeys.test;

import exp.hskeys.Function;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.io.IOException;

public class trapDoorDemo {
    public static void main(String[] args) throws IOException {
        Pairing bp = PairingFactory.getPairing("D:\\code\\java\\CloudCrypto-master\\src\\main\\java\\exp\\hskeys\\a.properties");
        Field Zr = bp.getZr();
        Element g = Zr.newRandomElement().getImmutable();
        Element gamma = Zr.newRandomElement().getImmutable();
        Element alpha = Zr.newRandomElement().getImmutable();
        Element u = Zr.newRandomElement().getImmutable();
        Element kw = Zr.newRandomElement().getImmutable();


        long startTime=System.currentTimeMillis();   //获取开始时间
        Function.trapDoor(100,g,gamma,alpha,u,kw);
        long endTime=System.currentTimeMillis(); //获取结束时间
        System.out.println("程序运行时间： "+(endTime-startTime)+"ms");
    }
}
