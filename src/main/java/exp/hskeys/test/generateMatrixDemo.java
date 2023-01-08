package exp.hskeys.test;

import exp.hskeys.Function;
import exp.hskeys.MyMatrix;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

public class generateMatrixDemo {
    public static void main(String[] args) throws Exception {
        Pairing bp = PairingFactory.getPairing("D:\\code\\java\\CloudCrypto-master\\src\\main\\java\\exp\\hskeys\\a.properties");
        Field Zr = bp.getZr();
        Element[][] data = new Element[2][3];
        for (int i = 0; i < 2; i++) {
            for (int j = 0; j < 3; j++) {
                data[i][j] = Zr.newRandomElement().getImmutable();
            }
        }
        MyMatrix mm = new MyMatrix(2,3,data);
        for (int i = 0; i < 2; i++) {
            for (int j = 0; j < 3; j++) {
                System.out.println(data[i][j]);
            }
        }

        Element[][] data1 = new Element[3][4];
        for (int i = 0; i < 3; i++) {
            for (int j = 0; j < 4; j++) {
                data1[i][j] = Zr.newRandomElement().getImmutable();
            }
        }
        for (int i = 0; i < 3; i++) {
            for (int j = 0; j < 4; j++) {
                System.out.println(data1[i][j]);
            }
        }

        MyMatrix mm1 = new MyMatrix(3, 4, data1);
        MyMatrix mm2 = mm.multiply(mm1);
        for (int i = 0; i < 2; i++) {
            for (int j = 0; j < 4; j++) {
                System.out.println(mm2.getValue()[i][j]);
            }
        }
        Element e1 = Zr.newRandomElement().getImmutable();
        Element e2 = Zr.newRandomElement().getImmutable();
        System.out.println("==========================");
        System.out.println(e1);
        System.out.println(e2);
        System.out.println(e1.add(e2));
        System.out.println(e1.mul(e2));
        System.out.println("==============================");
        MyMatrix.toString(mm1);
    }
}