package exp.hskeys;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.io.IOException;
import java.math.BigInteger;
import java.util.HashMap;



public class Function {
    public static MyMatrix generateMatrix(int l, int n) {
        Pairing bp = PairingFactory.getPairing("D:\\code\\java\\CloudCrypto-master\\src\\main\\java\\exp\\hskeys\\a.properties");
        Field Zr = bp.getZr();
        Element[][] data = new Element[l][n];
        for (int i = 0; i < l; i++) {
            for (int j = 0; j < n; j++) {
                data[i][j] = Zr.newRandomElement().getImmutable();
            }
        }
        MyMatrix mm = new MyMatrix(l, n, data);
        return mm;
    }
    public static HashMap<Object, Object> offlineEnc(MyMatrix mymatrix, Element alpha, Element u, Element h) throws Exception {
        Pairing bp = PairingFactory.getPairing("D:\\code\\java\\CloudCrypto-master\\src\\main\\java\\exp\\hskeys\\a.properties");
        Field Zr = bp.getZr();

        Field G1 = bp.getG1();
        Element g = G1.newRandomElement().getImmutable();


        Element[][] v = new Element[mymatrix.widthMatrixIsCol()][1];
        for (int i = 0; i < mymatrix.widthMatrixIsCol(); i++) {
            v[i][0] = Zr.newRandomElement().getImmutable();
        }
        Element s = v[0][0];
        MyMatrix myMatrix_v = new MyMatrix(mymatrix.widthMatrixIsCol(),1, v);
        MyMatrix myMatrix_Lammda = mymatrix.multiply(myMatrix_v);

        Element egg = bp.pairing(g,g).getImmutable();
        Element c0 = egg.powZn(alpha.mul(s));
        Element c1 = g.powZn(s);


        Element[] element_s = new Element[mymatrix.heightMatrixIsRow()];
        Element[] element_x = new Element[mymatrix.heightMatrixIsRow()];
        Element[] element_c2 = new Element[mymatrix.heightMatrixIsRow()];
        Element[] element_c3 = new Element[mymatrix.heightMatrixIsRow()];
        for(int i = 0; i < mymatrix.heightMatrixIsRow(); i++){
            element_s[i] = Zr.newRandomElement().getImmutable();
            element_x[i] = Zr.newRandomElement().getImmutable();
            element_c2[i] = (u.powZn(element_x[i]).mul(h)).powZn(element_s[i].pow(BigInteger.valueOf(-1)));
            element_c3[i] = g.powZn(element_s[i]);
        }
        HashMap<Object,Object> map = new HashMap<Object,Object>();
        map.put(1,mymatrix);
        map.put(2,myMatrix_v);
        map.put(3,c0);
        map.put(4,c1);
        map.put(5,element_c2);
        map.put(6,element_c3);
        map.put(7,myMatrix_Lammda);
        return map;
    }
    public static HashMap<Object, Object> onlineEnc(MyMatrix mymatrix, MyMatrix lammda, MyMatrix raw, Element M, Element[] s, Element alpha,Element t, Element[] element_x){
        Pairing bp = PairingFactory.getPairing("D:\\code\\java\\CloudCrypto-master\\src\\main\\java\\exp\\hskeys\\a.properties");
        Field Zr = bp.getZr();
        Field G1 = bp.getG1();
        Element g = G1.newRandomElement().getImmutable();
        Element S = G1.newRandomElement().getImmutable();
        Element w = Zr.newRandomElement().getImmutable();
        Element v = Zr.newRandomElement().getImmutable();
        Element u0 = Zr.newRandomElement().getImmutable();
        Element h0 = Zr.newRandomElement().getImmutable();
        Element[] element_c4 = new Element[raw.heightMatrixIsRow()];
        Element[] element_c22 = new Element[raw.heightMatrixIsRow()];
        Element egg = bp.pairing(g,g).getImmutable();
        Element c = egg.powZn(alpha.mul(S));
        Element c1 = g.powZn(S);

        for(int i = 0; i < raw.heightMatrixIsRow(); i++){
            Element[][] data = raw.getValue();
            element_c22[i] = data[i][0].sub(element_x[i]).pow(BigInteger.valueOf(-1));
        }

        for(int i = 0; i < raw.heightMatrixIsRow(); i++){
            Element[][] data = lammda.getValue();
            element_c4[i] = w.powZn(data[i][0]).mul(v.powZn(s[i]));
        }
        Element element_c5 = (u0.powZn(t).mul(h0)).powZn(S);

        HashMap<Object,Object> map = new HashMap<Object,Object>();
        map.put(1,mymatrix);
        map.put(2,raw);
        map.put(3,c);
        map.put(4,c1);
        map.put(5,element_c22);
        map.put(6,element_c5);
        return map;
    }
    public static HashMap<Object, Object> trapDoor(int k, Element g, Element gamma, Element alpha, Element u, Element kwHash) throws IOException {
        Pairing bp = PairingFactory.getPairing("D:\\code\\java\\CloudCrypto-master\\src\\main\\java\\exp\\hskeys\\a.properties");
        Field Zr = bp.getZr();
        Element tqKw = kwHash.mul(g.powZn(alpha));
        Element[][] t = new Element[k][2];
        for(int i = 0; i < k; i++){
            Element beta = Zr.newRandomElement().getImmutable();
            Element w = Zr.newRandomElement().getImmutable();
            Element h = Zr.newRandomElement().getImmutable();

            Element c1 = g.powZn(alpha.sub(u));
            Element c2 = g.powZn(alpha.sub(u)).powZn(gamma);
            Element c5 = (u.powZn(w)).sub(h);
            Element c3 = c5.powZn(beta);
            Element c4 = c1.mul(c2);
            Element t1 = c4.mul(c3);

            Element t2 = g.powZn(u.mul(beta));
            t[i][0] = t1;
            t[i][1] = t2;
        }
        HashMap<Object,Object> map = new HashMap<Object,Object>();
        map.put(1,tqKw);
        map.put(2,t);
        return map;
    }
    public static HashMap<Object, Object> generateIndex(int keyword_k, Element[] kwHash, MyMatrix mymatrix, MyMatrix raw, MyMatrix lammda, Element alpha){
        Pairing bp = PairingFactory.getPairing("D:\\code\\java\\CloudCrypto-master\\src\\main\\java\\exp\\hskeys\\a.properties");
        Field Zr = bp.getZr();

        Field G1 = bp.getG1();
        Element g = G1.newRandomElement().getImmutable();
        Element u = Zr.newRandomElement().getImmutable();
        Element h = Zr.newRandomElement().getImmutable();

        Element[] k = new Element[keyword_k];
        Element[] Idx_0 = new Element[keyword_k];
        Element[] Idx_1 = new Element[lammda.heightMatrixIsRow()];
        Element[] Idx_2 = new Element[lammda.heightMatrixIsRow()];
        Element[][] e1 = lammda.getValue();

        for(int i = 0; i < keyword_k; i++){
            Element egg1 = bp.pairing(g,kwHash[i]).getImmutable();
            Element egg2 = bp.pairing(g,g).getImmutable();
            Element s = Zr.newRandomElement().getImmutable();
            Element s1 = egg2.powZn(alpha.mul(s));
            k[i] = egg1.powZn(s).sub(s1);
            Idx_0[i] = g.powZn(s);
        }
        for(int i = 0; i < lammda.heightMatrixIsRow(); i++){
            Element z = u.mul(e1[i][0]);
            Idx_1[i] = g.powZn(z);
            Element[][] e2 = raw.getValue();
            Idx_2[i] = (u.powZn(e2[i][0]).mul(h)).powZn(e1[i][0]);
        }
        HashMap<Object,Object> map = new HashMap<Object,Object>();
        map.put(1,k);
        map.put(2,Idx_0);
        map.put(3,Idx_1);
        map.put(4,Idx_2);
        return map;
    }
    public static boolean Search(int k, MyMatrix lammda, Element tqKw, Element t1, Element t2, Element Idx_0, Element Idx_1, Element Idx_2, Element alpha, Element[] kwHash){
        Pairing bp = PairingFactory.getPairing("D:\\code\\java\\CloudCrypto-master\\src\\main\\java\\exp\\hskeys\\a.properties");
        Field Zr = bp.getZr();

        Field G1 = bp.getG1();
        Element g = G1.newRandomElement().getImmutable();
        Element[][] lammdaArray = lammda.getValue();
        for(int i = 1; i < lammda.heightMatrixIsRow(); i++){
            lammdaArray[0][0] = lammdaArray[0][0].add(lammdaArray[i][0]);
        }
        Element egg1 = bp.pairing(g,Idx_0).getImmutable();
        Element egg2 = bp.pairing(Idx_1,t1).getImmutable();
        Element egg3 = bp.pairing(Idx_2,t2).getImmutable();
        Element down = egg2.sub(egg3);
        Element down1 = down.powZn(lammdaArray[0][0]);
        Element s = Zr.newRandomElement().getImmutable();
        Element k_kw = egg1.sub(down1);
        for(int i = 0; i < k; i++){
            Element upNow = bp.pairing(g,kwHash[i]).getImmutable();
            Element downNow = egg2.powZn(alpha.mul(s));
            Element k_num = upNow.sub(downNow);
            if(k_num.equals(k_kw)){
                return true;
            }
        }
        return false;
    }
    public static boolean onlineDec(Element m1, Element q, Element c1, Element c5, Element hashValue, Element SDK1, Element SDK2){
        Pairing bp = PairingFactory.getPairing("D:\\code\\java\\CloudCrypto-master\\src\\main\\java\\exp\\hskeys\\a.properties");
        Element egg1 = bp.pairing(c5,SDK1.powZn(hashValue)).getImmutable();
        Element e = q.mul(egg1);
        Element egg2 = bp.pairing(c1,SDK2).getImmutable();
        Element m0 = e.sub(egg2);
        if(m0.equals(m1)){
            return true;
        }else {
            return false;
        }
    }
}
