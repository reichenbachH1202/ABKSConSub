package cn.edu.buaa.crypto.encryption.abe.cpabe.llw16.generators;

import cn.edu.buaa.crypto.algebra.generators.AsymmetricKeySerPairGenerator;
import cn.edu.buaa.crypto.algebra.serparams.AsymmetricKeySerPair;
import cn.edu.buaa.crypto.algebra.serparams.AsymmetricKeySerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeyEncapsulationSerPair;
import cn.edu.buaa.crypto.chameleonhash.ChameleonHasher;
import cn.edu.buaa.crypto.encryption.abe.cpabe.genparams.CPABEEncryptionGenerationParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.hw14.generators.CPABEHW14EncryptionGenerator;
import cn.edu.buaa.crypto.encryption.abe.cpabe.hw14.serparams.CPABEHW14IntermediateSerParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.llw16.serparams.CPABELLW16CiphertextSerParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.llw16.serparams.CPABELLW16HeaderSerParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.llw16.serparams.CPABELLW16IntermediateSerParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.llw16.serparams.CPABELLW16PublicKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.KeyGenerationParameters;

import java.io.IOException;

/**
 * Created by Weiran Liu on 17/1/2.
 *
 * Liu-Liu-Wu-16 CCA2-secure OO-CP-ABE encryption generator.
 */
public class CPABELLW16EncryptionGenerator extends CPABEHW14EncryptionGenerator {
    private ChameleonHasher chameleonHasher;
    private CPABELLW16PublicKeySerParameter publicKeyParameter;
    private CPABELLW16IntermediateSerParameter intermediate;
    private AsymmetricKeySerParameter chameleonHashPublicKey;
    private AsymmetricKeySerParameter chameleonHashSecretKey;
    private Element C01;
    private Element C02;
    private Element C03;
    private byte[] chameleonHash;
    private byte[] r;

    public void init(CipherParameters parameter) {
        CPABEEncryptionGenerationParameter oriEncryptionParameter = (CPABEEncryptionGenerationParameter) parameter;
        this.chameleonHasher = oriEncryptionParameter.getChameleonHasher();
        this.publicKeyParameter = (CPABELLW16PublicKeySerParameter) oriEncryptionParameter.getPublicKeyParameter();
        if (oriEncryptionParameter.isIntermediateGeneration()) {
            this.intermediate = (CPABELLW16IntermediateSerParameter)oriEncryptionParameter.getIntermediate();
            this.chameleonHashPublicKey = this.intermediate.getChameleonHashPublicKey();
            this.chameleonHashSecretKey = this.intermediate.getChameleonHashSecretKey();
        } else {
            AsymmetricKeySerPairGenerator chKeyPairGenerator = oriEncryptionParameter.getChameleonHashKeyPairGenerator();
            KeyGenerationParameters chKeyPairGenerationParameter = oriEncryptionParameter.getChameleonHashKeyPairGenerationParameter();
            chKeyPairGenerator.init(chKeyPairGenerationParameter);
            AsymmetricKeySerPair chKeyPair = chKeyPairGenerator.generateKeyPair();
            this.chameleonHashPublicKey = chKeyPair.getPublic();
            this.chameleonHashSecretKey = chKeyPair.getPrivate();
        }
        Pairing pairing = PairingFactory.getPairing(oriEncryptionParameter.getPublicKeyParameter().getParameters());
        String[] rhos = oriEncryptionParameter.getRhos();
        Element[] mappedElementRhos = PairingUtils.MapStringArrayToFirstHalfZr(pairing, rhos);
        String[] mappedStringRhos = PairingUtils.MapElementArrayToStringArray(mappedElementRhos);
        CPABEEncryptionGenerationParameter resultEncryptionParameter = new CPABEEncryptionGenerationParameter(
                oriEncryptionParameter.getAccessControlEngine(),
                oriEncryptionParameter.getPublicKeyParameter(),
                oriEncryptionParameter.getAccessPolicy(),
                mappedStringRhos,
                oriEncryptionParameter.getMessage()
        );
        if (oriEncryptionParameter.isIntermediateGeneration()) {
            CPABEHW14IntermediateSerParameter intermediateHW14 = new CPABEHW14IntermediateSerParameter(
                    this.intermediate.getParameters(),
                    this.intermediate.getN(),
                    this.intermediate.getSessionKey(),
                    this.intermediate.getS(),
                    this.intermediate.getC0(),
                    this.intermediate.getLambdas(),
                    this.intermediate.getTs(),
                    this.intermediate.getXs(),
                    this.intermediate.getC1s(),
                    this.intermediate.getC2s(),
                    this.intermediate.getC3s()
            );
            resultEncryptionParameter.setIntermediate(intermediateHW14);
        }
        super.init(resultEncryptionParameter);
    }

    protected void computeEncapsulation() {
        super.computeEncapsulation();
        try {
            Pairing pairing = PairingFactory.getPairing(this.publicKeyParameter.getParameters());
            if (this.parameter.isIntermediateGeneration()) {
                this.C01 = this.intermediate.getC01().getImmutable();
                this.C02 = this.intermediate.getC02().getImmutable();
                this.C03 = this.intermediate.getC03().getImmutable();
                this.chameleonHash = this.intermediate.getChameleonHash();
                this.r = this.intermediate.getR();
            } else {
                Element t0 = pairing.getZr().newRandomElement().getImmutable();
                this.C01 = publicKeyParameter.getW().powZn(s).mul(publicKeyParameter.getV().powZn(t0)).getImmutable();
                this.C03 = publicKeyParameter.getG().powZn(t0).getImmutable();
                chameleonHasher.init(false, chameleonHashPublicKey);
                byte[] byteArrayChameleonHashPublicKey = PairingUtils.SerCipherParameter(chameleonHashPublicKey);
                chameleonHasher.update(byteArrayChameleonHashPublicKey, 0, byteArrayChameleonHashPublicKey.length);
                byte[][] chResult = chameleonHasher.computeHash();
                this.chameleonHash = chResult[0];
                this.r = chResult[1];
                Element tempV = PairingUtils.MapByteArrayToSecondHalfZr(pairing, chResult[0]);
                String mappedStringV = tempV.toString();
                Element V = PairingUtils.MapStringToGroup(pairing, mappedStringV, PairingUtils.PairingGroupType.Zr);
                this.C02 = publicKeyParameter.getU().powZn(V).mul(publicKeyParameter.getH()).powZn(t0.negate()).getImmutable();
            }
            chameleonHasher.init(true, chameleonHashSecretKey);
            byte[] byteArrayChPublicKey = PairingUtils.SerCipherParameter(chameleonHashPublicKey);
            chameleonHasher.update(byteArrayChPublicKey, 0, byteArrayChPublicKey.length);
            byte[] byteArrayAccessControlParameter = PairingUtils.SerCipherParameter(accessControlParameter);
            chameleonHasher.update(byteArrayAccessControlParameter, 0, byteArrayAccessControlParameter.length);
            if (this.parameter.getMessage() != null) {
                Element C = this.sessionKey.mul(this.parameter.getMessage()).getImmutable();
                byte[] byteArrayC = C.toBytes();
                chameleonHasher.update(byteArrayC, 0, byteArrayC.length);
            }
            byte[] byteArrayC0 = C0.toBytes();
            chameleonHasher.update(byteArrayC0, 0, byteArrayC0.length);
            byte[] byteArrayC01 = C01.toBytes();
            chameleonHasher.update(byteArrayC01, 0, byteArrayC01.length);
            byte[] byteArrayC03 = C03.toBytes();
            chameleonHasher.update(byteArrayC03, 0, byteArrayC03.length);
            for (String rho : accessControlParameter.getRhos()) {
                byte[] byteArrayC1i = C1s.get(rho).toBytes();
                chameleonHasher.update(byteArrayC1i, 0, byteArrayC1i.length);
                byte[] byteArrayC2i = C2s.get(rho).toBytes();
                chameleonHasher.update(byteArrayC2i, 0, byteArrayC2i.length);
                byte[] byteArrayC3i = C3s.get(rho).toBytes();
                chameleonHasher.update(byteArrayC3i, 0, byteArrayC3i.length);
                byte[] byteArrayC4i = C4s.get(rho).toBytes();
                chameleonHasher.update(byteArrayC4i, 0, byteArrayC4i.length);
                byte[] byteArrayC5i = C5s.get(rho).toBytes();
                chameleonHasher.update(byteArrayC5i, 0, byteArrayC5i.length);
            }
            byte[][] chResult = chameleonHasher.findCollision(this.chameleonHash, this.r);
            this.chameleonHash = chResult[0];
            this.r = chResult[1];
        } catch (IOException e) {
            throw new RuntimeException("Cannot serialize chk.");
        } catch (CryptoException e) {
            throw new RuntimeException("Cannot compute chameleon hash.");
        }
    }

    public PairingKeyEncapsulationSerPair generateEncryptionPair() {
        computeEncapsulation();
        return new PairingKeyEncapsulationSerPair(
                this.sessionKey.toBytes(),
                new CPABELLW16HeaderSerParameter(
                        publicKeyParameter.getParameters(), chameleonHash, r, chameleonHashPublicKey,
                        C01, C02, C03, C0, C1s, C2s, C3s, C4s, C5s)
        );
    }

    public PairingCipherSerParameter generateCiphertext() {
        computeEncapsulation();
        Element C = this.sessionKey.mul(this.parameter.getMessage()).getImmutable();
        return new CPABELLW16CiphertextSerParameter(
                publicKeyParameter.getParameters(), chameleonHash, r, chameleonHashPublicKey,
                C01, C02, C03, C, C0, C1s, C2s, C3s, C4s, C5s);
    }
}
