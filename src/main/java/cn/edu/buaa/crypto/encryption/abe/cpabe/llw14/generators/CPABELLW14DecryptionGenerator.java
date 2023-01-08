package cn.edu.buaa.crypto.encryption.abe.cpabe.llw14.generators;

import cn.edu.buaa.crypto.access.AccessControlEngine;
import cn.edu.buaa.crypto.access.AccessControlParameter;
import cn.edu.buaa.crypto.algebra.serparams.AsymmetricKeySerParameter;
import cn.edu.buaa.crypto.chameleonhash.ChameleonHasher;
import cn.edu.buaa.crypto.encryption.abe.cpabe.genparams.CPABEDecryptionGenerationParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.llw14.serparams.CPABELLW14CiphertextSerParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.llw14.serparams.CPABELLW14HeaderSerParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.llw14.serparams.CPABELLW14PublicKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.rw13.generators.CPABERW13DecryptionGenerator;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.InvalidCipherTextException;

import java.io.IOException;

/**
 * Created by Weiran Liu on 2016/12/31.
 *
 * Liu-Liu-Wu-14 CCA2-secure CP-ABE decryption generator.
 */
public class CPABELLW14DecryptionGenerator extends CPABERW13DecryptionGenerator {
    private ChameleonHasher chameleonHasher;
    private CPABELLW14PublicKeySerParameter publicKeyParameter;
    private CPABELLW14HeaderSerParameter headerParameter;

    public void init(CipherParameters parameter) {
        CPABEDecryptionGenerationParameter oriDecryptionGenerationParameter  = (CPABEDecryptionGenerationParameter) parameter;
        this.chameleonHasher = oriDecryptionGenerationParameter.getChameleonHasher();
        this.publicKeyParameter = (CPABELLW14PublicKeySerParameter) oriDecryptionGenerationParameter.getPublicKeyParameter();
        this.headerParameter = (CPABELLW14HeaderSerParameter) oriDecryptionGenerationParameter.getCiphertextParameter();
        Pairing pairing = PairingFactory.getPairing(oriDecryptionGenerationParameter.getPublicKeyParameter().getParameters());
        String[] rhos = oriDecryptionGenerationParameter.getRhos();
        Element[] mappedElementRhos = PairingUtils.MapStringArrayToFirstHalfZr(pairing, rhos);
        String[] mappedStringRhos = PairingUtils.MapElementArrayToStringArray(mappedElementRhos);
        CPABEDecryptionGenerationParameter decryptionGenerationParameter
                = new CPABEDecryptionGenerationParameter(
                    oriDecryptionGenerationParameter.getAccessControlEngine(),
                    oriDecryptionGenerationParameter.getPublicKeyParameter(),
                    oriDecryptionGenerationParameter.getSecretKeyParameter(),
                    oriDecryptionGenerationParameter.getAccessPolicy(),
                    mappedStringRhos,
                    oriDecryptionGenerationParameter.getCiphertextParameter());
        decryptionGenerationParameter.setChameleonHasher(chameleonHasher);
        super.init(decryptionGenerationParameter);
    }

    private void verifyCiphertext() throws InvalidCipherTextException {
        int[][] accessPolicy = this.parameter.getAccessPolicy();
        String[] mappedStringRhos = this.parameter.getRhos();
        Element C0 = headerParameter.getC0().getImmutable();
        Element C01 = headerParameter.getC01().getImmutable();
        Element C02 = headerParameter.getC02().getImmutable();
        Element C03 = headerParameter.getC03().getImmutable();
        AccessControlEngine accessControlEngine = this.parameter.getAccessControlEngine();
        AccessControlParameter accessControlParameter = accessControlEngine.generateAccessControl(accessPolicy, mappedStringRhos);
        Pairing pairing = PairingFactory.getPairing(publicKeyParameter.getParameters());
        //compute Xch
        try {
            AsymmetricKeySerParameter chameleonHashPublicKey = publicKeyParameter.getChameleonHashPublicKey();
            chameleonHasher.init(false, chameleonHashPublicKey);
            byte[] byteArrayChPublicKey = PairingUtils.SerCipherParameter(chameleonHashPublicKey);
            chameleonHasher.update(byteArrayChPublicKey, 0, byteArrayChPublicKey.length);
            byte[] byteArrayAccessControlParameter = PairingUtils.SerCipherParameter(accessControlParameter);
            chameleonHasher.update(byteArrayAccessControlParameter, 0, byteArrayAccessControlParameter.length);
            if (headerParameter instanceof CPABELLW14CiphertextSerParameter) {
                Element C = ((CPABELLW14CiphertextSerParameter)headerParameter).getC().getImmutable();
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
                byte[] byteArrayC1i = headerParameter.getC1sAt(rho).toBytes();
                chameleonHasher.update(byteArrayC1i, 0, byteArrayC1i.length);
                byte[] byteArrayC2i = headerParameter.getC2sAt(rho).toBytes();
                chameleonHasher.update(byteArrayC2i, 0, byteArrayC2i.length);
                byte[] byteArrayC3i = headerParameter.getC3sAt(rho).toBytes();
                chameleonHasher.update(byteArrayC3i, 0, byteArrayC3i.length);
            }
            byte[] chameleonHash = headerParameter.getChameleonHash();
            byte[] r = headerParameter.getR();
            byte[][] chResult = chameleonHasher.computeHash(chameleonHash, r);
            Element tempV = PairingUtils.MapByteArrayToSecondHalfZr(pairing, chResult[0]);
            String mappedStringV = tempV.toString();
            Element V = PairingUtils.MapStringToGroup(pairing, mappedStringV, PairingUtils.PairingGroupType.Zr);
            //verify ciphertext
            Element tau0 = pairing.getZr().newRandomElement().getImmutable();
            Element temp1 = C03.powZn(tau0).getImmutable();
            Element temp2 = C03.powZn(tau0.mulZn(V)).getImmutable();
            Element temp3 = C02.powZn(tau0).getImmutable();
            //verify attributes
            for (String rho : accessControlParameter.getRhos()) {
                Element elementRho = PairingUtils.MapStringToGroup(pairing, rho, PairingUtils.PairingGroupType.Zr);
                Element taui = pairing.getZr().newRandomElement().getImmutable();
                temp1 = temp1.mul(headerParameter.getC3sAt(rho).powZn(taui)).getImmutable();
                temp2 = temp2.mul(headerParameter.getC3sAt(rho).powZn(taui.mulZn(elementRho))).getImmutable();
                temp3 = temp3.mul(headerParameter.getC2sAt(rho).powZn(taui));
            }
            Element verifyResult = pairing.pairing(temp1, publicKeyParameter.getH())
                    .mul(pairing.pairing(temp2, publicKeyParameter.getU()))
                    .mul(pairing.pairing(temp3, publicKeyParameter.getG())).getImmutable();
            if (!verifyResult.equals(pairing.getGT().newOneElement())) {
                throw new InvalidCipherTextException("Illegal ciphertext, reject to decrypt.");
            }
        } catch (IOException e) {
            throw new InvalidCipherTextException("Illegal ciphertext, reject to decrypt.");
        } catch (CryptoException e) {
            throw new InvalidCipherTextException("Illegal ciphertext, reject to decrypt.");
        }
    }

    public Element recoverMessage() throws InvalidCipherTextException {
        verifyCiphertext();
        computeDecapsulation();
        CPABELLW14CiphertextSerParameter ciphertextParameter = (CPABELLW14CiphertextSerParameter) this.parameter.getCiphertextParameter();
        return ciphertextParameter.getC().div(sessionKey).getImmutable();
    }

    public byte[] recoverKey() throws InvalidCipherTextException {
        verifyCiphertext();
        computeDecapsulation();
        return this.sessionKey.toBytes();
    }
}
