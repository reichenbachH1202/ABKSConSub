package cn.edu.buaa.crypto.encryption.abe.kpabe.llw14.generators;

import cn.edu.buaa.crypto.algebra.serparams.AsymmetricKeySerParameter;
import cn.edu.buaa.crypto.chameleonhash.ChameleonHasher;
import cn.edu.buaa.crypto.encryption.abe.kpabe.genparams.KPABEDecryptionGenerationParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.llw14.serparams.KPABELLW14CiphertextSerParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.llw14.serparams.KPABELLW14HeaderSerParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.llw14.serparams.KPABELLW14PublicKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.rw13.generators.KPABERW13DecryptionGenerator;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.InvalidCipherTextException;

import java.io.IOException;
import java.util.Arrays;

/**
 * Created by Weiran Liu on 2017/1/1.
 *
 * Liu-Liu-Wu-14 CCA2-secure KP-ABE decryption generator.
 */
public class KPABELLW14DecryptionGenerator extends KPABERW13DecryptionGenerator {
    private ChameleonHasher chameleonHasher;
    private KPABELLW14PublicKeySerParameter publicKeyParameter;
    private KPABELLW14HeaderSerParameter headerParameter;

    public void init(CipherParameters parameter) {
        KPABEDecryptionGenerationParameter oriDecryptionGenerationParameter  = (KPABEDecryptionGenerationParameter) parameter;
        this.chameleonHasher = oriDecryptionGenerationParameter.getChameleonHasher();
        this.publicKeyParameter = (KPABELLW14PublicKeySerParameter) oriDecryptionGenerationParameter.getPublicKeyParameter();
        this.headerParameter = (KPABELLW14HeaderSerParameter) oriDecryptionGenerationParameter.getCiphertextParameter();
        Pairing pairing = PairingFactory.getPairing(oriDecryptionGenerationParameter.getPublicKeyParameter().getParameters());
        String[] attributes = oriDecryptionGenerationParameter.getAttributes();
        Element[] mappedElementAttributes = PairingUtils.MapStringArrayToFirstHalfZr(pairing, attributes);
        String[] mappedStringAttributes = PairingUtils.MapElementArrayToStringArray(mappedElementAttributes);
        KPABEDecryptionGenerationParameter decryptionGenerationParameter
                = new KPABEDecryptionGenerationParameter(
                oriDecryptionGenerationParameter.getAccessControlEngine(),
                oriDecryptionGenerationParameter.getPublicKeyParameter(),
                oriDecryptionGenerationParameter.getSecretKeyParameter(),
                mappedStringAttributes,
                oriDecryptionGenerationParameter.getCiphertextParameter());
        decryptionGenerationParameter.setChameleonHasher(chameleonHasher);
        super.init(decryptionGenerationParameter);
    }

    private void verifyCiphertext() throws InvalidCipherTextException {
        Element C0 = headerParameter.getC0().getImmutable();
        Element C01 = headerParameter.getC01().getImmutable();
        Element C02 = headerParameter.getC02().getImmutable();
        Pairing pairing = PairingFactory.getPairing(publicKeyParameter.getParameters());
        //compute Xch
        try {
            AsymmetricKeySerParameter chameleonHashPublicKey = publicKeyParameter.getChameleonHashPublicKey();
            chameleonHasher.init(false, chameleonHashPublicKey);
            byte[] byteArrayChPublicKey = PairingUtils.SerCipherParameter(chameleonHashPublicKey);
            chameleonHasher.update(byteArrayChPublicKey, 0, byteArrayChPublicKey.length);
            if (headerParameter instanceof KPABELLW14CiphertextSerParameter) {
                Element C = ((KPABELLW14CiphertextSerParameter)headerParameter).getC().getImmutable();
                byte[] byteArrayC = C.toBytes();
                chameleonHasher.update(byteArrayC, 0, byteArrayC.length);
            }
            byte[] byteArrayC0 = C0.toBytes();
            chameleonHasher.update(byteArrayC0, 0, byteArrayC0.length);
            byte[] byteArrayC01 = C01.toBytes();
            chameleonHasher.update(byteArrayC01, 0, byteArrayC01.length);
            String[] sortedAttributes = new String[this.parameter.getAttributes().length];
            System.arraycopy(this.parameter.getAttributes(), 0, sortedAttributes, 0, sortedAttributes.length);
            Arrays.sort(sortedAttributes);
            for (String attribute : sortedAttributes) {
                byte[] byteArrayAttribute = attribute.getBytes();
                chameleonHasher.update(byteArrayAttribute, 0, byteArrayAttribute.length);
                byte[] byteArrayC1i = headerParameter.getC1sAt(attribute).toBytes();
                chameleonHasher.update(byteArrayC1i, 0, byteArrayC1i.length);
                byte[] byteArrayC2i = headerParameter.getC2sAt(attribute).toBytes();
                chameleonHasher.update(byteArrayC2i, 0, byteArrayC2i.length);
            }
            byte[] chameleonHash = headerParameter.getChameleonHash();
            byte[] r = headerParameter.getR();
            byte[][] chResult = chameleonHasher.computeHash(chameleonHash, r);
            Element tempV = PairingUtils.MapByteArrayToSecondHalfZr(pairing, chResult[0]);
            String mappedStringV = tempV.toString();
            Element V = PairingUtils.MapStringToGroup(pairing, mappedStringV, PairingUtils.PairingGroupType.Zr);
            //verify ciphertext
            Element tau0 = pairing.getZr().newRandomElement().getImmutable();
            Element temp1 = C02.powZn(tau0).getImmutable();
            Element temp2 = tau0.duplicate().getImmutable();
            Element temp3 = C01.powZn(tau0).getImmutable();
            Element temp4 = C01.powZn(V.mulZn(tau0)).getImmutable();
            for (String attribute : sortedAttributes) {
                Element elementAttribute = PairingUtils.MapStringToGroup(pairing, attribute, PairingUtils.PairingGroupType.Zr);
                Element taui = pairing.getZr().newRandomElement().getImmutable();
                temp1 = temp1.mul(headerParameter.getC2sAt(attribute).powZn(taui)).getImmutable();
                temp2 = temp2.add(taui).getImmutable();
                temp3 = temp3.mul(headerParameter.getC1sAt(attribute).powZn(taui)).getImmutable();
                temp4 = temp4.mul(headerParameter.getC1sAt(attribute).powZn(elementAttribute.mulZn(taui))).getImmutable();
            }
            Element verifyResult = pairing.pairing(temp1, publicKeyParameter.getG())
                    .mul(pairing.pairing(headerParameter.getC0(), publicKeyParameter.getW()).powZn(temp2))
                    .div(pairing.pairing(temp3, publicKeyParameter.getH()))
                    .div(pairing.pairing(temp4, publicKeyParameter.getU())).getImmutable();
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
        KPABELLW14CiphertextSerParameter ciphertextParameter = (KPABELLW14CiphertextSerParameter) this.parameter.getCiphertextParameter();
        return ciphertextParameter.getC().div(sessionKey).getImmutable();
    }

    public byte[] recoverKey() throws InvalidCipherTextException {
        verifyCiphertext();
        computeDecapsulation();
        return this.sessionKey.toBytes();
    }
}
