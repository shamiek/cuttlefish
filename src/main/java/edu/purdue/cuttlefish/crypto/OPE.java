package edu.purdue.cuttlefish.crypto;

import edu.purdue.cuttlefish.utils.FileUtils;

import java.math.BigInteger;

/**
 * TODO: SIMULATED OPE.
 * <p>
 * This is a simulated OPE scheme that offers no security and used only for testing. For a proper
 * scheme implementation take a look at our java implementation of the Boldyreva et al.
 * "Order-Preserving Symmetric Encryption" scheme @ https://github.com/ssavvides/jope
 */
public class OPE extends CryptoScheme {

//    private static final String DEFAULT_KEY_PATH = "/tmp/ope.sk";
    private static final String DEFAULT_KEY_PATH = System.getenv("CF_KEYS_DIR").concat("/ope.sk");
    private static final int DEFAULT_CIPHERTEXT_EXTRABITS = 32;
    private static final long CTXT_BLOCKS = (long) Math.pow(2, DEFAULT_CIPHERTEXT_EXTRABITS);

    public OPE() {
        this(DEFAULT_KEY_PATH);
    }

    public OPE(String privateKeyPath) {
        super(privateKeyPath);
    }

    @Override
    public void keyGen() {
        String key = new BigInteger(128, RNG).toString(32);
        FileUtils.saveObjectToFile(key, privateKeyPath);
    }

    public long encrypt(long m) {
        return m * CTXT_BLOCKS;
    }

    public String encrypt(String m) {
        String s = m + CTXT_BLOCKS;
        String o = "";
        for (char c : s.toCharArray())
            o += (char) (c + 10);
        return o;
    }

    public long decrypt(long c) {
        return c / CTXT_BLOCKS;
    }

    public String decrypt(String ctxt) {
        String o = ctxt.substring(0, ctxt.length() - String.valueOf(CTXT_BLOCKS).length());
        String p = "";
        for (char c : o.toCharArray())
            p += (char) (c - 10);
        return p;
    }

    public void q01Const(String qName) {
        String d = "1998-09-02";
//        OPE ope = new OPE();
        String cGram = this.encrypt(d);
        System.out.println(qName + " cGram: " + cGram + "\tplain: " + this.decrypt(cGram));
    }

    public void q02Const(String qName) {
        long d = 15;
//        OPE ope = new OPE();
        long cGram = this.encrypt(d);
        System.out.println(qName + " cGram: " + cGram + "\tplain: " + this.decrypt(cGram));
    }

    public void q03Const(String qName) {
        String [] d = {"1995-03-15"};
        String [] cGram = {this.encrypt(d[0])};
        System.out.println(qName + " cGram: " + cGram[0] + "\tplain: " + this.decrypt(cGram[0]));
    }
    public void q04Const(String qName) {
        String [] d = {"1993-07-01", "1993-10-01"};
        String [] cGram = {this.encrypt(d[0]), this.encrypt(d[1])};
        System.out.println(qName + " cGram: " + cGram[0] + "\tplain: " + this.decrypt(cGram[0]));
        System.out.println(qName + " cGram: " + cGram[1] + "\tplain: " + this.decrypt(cGram[1]));
    }
    public void q05Const(String qName) {
        String [] d = {"1995-01-01", "1994-01-01"};
        String [] cGram = {this.encrypt(d[0]), this.encrypt(d[1])};
        System.out.println(qName + " cGram: " + cGram[0] + "\tplain: " + this.decrypt(cGram[0]));
        System.out.println(qName + " cGram: " + cGram[1] + "\tplain: " + this.decrypt(cGram[1]));
    }
    public void q07Const(String qName) {
        String [] d = {"FRANCE", "GERMANY", "1995-01-01", "1996-12-31"};
        String [] cGram = {this.encrypt(d[0]), this.encrypt(d[1]), this.encrypt(d[2]), this.encrypt(d[3])};
        System.out.println(qName + " cGram: " + cGram[0] + "\tplain: " + this.decrypt(cGram[0]));
        System.out.println(qName + " cGram: " + cGram[1] + "\tplain: " + this.decrypt(cGram[1]));
        System.out.println(qName + " cGram: " + cGram[2] + "\tplain: " + this.decrypt(cGram[2]));
        System.out.println(qName + " cGram: " + cGram[3] + "\tplain: " + this.decrypt(cGram[3]));
    }
    public void q08Const(String qName) {
        String [] d = {"BRAZIL", "1995-01-01", "1996-12-31"};
        String [] cGram = {this.encrypt(d[0]), this.encrypt(d[1]), this.encrypt(d[2])};
        System.out.println(qName + " cGram: " + cGram[0] + "\tplain: " + this.decrypt(cGram[0]));
        System.out.println(qName + " cGram: " + cGram[1] + "\tplain: " + this.decrypt(cGram[1]));
        System.out.println(qName + " cGram: " + cGram[2] + "\tplain: " + this.decrypt(cGram[2]));
    }
    public void q10Const(String qName) {
        String [] d = {"R", "1994-01-01", "1993-10-01"};
        String [] cGram = {this.encrypt(d[0]), this.encrypt(d[1]), this.encrypt(d[2])};
        System.out.println(qName + " cGram: " + cGram[0] + "\tplain: " + this.decrypt(cGram[0]));
        System.out.println(qName + " cGram: " + cGram[1] + "\tplain: " + this.decrypt(cGram[1]));
        System.out.println(qName + " cGram: " + cGram[2] + "\tplain: " + this.decrypt(cGram[2]));
    }
    public void q11Const(String qName) {
        String [] d = {"GERMANY"};
        String [] cGram = {this.encrypt(d[0])};
        System.out.println(qName + " cGram: " + cGram[0] + "\tplain: " + this.decrypt(cGram[0]));
    }
    public void q12Const(String qName) {
        String [] d = {"MAIL", "SHIP", "1994-01-01", "1995-01-01", "1-URGENT", "2-HIGH"};
//        String [] cGram = {this.encrypt(d[0]), this.encrypt(d[1]),
//                this.encrypt(d[2]), this.encrypt(d[3]),
//                this.encrypt(d[4]), this.encrypt(d[5])};
//        System.out.println(qName + " cGram: " + cGram[0] + "\tplain: " + this.decrypt(cGram[0]));
//        System.out.println(qName + " cGram: " + cGram[1] + "\tplain: " + this.decrypt(cGram[1]));
//        System.out.println(qName + " cGram: " + cGram[2] + "\tplain: " + this.decrypt(cGram[2]));
//        System.out.println(qName + " cGram: " + cGram[3] + "\tplain: " + this.decrypt(cGram[3]));
//        System.out.println(qName + " cGram: " + cGram[4] + "\tplain: " + this.decrypt(cGram[4]));
//        System.out.println(qName + " cGram: " + cGram[5] + "\tplain: " + this.decrypt(cGram[5]));
        String [] cGram = new String[6];
        for (int i = 0; i < d.length; i++) {
            cGram[i] = this.encrypt(d[i]);
        }
        for (int i = 0; i < d.length; i++) {
            System.out.println(qName + " cGram: " + cGram[i] + "\tplain: " + this.decrypt(cGram[i]));
        }
    }
    public void q14Const(String qName) {
        String [] d = {"1995-09-01", "1995-10-01"};
        String [] cGram = {this.encrypt(d[0]), this.encrypt(d[1])};
        System.out.println(qName + " cGram: " + cGram[0] + "\tplain: " + this.decrypt(cGram[0]));
        System.out.println(qName + " cGram: " + cGram[1] + "\tplain: " + this.decrypt(cGram[1]));
    }
    public void q15Const(String qName) {
        String [] d = {"1996-01-01", "1996-04-01"};
        String [] cGram = {this.encrypt(d[0]), this.encrypt(d[1])};
        System.out.println(qName + " cGram: " + cGram[0] + "\tplain: " + this.decrypt(cGram[0]));
        System.out.println(qName + " cGram: " + cGram[1] + "\tplain: " + this.decrypt(cGram[1]));
    }
    public void q16Const(String qName) {
        String d = "Brand#45";
        String dEnc = this.encrypt(d);
        long [] dLong = {49, 14, 23, 45, 19, 3, 36, 9};
        long [] cGram = new long[8];
        System.out.println(qName + " cGram: " + dEnc + "\tplain: " + this.decrypt(dEnc));
        for (int i = 0; i < dLong.length; i++) {
            cGram[i] = this.encrypt(dLong[i]);
        }
        for (int i = 0; i < dLong.length; i++) {
            System.out.println(qName + " cGram: " + cGram[i] + "\tplain: " + this.decrypt(cGram[i]));
        }
        // for copying
//        System.out.println();
//        for (int i = 0; i < dLong.length; i++) {
//            System.out.print(cGram[i] + "L||");
//        }
//        System.out.println();
    }
    public void q17Const(String qName) {
        String d = "Brand#23";
        String dEnc = this.encrypt(d);
        System.out.println(qName + " cGram: " + dEnc + "\tplain: " + this.decrypt(dEnc));
    }
    public void q19Const(String qName) {
        String [] dString = {"AIR", "AIR REG", "DELIVER IN PERSON"};
        String [] cGramS = new String[4];

        long [] dLong = {1, 5, 10, 15};
        long [] cGramL = new long[4];

        for (int i = 0; i < dString.length; i++) {
            cGramS[i] = this.encrypt(dString[i]);
        }
        for (int i = 0; i < dLong.length; i++) {
            cGramL[i] = this.encrypt(dLong[i]);
        }
        for (int i = 0; i < dString.length; i++) {
            System.out.println(qName + " cGram: " + cGramS[i] + "\tplain: " + this.decrypt(cGramS[i]));
        }
        for (int i = 0; i < dLong.length; i++) {
            System.out.println(qName + " cGram: " + cGramL[i] + "\tplain: " + this.decrypt(cGramL[i]));
        }
        // for copying
//        System.out.println();
//        for (int i = 0; i < dLong.length; i++) {
//            System.out.print(cGram[i] + "L||");
//        }
//        System.out.println();
    }
    public void q20Const(String qName) {
        String [] d = {"1994-01-01", "1995-01-01", "CANADA"};
        String [] cGram = {this.encrypt(d[0]), this.encrypt(d[1]), this.encrypt(d[2])};
        System.out.println(qName + " cGram: " + cGram[0] + "\tplain: " + this.decrypt(cGram[0]));
        System.out.println(qName + " cGram: " + cGram[1] + "\tplain: " + this.decrypt(cGram[1]));
        System.out.println(qName + " cGram: " + cGram[2] + "\tplain: " + this.decrypt(cGram[2]));
    }
    public void q21Const(String qName) {
        String [] d = {"F", "SAUDI ARABIA"};
        String [] cGram = {this.encrypt(d[0]), this.encrypt(d[1])};
        System.out.println(qName + " cGram: " + cGram[0] + "\tplain: " + this.decrypt(cGram[0]));
        System.out.println(qName + " cGram: " + cGram[1] + "\tplain: " + this.decrypt(cGram[1]));
    }
    public void q22Const(String qName) {
        long d = 0;
        long dEnc = this.encrypt(d);
        System.out.println(qName + " cGram: " + dEnc + "\tplain: " + this.decrypt(dEnc));
    }
    public static void main(String[] args) {
        OPE ope = new OPE();
        long m = 5;
        long c = ope.encrypt(m);
        System.out.println("cGram: " + c + "\tplain: " + ope.decrypt(c));
//        System.out.println("cGram: " + c + "\tplain: " + ope.decrypt("\\><C>C@A<C@"));
        ope.q01Const("[Q01].");
        ope.q02Const("[Q02].");
        ope.q03Const("[Q03].");
        ope.q04Const("[Q04].");
        ope.q05Const("[Q05].");
        ope.q07Const("[Q07].");
        ope.q08Const("[Q08].");
        ope.q10Const("[Q10].");
        ope.q11Const("[Q11].");
        ope.q12Const("[Q12].");
        ope.q14Const("[Q14].");
        ope.q15Const("[Q15].");
        ope.q16Const("[Q16].");
        ope.q17Const("[Q17].");
        ope.q19Const("[Q19].");
        ope.q20Const("[Q20].");
        ope.q21Const("[Q21].");
        ope.q22Const("[Q22].");

    }
}