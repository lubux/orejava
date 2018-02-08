import ch.ethz.dsg.ore.ORE;
import ch.ethz.dsg.ore.ORE.*;
import org.junit.Test;

import java.security.SecureRandom;
import java.util.Random;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class ORETest {

    SecureRandom rand = new SecureRandom();
    Random basicRand = new Random();

    @Test
    public void testBasic() {
        OREKey key = ORE.generateKey(rand);
        ORE ore = ORE.getDefaultOREInstance(key);
        long val1 = 10, val2 = 20;
        long val1Dec, val2Dec;
        int cmp;
        ORECiphertext ctxt1, ctxt2;
        try {
            ctxt1 = ore.encrypt(val1);
            ctxt2 = ore.encrypt(val2);
            cmp = ctxt1.compareTo(ctxt2);
            assertEquals(cmp, -1);
            cmp = ctxt2.compareTo(ctxt1);
            assertEquals(cmp, 1);
            cmp = ctxt1.compareTo(ctxt1);
            assertEquals(cmp, 0);

            val1Dec = ore.decrypt(ctxt1);
            val2Dec = ore.decrypt(ctxt2);
            assertEquals(val1Dec, val1);
            assertEquals(val2Dec, val2);
        } catch (Exception e) {
           assertTrue(false);
        }

    }


    @Test
    public void testRand() {
        OREKey key = ORE.generateKey(rand);
        ORE ore = ORE.getDefaultOREInstance(key);
        ORECiphertext ctxt1, ctxt2;
        for (int i=0;  i<1000; i++){
            long val1 = basicRand.nextLong(),val2;
            long val1Dec, val2Dec;
            int cmp;
            do {
                val2 = basicRand.nextLong();
            } while (val1 == val2);
            try {
                ctxt1 = ore.encrypt(val1);
                ctxt2 = ore.encrypt(val2);
                cmp = ctxt1.compareTo(ctxt2);
                assertEquals(cmp, (val1 < val2) ? -1 : 1);
                cmp = ctxt2.compareTo(ctxt1);
                assertEquals(cmp, (val1 < val2) ? 1 : -1);
                cmp = ctxt1.compareTo(ctxt1);
                assertEquals(cmp, 0);

                val1Dec = ore.decrypt(ctxt1);
                val2Dec = ore.decrypt(ctxt2);
                assertEquals(val1Dec, val1);
                assertEquals(val2Dec, val2);
            } catch (Exception e) {
                assertTrue(false);
            }
        }

    }

    @Test
    public void testEncode() {
        OREKey key = ORE.generateKey(rand);
        ORE ore = ORE.getDefaultOREInstance(key);
        long val1 = 10, val2 = 20;
        ORECiphertext ctxt1, ctxt2, ctxt1A,  ctxt2A;
        try {
            ctxt1 = ore.encrypt(val1);
            ctxt2 = ore.encrypt(val2);
            byte[] encoded1 = ctxt1.encode();
            byte[] encoded2 = ctxt2.encode();

            ctxt1A = ORECiphertext.decodeDefault(encoded1);
            ctxt2A = ORECiphertext.decodeDefault(encoded2);

            assertArrayEquals(ctxt1.getContent(), ctxt1A.getContent());
            assertArrayEquals(ctxt2.getContent(), ctxt2A.getContent());

        } catch (Exception e) {
            assertTrue(false);
        }

    }
}
