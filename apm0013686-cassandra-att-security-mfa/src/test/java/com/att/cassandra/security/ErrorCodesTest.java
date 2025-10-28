package com.att.cassandra.security;

import org.junit.jupiter.api.Test;
import java.lang.reflect.Modifier;
import static org.junit.jupiter.api.Assertions.*;

class ErrorCodesTest {
    @Test
    void testConstantsPresentAndClassFinal() throws Exception {
        // Check that all expected codes are present and non-null
        assertEquals("E102", ErrorCodes.E102);
        assertEquals("E103", ErrorCodes.E103);
        assertEquals("E104", ErrorCodes.E104);
        assertEquals("E106", ErrorCodes.E106);
        assertEquals("E107", ErrorCodes.E107);
        assertEquals("E108", ErrorCodes.E108);
        assertEquals("E109", ErrorCodes.E109);
        assertEquals("E110", ErrorCodes.E110);
        assertEquals("E111", ErrorCodes.E111);
        assertEquals("W201", ErrorCodes.W201);
        assertEquals("W202", ErrorCodes.W202);
        assertEquals("W203", ErrorCodes.W203);
        assertEquals("W204", ErrorCodes.W204);
        // Class is final and has private constructor
        assertTrue(Modifier.isFinal(ErrorCodes.class.getModifiers()));
        var ctor = ErrorCodes.class.getDeclaredConstructor();
        assertTrue(Modifier.isPrivate(ctor.getModifiers()));
        ctor.setAccessible(true);
        ctor.newInstance(); // Should not throw
    }
}
